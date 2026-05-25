// backfill-us-ids merges rows that landed under SHA-1 fallback UUIDs for
// "us_<digits>" Xray emails into the real Remnawave UUID resolved via
// remna_users.us_id. One-shot, idempotent: rerunning after success is a
// no-op because the cleanup step removes the email_index join key.
//
// Run once after deploying the forward-fix in
// server/internal/storage/email_resolve.go that routes "us_<digits>" through
// the us_id index. Before the fix, those inputs were silently stored as
// SHA-1 derivatives, producing duplicate user rows in the threat category
// UI alongside the real UUID once the same human was logged as bare digits.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xray-log-analyzer/server/internal/storage"
)

type pair struct {
	sha1 uuid.UUID
	real uuid.UUID
}

func main() {
	dsn := flag.String("postgres", os.Getenv("DATABASE_DSN"), "Postgres DSN (or DATABASE_DSN env)")
	dryRun := flag.Bool("dry-run", false, "list candidate pairs but do not modify any rows")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("-postgres required (or set DATABASE_DSN)")
	}

	ctx := context.Background()
	s, err := storage.New(ctx, *dsn)
	if err != nil {
		log.Fatalf("storage.New: %v", err)
	}
	defer s.Close()

	pairs, err := buildPairs(ctx, s.Pool())
	if err != nil {
		log.Fatalf("buildPairs: %v", err)
	}
	log.Printf("found %d candidate pairs", len(pairs))

	if *dryRun {
		for _, p := range pairs {
			log.Printf("would merge %s -> %s", p.sha1, p.real)
		}
		return
	}

	var moved, skipped int
	start := time.Now()
	for i, p := range pairs {
		if err := mergePair(ctx, s.Pool(), p); err != nil {
			log.Printf("pair %d (%s -> %s) failed: %v", i, p.sha1, p.real, err)
			skipped++
			continue
		}
		moved++
		if (i+1)%500 == 0 {
			log.Printf("progress: %d/%d", i+1, len(pairs))
		}
	}
	log.Printf("done: moved=%d skipped=%d elapsed=%s", moved, skipped, time.Since(start))

	s.ResetUUIDCache()
	s.InvalidateCache("")
}

// buildPairs finds every (sha1, real) mapping where:
//   - email_index has a row with an "us_<digits>" original_email,
//   - and remna_users.us_id matches the digits.
//
// Only such pairs are safe to merge; if us_id is not yet known the SHA-1
// fallback is the only identifier we have and a future WarmCache after the
// next Remnawave sync will pick it up.
func buildPairs(ctx context.Context, pool *pgxpool.Pool) ([]pair, error) {
	rows, err := pool.Query(ctx, `
		SELECT ei.uuid, ru.uuid
		FROM   email_index ei
		JOIN   remna_users ru
		       ON ru.us_id = substring(ei.original_email FROM '(?i)^us_([0-9]+)$')
		WHERE  ei.original_email ~* '^us_[0-9]+$'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.sha1, &p.real); err != nil {
			return nil, err
		}
		if p.sha1 == p.real {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func mergePair(ctx context.Context, pool *pgxpool.Pool, p pair) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// user_threat_stats: PK (user_email, threat_type) — sum counters.
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		SELECT $1, threat_type, match_count, last_match
		FROM   user_threat_stats WHERE user_email = $2
		ON CONFLICT (user_email, threat_type) DO UPDATE SET
		    match_count = user_threat_stats.match_count + EXCLUDED.match_count,
		    last_match  = GREATEST(user_threat_stats.last_match, EXCLUDED.last_match)
	`, p.real, p.sha1); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_threat_stats WHERE user_email = $1`, p.sha1); err != nil {
		return err
	}

	// user_threat_domains: PK (user_email, threat_type, domain) — sum hits.
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_threat_domains (user_email, threat_type, domain, hit_count, last_seen)
		SELECT $1, threat_type, domain, hit_count, last_seen
		FROM   user_threat_domains WHERE user_email = $2
		ON CONFLICT (user_email, threat_type, domain) DO UPDATE SET
		    hit_count = user_threat_domains.hit_count + EXCLUDED.hit_count,
		    last_seen = GREATEST(user_threat_domains.last_seen, EXCLUDED.last_seen)
	`, p.real, p.sha1); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_threat_domains WHERE user_email = $1`, p.sha1); err != nil {
		return err
	}

	// threat_matches: plain rows, no constraint on user_email.
	if _, err := tx.Exec(ctx, `UPDATE threat_matches SET user_email = $1 WHERE user_email = $2`, p.real, p.sha1); err != nil {
		return err
	}

	// Cleanup: drop the email_index row so a re-run finds zero candidates.
	if _, err := tx.Exec(ctx, `DELETE FROM email_index WHERE uuid = $1`, p.sha1); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

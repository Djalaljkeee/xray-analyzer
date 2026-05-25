package storage

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestResolveUserEmailToUUID_USPrefix verifies that "us_<digits>" inputs are
// routed through the us_id index instead of falling into the SHA-1 fallback
// path (which is the bug that caused the same human user to show up under
// two different user_email UUIDs in the threat category UI).
func TestResolveUserEmailToUUID_USPrefix(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	realUUID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status, us_id)
		VALUES ($1, 'alice', 'ACTIVE', '793')
	`, realUUID); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  uuid.UUID
	}{
		{"us_<digits> resolves via us_id", "us_793", realUUID},
		{"case-insensitive prefix", "US_793", realUUID},
		{"bare numeric unchanged", "793", realUUID},
		{"UUID pass-through", realUUID.String(), realUUID},
		{"non-digit suffix falls back to SHA-1", "us_abc", emailToUUID("us_abc")},
		{"unknown us_id still SHA-1 fallback", "us_99999", emailToUUID("us_99999")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s.ResetUUIDCache()
			got, err := s.ResolveUserEmailToUUID(ctx, c.input)
			if err != nil {
				t.Fatalf("ResolveUserEmailToUUID(%q): %v", c.input, err)
			}
			if got != c.want {
				t.Errorf("ResolveUserEmailToUUID(%q) = %s, want %s", c.input, got, c.want)
			}
		})
	}
}

// TestResolveUserEmailToUUID_USPrefix_Cache verifies that the second lookup
// for the same us_<digits> input is served from the in-process cache (i.e.
// the cache key is the original input, not the stripped digits).
func TestResolveUserEmailToUUID_USPrefix_Cache(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	realUUID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status, us_id)
		VALUES ($1, 'bob', 'ACTIVE', '42')
	`, realUUID); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	first, err := s.ResolveUserEmailToUUID(ctx, "us_42")
	if err != nil || first != realUUID {
		t.Fatalf("first lookup: got %s err=%v, want %s", first, err, realUUID)
	}

	// Delete the row so any DB-touching path would fail to resolve.
	if _, err := s.pool.Exec(ctx, `DELETE FROM remna_users WHERE uuid = $1`, realUUID); err != nil {
		t.Fatalf("delete remna_users: %v", err)
	}

	second, err := s.ResolveUserEmailToUUID(ctx, "us_42")
	if err != nil || second != realUUID {
		t.Errorf("second lookup (should hit cache): got %s err=%v, want %s", second, err, realUUID)
	}
}

// TestBackfillUsIds_MergeAggregates verifies the SQL the backfill tool runs
// against user_threat_stats: a row under the SHA-1 fallback UUID and a row
// under the real Remnawave UUID for the same (us_id, threat_type) must
// collapse into a single row with summed counters.
func TestBackfillUsIds_MergeAggregates(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()

	realUUID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO remna_users (uuid, username, status, us_id)
		VALUES ($1, 'carol', 'ACTIVE', '555')
	`, realUUID); err != nil {
		t.Fatalf("seed remna_users: %v", err)
	}

	sha1UUID := emailToUUID("us_555")
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO email_index (uuid, original_email) VALUES ($1, $2)
	`, sha1UUID, "us_555"); err != nil {
		t.Fatalf("seed email_index: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		VALUES ($1, 'gambling', 7, '2024-01-01T00:00:00Z'),
		       ($2, 'gambling', 3, '2024-02-01T00:00:00Z')
	`, sha1UUID, realUUID); err != nil {
		t.Fatalf("seed user_threat_stats: %v", err)
	}

	// Same SQL the backfill tool will run.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO user_threat_stats (user_email, threat_type, match_count, last_match)
		SELECT $1, threat_type, match_count, last_match
		FROM   user_threat_stats WHERE user_email = $2
		ON CONFLICT (user_email, threat_type) DO UPDATE SET
			match_count = user_threat_stats.match_count + EXCLUDED.match_count,
			last_match  = GREATEST(user_threat_stats.last_match, EXCLUDED.last_match)
	`, realUUID, sha1UUID); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_threat_stats WHERE user_email = $1`, sha1UUID); err != nil {
		t.Fatalf("delete sha1 row: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM email_index WHERE uuid = $1`, sha1UUID); err != nil {
		t.Fatalf("delete email_index: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var count int64
	var rows int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(match_count), 0)
		FROM user_threat_stats WHERE threat_type = 'gambling'
	`).Scan(&rows, &count); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rows != 1 {
		t.Errorf("rows after merge = %d, want 1", rows)
	}
	if count != 10 {
		t.Errorf("summed match_count = %d, want 10", count)
	}

	var idxRows int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_index WHERE uuid = $1`, sha1UUID).Scan(&idxRows); err != nil {
		t.Fatalf("email_index check: %v", err)
	}
	if idxRows != 0 {
		t.Errorf("email_index rows for sha1 = %d, want 0", idxRows)
	}
}

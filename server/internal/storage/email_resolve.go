package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// uuidResolveCacheCap bounds the in-memory map of email→uuid resolutions.
// Each entry is ~80 bytes, so 100k entries ≈ 8MB. When the cap is reached
// the cache is fully reset (cheap and avoids per-entry eviction overhead).
const uuidResolveCacheCap = 100000

// resolveUUIDFromCache returns a previously resolved UUID for email, if any.
func (s *Storage) resolveUUIDFromCache(email string) (uuid.UUID, bool) {
	s.uuidCacheMu.RLock()
	id, ok := s.uuidCache[email]
	s.uuidCacheMu.RUnlock()
	return id, ok
}

// cacheResolvedUUID stores a (email, uuid) mapping.
func (s *Storage) cacheResolvedUUID(email string, id uuid.UUID) {
	s.uuidCacheMu.Lock()
	if len(s.uuidCache) >= uuidResolveCacheCap {
		s.uuidCache = make(map[string]uuid.UUID, uuidResolveCacheCap/2)
	}
	s.uuidCache[email] = id
	s.uuidCacheMu.Unlock()
}

// ResolveUserEmailToUUID converts a raw xray user_email identifier into a
// Remnawave user UUID for storage. Resolution order:
//  1. If the input is already a valid UUID, returns it unchanged.
//  2. Single round-trip lookup in remna_users (matches username, email, id,
//     us_id in one query — see resolveUserEmailQuery).
//  3. Numeric-only inputs also try a description LIKE '%US_ID: N%' fallback.
//  4. Falls back to a deterministic SHA-1 derivative of the input,
//     additionally writing (uuid, original_email) into email_index so the UI
//     can resolve the original string later.
//
// Results are memoized in an in-process map (uuidCache) so repeat lookups
// for the same identifier — which dominate ingestion under any batch with
// re-used users — skip the DB entirely.
func (s *Storage) ResolveUserEmailToUUID(ctx context.Context, email string) (uuid.UUID, error) {
	if email == "" {
		return uuid.Nil, fmt.Errorf("empty email")
	}

	// Step 0: in-process cache (hot path).
	if id, ok := s.resolveUUIDFromCache(email); ok {
		return id, nil
	}

	// Step 1: already a valid UUID — pass through and cache.
	if id, err := uuid.Parse(email); err == nil {
		s.cacheResolvedUUID(email, id)
		return id, nil
	}

	// Step 2: single-query lookup in remna_users. UNION ALL with LIMIT 1 lets
	// the planner short-circuit on the first matching branch instead of
	// scanning every alternative. Each branch hits a dedicated index.
	numeric := isNumericString(email)
	var idStr string
	var err error
	if numeric {
		err = s.pool.QueryRow(ctx, resolveUserEmailQueryNumeric, email).Scan(&idStr)
	} else {
		err = s.pool.QueryRow(ctx, resolveUserEmailQueryText, email).Scan(&idStr)
	}
	if err == nil && idStr != "" {
		if id, perr := uuid.Parse(idStr); perr == nil {
			s.cacheResolvedUUID(email, id)
			return id, nil
		}
	}

	// Step 3: legacy description-LIKE fallback for numeric IDs whose us_id
	// column was never parsed out. Only fires when the cheap lookups missed.
	if numeric {
		if err := s.pool.QueryRow(ctx, `
			SELECT uuid::text FROM remna_users WHERE description LIKE $1 LIMIT 1
		`, "%US_ID: "+email+"%").Scan(&idStr); err == nil && idStr != "" {
			if id, perr := uuid.Parse(idStr); perr == nil {
				s.cacheResolvedUUID(email, id)
				return id, nil
			}
		}
	}

	// Step 4: SHA-1 fallback + register in email_index for reverse lookup.
	derived := emailToUUID(email)
	// Register only once per process — email_index registration is purely
	// for the UI's reverse lookup and the SHA-1 derivation is stable, so
	// caching the resolution skips the ExecContext entirely on repeats.
	s.registerEmailIndexOnce(ctx, derived, email)
	s.cacheResolvedUUID(email, derived)
	return derived, nil
}

// resolveUserEmailQueryText matches by username or email columns.
const resolveUserEmailQueryText = `
	SELECT uuid::text FROM remna_users
	WHERE username = $1 OR email = $1
	LIMIT 1
`

// resolveUserEmailQueryNumeric matches numeric-looking inputs against id,
// us_id, username, and email in a single planner-visible query so the
// engine can pick the best index branch instead of forcing 3 round-trips.
const resolveUserEmailQueryNumeric = `
	SELECT uuid::text FROM remna_users WHERE id = $1::bigint LIMIT 1
	UNION ALL
	SELECT uuid::text FROM remna_users WHERE us_id = $1     LIMIT 1
	UNION ALL
	SELECT uuid::text FROM remna_users WHERE username = $1  LIMIT 1
	UNION ALL
	SELECT uuid::text FROM remna_users WHERE email = $1     LIMIT 1
	LIMIT 1
`

// registerEmailIndexOnce upserts a (uuid, original_email) row into
// email_index but only the first time a given uuid is seen in this
// process. Subsequent calls for the same uuid skip the DB.
func (s *Storage) registerEmailIndexOnce(ctx context.Context, id uuid.UUID, email string) {
	if _, seen := s.emailIndexSeen.Load(id); seen {
		return
	}
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO email_index (uuid, original_email) VALUES ($1, $2)
		ON CONFLICT (uuid) DO NOTHING
	`, id, email)
	s.emailIndexSeen.Store(id, struct{}{})
}

// resetUUIDCache clears all memoized resolutions. Called from cache
// invalidation paths so newly-synced Remnawave users are picked up
// immediately instead of being shadowed by stale SHA-1 fallbacks.
func (s *Storage) resetUUIDCache() {
	s.uuidCacheMu.Lock()
	s.uuidCache = make(map[string]uuid.UUID, 1024)
	s.uuidCacheMu.Unlock()
	s.emailIndexSeen = sync.Map{}
}

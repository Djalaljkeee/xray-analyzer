package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xray-log-analyzer/server/internal/models"
)

// RecordBlacklistMatch records a blacklist match.
// match.NodeID is resolved to nodes(id) smallint FK via LookupNodeID.
// match.UserEmail may be any string; non-UUID values are resolved via
// ResolveUserEmailToUUID (remna_users lookup, then SHA-1 fallback).
// match.SourceIP is passed as text; Postgres casts to inet.
func (s *Storage) RecordBlacklistMatch(ctx context.Context, match *models.BlacklistMatch) error {
	nodeID, err := s.LookupNodeID(ctx, match.NodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id: %w", err)
	}

	userUUID, err := s.ResolveUserEmailToUUID(ctx, match.UserEmail)
	if err != nil {
		return fmt.Errorf("resolve user_email: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO blacklist_matches (node_id, user_email, source_ip, destination, matched_rule, timestamp, ts)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7)
	`, int16(nodeID), userUUID, match.SourceIP, match.Destination, match.MatchedRule, match.Timestamp.UTC(), now)
	return err
}

// BulkRecordBlacklistMatches inserts multiple blacklist matches in a single
// round-trip. Used by the analyzer to amortize ingestion: a batch of 100
// log events with 30 blacklist hits drops from 30 INSERTs to 1.
//
// All matches MUST share the same NodeID (the analyzer ingests per-batch
// from one agent). user_email is resolved per row through the in-process
// cache, which is hit-rate-dominant after the first batch.
func (s *Storage) BulkRecordBlacklistMatches(ctx context.Context, matches []*models.BlacklistMatch) error {
	if len(matches) == 0 {
		return nil
	}
	nodeID, err := s.LookupNodeID(ctx, matches[0].NodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve node_id: %w", err)
	}

	now := time.Now().UTC()
	rows := make([][]any, 0, len(matches))
	for _, m := range matches {
		userUUID, err := s.ResolveUserEmailToUUID(ctx, m.UserEmail)
		if err != nil {
			continue
		}
		rows = append(rows, []any{
			int16(nodeID),
			userUUID,
			m.SourceIP,
			m.Destination,
			m.MatchedRule,
			m.Timestamp.UTC(),
			now,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	// COPY FROM is the fastest bulk-insert path in pgx. source_ip is
	// passed as plain text — Postgres casts text→inet at COPY time.
	_, err = s.pool.CopyFrom(ctx,
		pgx.Identifier{"blacklist_matches"},
		[]string{"node_id", "user_email", "source_ip", "destination", "matched_rule", "timestamp", "ts"},
		pgx.CopyFromRows(rows),
	)
	return err
}

// GetBlacklistAnalytics returns detailed blacklist analytics for a time period (cached)
func (s *Storage) GetBlacklistAnalytics(ctx context.Context, since time.Time) (*models.BlacklistAnalytics, error) {
	// Cache key based on hours since epoch (cache per hour window)
	hours := int(time.Since(since).Hours())
	cacheKey := fmt.Sprintf("blacklist_analytics_%d", hours)

	if cached, found := s.cache.Get(cacheKey); found {
		return cached.(*models.BlacklistAnalytics), nil
	}

	analytics := &models.BlacklistAnalytics{
		TopDomains:    []models.DomainStats{},
		TopUsers:      []models.UserBlacklistStats{},
		RecentMatches: []models.BlacklistMatchInfo{},
		HourlyStats:   []models.HourlyBlacklistStats{},
	}

	// All three top-level counters in a single pass over the partition
	// instead of three separate scans. COUNT(DISTINCT ...) still does the
	// hash aggregate work, but it walks the rows once.
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(DISTINCT user_email),
			COUNT(DISTINCT destination)
		FROM blacklist_matches WHERE timestamp > $1
	`, since.UTC()).Scan(&analytics.TotalHits, &analytics.UniqueUsers, &analytics.UniqueDomains); err != nil {
		return nil, fmt.Errorf("count blacklist totals: %w", err)
	}

	// Top domains
	if err := s.loadTopDomains(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Top users
	if err := s.loadTopUsers(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Recent matches
	if err := s.loadRecentMatches(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	// Hourly stats
	if err := s.loadHourlyBlacklistStats(ctx, since.UTC(), analytics); err != nil {
		return nil, err
	}

	s.cache.Set(cacheKey, analytics, CacheTTLMedium)
	return analytics, nil
}

func (s *Storage) loadTopDomains(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT destination, MAX(matched_rule) as matched_rule, COUNT(*) as hits, COUNT(DISTINCT user_email) as users
		FROM blacklist_matches
		WHERE timestamp > $1
		GROUP BY destination
		ORDER BY hits DESC
		LIMIT 50
	`, since)
	if err != nil {
		return fmt.Errorf("query top domains: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var d models.DomainStats
		if err := rows.Scan(&d.Domain, &d.MatchedRule, &d.HitCount, &d.UniqueUsers); err != nil {
			return fmt.Errorf("scan domain: %w", err)
		}
		analytics.TopDomains = append(analytics.TopDomains, d)
	}
	return rows.Err()
}

func (s *Storage) loadTopUsers(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	// Top users + top-5 domains per user in a single query via LATERAL.
	// The prior version's STRING_AGG(DISTINCT destination, ', ') over the
	// full window forced Postgres to materialize and dedupe every domain
	// per user — O(N) per user, dominated dashboard latency. The LATERAL
	// subquery walks the (user_email, destination) hash for the top 5
	// hottest destinations only.
	rows, err := s.pool.Query(ctx, `
		WITH agg AS (
			SELECT
				bm.user_email,
				COUNT(*)                              AS hits,
				COUNT(DISTINCT bm.destination)        AS domains,
				COALESCE(MAX(bm.source_ip::text), '') AS last_ip
			FROM blacklist_matches bm
			WHERE bm.timestamp > $1
			GROUP BY bm.user_email
			ORDER BY hits DESC
			LIMIT 50
		)
		SELECT
			agg.user_email::text,
			COALESCE(r.username, agg.user_email::text) AS display_name,
			agg.hits,
			agg.domains,
			agg.last_ip,
			COALESCE(td.top_domains, '{}'::text[])     AS top_domains
		FROM agg
		LEFT JOIN remna_users r ON r.uuid = agg.user_email
		LEFT JOIN LATERAL (
			SELECT array_agg(destination ORDER BY hits DESC) AS top_domains
			FROM (
				SELECT destination, COUNT(*) AS hits
				FROM blacklist_matches
				WHERE user_email = agg.user_email AND timestamp > $1
				GROUP BY destination
				ORDER BY hits DESC
				LIMIT 5
			) sub
		) td ON true
		ORDER BY agg.hits DESC
	`, since)
	if err != nil {
		return fmt.Errorf("query top users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u models.UserBlacklistStats
		var displayName string
		var topDomains []string
		if err := rows.Scan(&u.UserEmail, &displayName, &u.HitCount, &u.UniqueDomains, &u.LastIP, &topDomains); err != nil {
			return fmt.Errorf("scan user: %w", err)
		}
		u.Username = displayName
		u.TopDomains = topDomains
		analytics.TopUsers = append(analytics.TopUsers, u)
	}
	return rows.Err()
}

func (s *Storage) loadRecentMatches(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.user_email::text, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.timestamp > $1
		ORDER BY bm.timestamp DESC
		LIMIT 100
	`, since)
	if err != nil {
		return fmt.Errorf("query recent matches: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.UserEmail, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return fmt.Errorf("scan match: %w", err)
		}
		if ts != nil {
			m.Timestamp = *ts
		}
		analytics.RecentMatches = append(analytics.RecentMatches, m)
	}
	return rows.Err()
}

func (s *Storage) loadHourlyBlacklistStats(ctx context.Context, since time.Time, analytics *models.BlacklistAnalytics) error {
	rows, err := s.pool.Query(ctx, `
		SELECT date_trunc('hour', timestamp) AS hour, COUNT(*) as hits
		FROM blacklist_matches
		WHERE timestamp > $1 AND timestamp IS NOT NULL
		GROUP BY hour
		ORDER BY hour
	`, since)
	if err != nil {
		return fmt.Errorf("query hourly stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var h models.HourlyBlacklistStats
		if err := rows.Scan(&h.Hour, &h.HitCount); err != nil {
			return fmt.Errorf("scan hourly: %w", err)
		}
		analytics.HourlyStats = append(analytics.HourlyStats, h)
	}
	return rows.Err()
}

// GetUserBlacklistDetails returns detailed blacklist info for a user
func (s *Storage) GetUserBlacklistDetails(ctx context.Context, userEmail string, since time.Time) ([]models.BlacklistMatchInfo, error) {
	searchUUIDs := s.buildBlacklistSearchUUIDs(ctx, userEmail)
	if len(searchUUIDs) == 0 {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.user_email = ANY($1) AND bm.timestamp > $2
		ORDER BY bm.timestamp DESC
		LIMIT 500
	`, searchUUIDs, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return nil, err
		}
		if ts != nil {
			m.Timestamp = *ts
		}
		matches = append(matches, m)
	}
	return matches, rows.Err()
}

// extractNumericPartBl extracts numeric suffix from a string like "prefix_123"
func extractNumericPartBl(s string) string {
	if idx := strings.LastIndex(s, "_"); idx != -1 && idx < len(s)-1 {
		part := s[idx+1:]
		if _, err := strconv.Atoi(part); err == nil {
			return part
		}
	}
	if _, err := strconv.Atoi(s); err == nil {
		return s
	}
	return ""
}

// buildBlacklistSearchUUIDs resolves a user identifier to every plausible
// canonical UUID for blacklist_matches lookups. Goes through the same
// numeric-id / us_id / username / SHA-1 fallback chain as ResolveUserEmailToUUID
// so a URL like /users/us_<id> also matches data keyed by the real user's UUID.
func (s *Storage) buildBlacklistSearchUUIDs(ctx context.Context, userEmail string) []uuid.UUID {
	seen := make(map[uuid.UUID]bool)
	var uuids []uuid.UUID
	for _, id := range buildUserSearchIDs(userEmail) {
		u, err := s.ResolveUserEmailToUUID(ctx, id)
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		uuids = append(uuids, u)
	}
	return uuids
}

// GetUserBlacklistMatches returns paginated blacklist matches for a user
func (s *Storage) GetUserBlacklistMatches(ctx context.Context, userEmail string, since time.Time, page, pageSize int) (*models.PaginatedBlacklistMatchesResponse, error) {
	offset := (page - 1) * pageSize

	searchUUIDs := s.buildBlacklistSearchUUIDs(ctx, userEmail)
	if len(searchUUIDs) == 0 {
		return &models.PaginatedBlacklistMatchesResponse{
			Matches:    []models.BlacklistMatchInfo{},
			Total:      0,
			Page:       page,
			PageSize:   pageSize,
			TotalPages: 1,
		}, nil
	}

	// Get total count
	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM blacklist_matches
		WHERE user_email = ANY($1) AND timestamp > $2
	`, searchUUIDs, since.UTC()).Scan(&total)
	if err != nil {
		return nil, err
	}

	// Get paginated results
	rows, err := s.pool.Query(ctx, `
		SELECT n.node_id, bm.source_ip::text, bm.destination, bm.matched_rule, bm.timestamp
		FROM blacklist_matches bm
		JOIN nodes n ON n.id = bm.node_id
		WHERE bm.user_email = ANY($1) AND bm.timestamp > $2
		ORDER BY bm.timestamp DESC
		LIMIT $3 OFFSET $4
	`, searchUUIDs, since.UTC(), pageSize, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.BlacklistMatchInfo
	for rows.Next() {
		var m models.BlacklistMatchInfo
		var ts *time.Time
		if err := rows.Scan(&m.NodeID, &m.SourceIP, &m.Destination, &m.MatchedRule, &ts); err != nil {
			return nil, err
		}
		if ts != nil {
			m.Timestamp = *ts
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.PaginatedBlacklistMatchesResponse{
		Matches:    matches,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

package threatintel

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/xray-log-analyzer/server/internal/ipinfo"
)

// Service manages threat intelligence operations
type Service struct {
	loader         *FeedLoader
	storage        Storage
	ipInfo         *ipinfo.Service
	mu             sync.RWMutex
	updateInterval time.Duration
	stopChan       chan struct{}
	running        bool

	// geoQueue buffers geo-enrichment jobs from CheckAndRecord. A small
	// worker pool drains it, replacing the previous "goroutine-per-match"
	// pattern that flooded the pgx pool under bursty ingest. Buffer is
	// generous; if full, new jobs are dropped to keep the hot path
	// non-blocking (geo stats are telemetry, not source of truth).
	geoQueue chan geoJob
}

// geoJob is a deferred geo-enrichment request emitted by CheckAndRecord
// and consumed by geoWorker goroutines.
type geoJob struct {
	userEmail  string
	sourceIP   string
	threatType string
	enqueuedAt time.Time
}

// geoQueueCapacity bounds in-flight geo jobs. Sized to absorb short
// bursts without blocking the ingest path; jobs older than the worker
// can drain are dropped at enqueue time.
const geoQueueCapacity = 4096

// geoWorkerCount is the size of the geo flush worker pool. Each worker
// pulls one job, performs the (cached) IP lookup, and issues two short
// pgx writes (SaveGeoStats + SaveUserLocation). Kept small so that
// pool pressure stays bounded regardless of ingest spikes.
const geoWorkerCount = 2

// Storage interface for threat intel persistence
type Storage interface {
	SaveThreatMatch(ctx context.Context, match *ThreatMatch) error
	GetThreatMatches(ctx context.Context, limit int) ([]*ThreatMatch, error)
	GetThreatMatchesByUser(ctx context.Context, userEmail string, limit int) ([]*ThreatMatch, error)
	GetThreatMatchesByType(ctx context.Context, threatType string, limit int) ([]*ThreatMatch, error)
	GetThreatStats(ctx context.Context) (*ThreatStats, error)
	GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error)
	GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error)
	GetRecentUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error)
	GetRecentUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error)
	GetUsersByCategory(ctx context.Context, category string, page, pageSize int) ([]*CategoryUserStats, int, error)
	// Geo stats
	SaveGeoStats(ctx context.Context, countryCode, countryName, threatType, userEmail string) error
	SaveUserLocation(ctx context.Context, userEmail, countryCode, countryName, city string, lat, lon float64) error
	// Geo enrichment
	GetLocationsWithoutCoords(ctx context.Context, limit int) ([]*LocationWithoutCoords, error)
	UpdateLocationCoords(ctx context.Context, userEmail, countryCode, city string, lat, lon float64) error
}

// LocationWithoutCoords represents a user location missing coordinates
type LocationWithoutCoords struct {
	UserEmail   string
	CountryCode string
	City        string
}

// CategoryUserStats represents user stats for a content category
type CategoryUserStats struct {
	UserEmail   string   `json:"user_email"` // raw identifier from Xray logs (numeric id or username)
	DisplayName string   `json:"username"`   // resolved username from Remnawave when available
	Category    string   `json:"category"`
	MatchCount  int64    `json:"match_count"`
	Domains     []string `json:"domains"` // Top visited domains in this category
}

// NewService creates a new threat intelligence service
func NewService(storage Storage, ipInfoSvc *ipinfo.Service) *Service {
	return &Service{
		loader:         NewFeedLoader(),
		storage:        storage,
		ipInfo:         ipInfoSvc,
		updateInterval: 3 * time.Hour,
		stopChan:       make(chan struct{}),
		geoQueue:       make(chan geoJob, geoQueueCapacity),
	}
}

// Start starts the threat intelligence service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	log.Println("threatintel: starting service")

	// Load feeds in background to not block server startup
	go func() {
		if err := s.loader.LoadAllFeeds(ctx); err != nil {
			log.Printf("threatintel: initial load error: %v", err)
		}
		log.Printf("threatintel: loaded %d indicators", s.loader.GetIndicatorCount())
	}()

	// Start background update loop
	go s.updateLoop(ctx)

	// Start geo enrichment loop (backfill coordinates for existing records)
	go s.geoEnrichmentLoop(ctx)

	// Start the geo flush workers. They drain geoQueue serially per
	// goroutine, so concurrent threat matches no longer spawn one DB
	// goroutine each.
	for i := 0; i < geoWorkerCount; i++ {
		go s.geoWorker(ctx)
	}

	return nil
}

// Stop stops the threat intelligence service
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopChan)
	s.running = false
	log.Println("threatintel: stopped service")
}

// updateLoop periodically updates threat feeds
func (s *Service) updateLoop(ctx context.Context) {
	ticker := time.NewTicker(s.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			log.Println("threatintel: updating feeds")
			if err := s.loader.LoadAllFeeds(ctx); err != nil {
				log.Printf("threatintel: update error: %v", err)
			}
			log.Printf("threatintel: updated, now have %d indicators", s.loader.GetIndicatorCount())
		}
	}
}

// geoEnrichmentLoop periodically enriches user locations with coordinates
func (s *Service) geoEnrichmentLoop(ctx context.Context) {
	// Start after a delay to let the system stabilize
	time.Sleep(30 * time.Second)

	// Run every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run immediately on start
	s.enrichGeoCoordinates(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.enrichGeoCoordinates(ctx)
		}
	}
}

// enrichGeoCoordinates enriches user locations without coordinates
func (s *Service) enrichGeoCoordinates(ctx context.Context) {
	if s.storage == nil || s.ipInfo == nil {
		return
	}

	locations, err := s.storage.GetLocationsWithoutCoords(ctx, 50)
	if err != nil {
		log.Printf("threatintel: geo enrichment error: %v", err)
		return
	}

	if len(locations) == 0 {
		return
	}

	log.Printf("threatintel: enriching %d locations without coordinates", len(locations))
	enriched := 0

	for _, loc := range locations {
		// Try to get coordinates from IP lookup cache or by city/country
		// We need an IP to lookup - try to find one from user_ip_history
		ipData := s.ipInfo.GetCachedByLocation(loc.CountryCode, loc.City)
		if ipData != nil && ipData.Lat != 0 && ipData.Lon != 0 {
			if err := s.storage.UpdateLocationCoords(ctx, loc.UserEmail, loc.CountryCode, ipData.City, ipData.Lat, ipData.Lon); err != nil {
				log.Printf("threatintel: failed to update coords for %s/%s: %v", loc.UserEmail, loc.CountryCode, err)
				continue
			}
			enriched++
		}

		// Rate limit to avoid overwhelming IP-API
		time.Sleep(100 * time.Millisecond)
	}

	if enriched > 0 {
		log.Printf("threatintel: enriched %d/%d locations with coordinates", enriched, len(locations))
	}
}

// CheckDestination checks if a destination is a known threat
func (s *Service) CheckDestination(destination string) *ThreatIndicator {
	return s.loader.CheckDestination(destination)
}

// CheckAndRecord checks a destination and records a match if found
func (s *Service) CheckAndRecord(ctx context.Context, userEmail, nodeID, sourceIP, destination string) *ThreatMatch {
	indicator := s.loader.CheckDestination(destination)
	if indicator == nil {
		return nil
	}

	// Don't record low confidence matches (adware/tracking from StevenBlack)
	// unless confidence is >= 70
	if indicator.Confidence < 70 {
		return nil
	}

	match := &ThreatMatch{
		UserEmail:   userEmail,
		NodeID:      nodeID,
		SourceIP:    sourceIP,
		Destination: destination,
		ThreatType:  indicator.ThreatType,
		Source:      indicator.Source,
		Confidence:  indicator.Confidence,
		Description: indicator.Description,
		MatchedAt:   time.Now(),
	}

	// Save to storage if available
	if s.storage != nil {
		if err := s.storage.SaveThreatMatch(ctx, match); err != nil {
			log.Printf("threatintel: failed to save match: %v", err)
		}

		// Defer geo enrichment to the worker pool so a flood of threat
		// matches does not spawn one goroutine each — the previous
		// pattern saturated the pgx pool and caused tuple lock waits on
		// threat_geo_stats.
		if s.ipInfo != nil && sourceIP != "" {
			s.enqueueGeoJob(geoJob{
				userEmail:  userEmail,
				sourceIP:   sourceIP,
				threatType: string(indicator.ThreatType),
				enqueuedAt: time.Now(),
			})
		}
	}

	return match
}

// enqueueGeoJob attempts to push a job onto the geo flush queue.
// Non-blocking: if the queue is full (workers are behind), the job is
// dropped. Geo stats are best-effort telemetry, not the source of truth
// for any blocking flow.
func (s *Service) enqueueGeoJob(job geoJob) {
	if s.geoQueue == nil {
		return
	}
	select {
	case s.geoQueue <- job:
	default:
		// Queue saturated — drop silently. Logging here would be noisier
		// than useful under the bursts this guard is designed to absorb.
	}
}

// geoWorker drains geoQueue. Each iteration performs at most one IP
// lookup and two short pgx writes. ctx is the service's start ctx —
// when it (or stopChan) closes, the worker exits.
func (s *Service) geoWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case job, ok := <-s.geoQueue:
			if !ok {
				return
			}
			s.processGeoJob(ctx, job)
		}
	}
}

// processGeoJob performs a single deferred geo enrichment. Errors are
// swallowed — same semantics as the previous fire-and-forget goroutine.
func (s *Service) processGeoJob(ctx context.Context, job geoJob) {
	if s.ipInfo == nil || s.storage == nil {
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ipData, err := s.ipInfo.Lookup(jobCtx, job.sourceIP)
	if err != nil || ipData == nil {
		return
	}
	s.storage.SaveGeoStats(jobCtx, ipData.CountryCode, ipData.Country, job.threatType, job.userEmail)
	s.storage.SaveUserLocation(jobCtx, job.userEmail, ipData.CountryCode, ipData.Country, ipData.City, ipData.Lat, ipData.Lon)
}

// GetStats returns threat intelligence statistics
func (s *Service) GetStats() *ThreatStats {
	stats := s.loader.GetStats()

	// Add match stats from storage if available
	if s.storage != nil {
		ctx := context.Background()
		if dbStats, err := s.storage.GetThreatStats(ctx); err == nil {
			stats.TotalMatches = dbStats.TotalMatches
			stats.MatchesLast24h = dbStats.MatchesLast24h
		}
	}

	return stats
}

// GetFeedStatus returns the status of all feeds
func (s *Service) GetFeedStatus() []*FeedStatus {
	return s.loader.GetFeedStatus()
}

// GetIndicatorCount returns the total number of loaded indicators
func (s *Service) GetIndicatorCount() int {
	return s.loader.GetIndicatorCount()
}

// GetRecentMatches returns recent threat matches
func (s *Service) GetRecentMatches(ctx context.Context, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatches(ctx, limit)
}

// GetUserMatches returns threat matches for a specific user
func (s *Service) GetUserMatches(ctx context.Context, userEmail string, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatchesByUser(ctx, userEmail, limit)
}

// GetMatchesByType returns threat matches for a specific threat type
func (s *Service) GetMatchesByType(ctx context.Context, threatType string, limit int) ([]*ThreatMatch, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetThreatMatchesByType(ctx, threatType, limit)
}

// ForceUpdate forces an immediate update of all feeds
func (s *Service) ForceUpdate(ctx context.Context) error {
	log.Println("threatintel: forcing feed update")
	return s.loader.LoadAllFeeds(ctx)
}

// GetTopUsersByCategory returns top users for a specific content category
func (s *Service) GetTopUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetTopUsersByCategory(ctx, category, limit)
}

// GetTopUsersByAllCategories returns top users for all content categories
func (s *Service) GetTopUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetTopUsersByAllCategories(ctx, limit)
}

// GetRecentUsersByCategory returns recent users for a specific content category
func (s *Service) GetRecentUsersByCategory(ctx context.Context, category string, limit int) ([]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetRecentUsersByCategory(ctx, category, limit)
}

// GetRecentUsersByAllCategories returns recent users for all content categories
func (s *Service) GetRecentUsersByAllCategories(ctx context.Context, limit int) (map[string][]*CategoryUserStats, error) {
	if s.storage == nil {
		return nil, nil
	}
	return s.storage.GetRecentUsersByAllCategories(ctx, limit)
}

// GetUsersByCategory returns users for a category with pagination
func (s *Service) GetUsersByCategory(ctx context.Context, category string, page, pageSize int) ([]*CategoryUserStats, int, error) {
	if s.storage == nil {
		return nil, 0, nil
	}
	return s.storage.GetUsersByCategory(ctx, category, page, pageSize)
}

package cache

import (
	"sync"
	"time"
)

// Item represents a cached item with expiration
type Item struct {
	Value      interface{}
	Expiration int64
}

// IsExpired returns true if the item has expired
func (item Item) IsExpired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

// flight tracks an in-flight GetOrSet computation for a single key so
// concurrent callers share the same DB round-trip instead of each firing
// their own (singleflight pattern). Without this, every cache miss under
// load triggers a thundering herd against PostgreSQL.
type flight struct {
	done chan struct{}
	val  interface{}
	err  error
}

// Cache is a simple in-memory cache with TTL support
type Cache struct {
	items map[string]Item
	mu    sync.RWMutex

	flightMu sync.Mutex
	flights  map[string]*flight
}

// New creates a new cache instance
func New() *Cache {
	c := &Cache{
		items:   make(map[string]Item),
		flights: make(map[string]*flight),
	}
	// Start cleanup goroutine
	go c.cleanup()
	return c
}

// Set adds an item to the cache with the specified TTL
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	var expiration int64
	if ttl > 0 {
		expiration = time.Now().Add(ttl).UnixNano()
	}

	c.mu.Lock()
	c.items[key] = Item{
		Value:      value,
		Expiration: expiration,
	}
	c.mu.Unlock()
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.items[key]
	c.mu.RUnlock()

	if !found {
		return nil, false
	}

	if item.IsExpired() {
		c.Delete(key)
		return nil, false
	}

	return item.Value, true
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// DeletePrefix removes all items with keys starting with prefix
func (c *Cache) DeletePrefix(prefix string) {
	c.mu.Lock()
	for key := range c.items {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(c.items, key)
		}
	}
	c.mu.Unlock()
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	c.items = make(map[string]Item)
	c.mu.Unlock()
}

// cleanup periodically removes expired items
func (c *Cache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for key, item := range c.items {
			if item.IsExpired() {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// GetOrSet returns cached value or calls fn to get and cache a new value.
// Concurrent callers for the same key share a single fn execution.
func (c *Cache) GetOrSet(key string, ttl time.Duration, fn func() (interface{}, error)) (interface{}, error) {
	if value, found := c.Get(key); found {
		return value, nil
	}

	c.flightMu.Lock()
	if f, ok := c.flights[key]; ok {
		c.flightMu.Unlock()
		<-f.done
		return f.val, f.err
	}
	f := &flight{done: make(chan struct{})}
	c.flights[key] = f
	c.flightMu.Unlock()

	f.val, f.err = fn()
	if f.err == nil {
		c.Set(key, f.val, ttl)
	}

	c.flightMu.Lock()
	delete(c.flights, key)
	c.flightMu.Unlock()
	close(f.done)

	return f.val, f.err
}

// Stats returns cache statistics
func (c *Cache) Stats() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := len(c.items)
	expired := 0
	now := time.Now().UnixNano()

	for _, item := range c.items {
		if item.Expiration > 0 && item.Expiration < now {
			expired++
		}
	}

	return map[string]int{
		"total":  total,
		"active": total - expired,
	}
}

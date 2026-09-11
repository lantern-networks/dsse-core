package main

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Runtime, admin-configurable per-stream retention overrides (in DAYS), persisted so they survive a restart.
// The retention pruner consults this store FIRST (ahead of the -hot-events-retention* startup flags), so an
// operator can tune retention to their compliance regime from the Console without a redeploy. A value of 0 days
// means "keep that stream forever" (never prune). A stream with no override falls back to the flag default.

type retentionOverrideStore struct {
	mu        sync.RWMutex
	days      map[string]int // stream -> retention days (0 = keep forever)
	persister blobstore.Persister
}

func newRetentionOverrideStore(p blobstore.Persister) *retentionOverrideStore {
	s := &retentionOverrideStore{days: map[string]int{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		log.Printf("retention-override store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	if err := json.Unmarshal(data, &s.days); err != nil {
		log.Printf("retention-override store parse: %v", err)
		s.days = map[string]int{}
	}
	return s
}

// Get returns the override retention (days) for a stream and whether one is set.
func (s *retentionOverrideStore) Get(stream string) (int, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.days[stream]
	return d, ok
}

// Set records (or clears, when days < 0) a per-stream retention override and persists it.
func (s *retentionOverrideStore) Set(stream string, days int) {
	if s == nil || stream == "" {
		return
	}
	s.mu.Lock()
	if days < 0 {
		delete(s.days, stream)
	} else {
		s.days[stream] = days
	}
	s.persistLocked()
	s.mu.Unlock()
	log.Printf("retention_override_set stream=%s days=%d", stream, days)
}

// All returns a copy of the current overrides.
func (s *retentionOverrideStore) All() map[string]int {
	out := map[string]int{}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.days {
		out[k] = v
	}
	return out
}

func (s *retentionOverrideStore) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.Marshal(s.days)
	if err != nil {
		return
	}
	_ = s.persister.Save(data)
}

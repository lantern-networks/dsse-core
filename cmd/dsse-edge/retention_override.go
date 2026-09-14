package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Runtime, admin-configurable per-stream retention overrides (in DAYS), persisted so they survive a restart.
// The retention pruner consults this store FIRST (ahead of the -hot-events-retention* startup flags), so an
// operator can tune retention to their compliance regime from the Console without a redeploy. A value of 0 days
// means "keep that stream forever" (never prune). A stream with no override falls back to the flag default.

type retentionOverrideStore struct {
	mu        sync.RWMutex
	days      map[string]int // stream -> retention days (0 = keep forever)
	loadErr   error
	persister blobstore.Persister
}

func newRetentionOverrideStore(p blobstore.Persister) *retentionOverrideStore {
	s := &retentionOverrideStore{days: map[string]int{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		s.loadErr = fmt.Errorf("retention settings could not be loaded")
		log.Printf("retention-override store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	loaded, err := decodeRetentionOverrides(data)
	if err != nil {
		s.loadErr = fmt.Errorf("retention settings could not be loaded")
		log.Printf("retention-override store parse: %v", err)
	} else {
		s.days = loaded
	}

	return s
}

const maxRetentionDays = int((1<<63 - 1) / (24 * time.Hour))

func decodeRetentionOverrides(data []byte) (map[string]int, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected retention object")
	}
	result := map[string]int{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || strings.TrimSpace(key) == "" || key != strings.TrimSpace(key) {
			return nil, fmt.Errorf("invalid stream key")
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("duplicate stream key")
		}
		var value *int
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if value == nil || *value < 0 || *value > maxRetentionDays {
			return nil, fmt.Errorf("invalid retention days")
		}
		result[key] = *value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing retention data")
	}
	return result, nil
}

// Health is nil for an optional, unconfigured store; failed loads require a clean reload.
func (s *retentionOverrideStore) Health() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// Get returns the override retention (days). Unknown configuration preserves every stream.
func (s *retentionOverrideStore) Get(stream string) (int, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return 0, true // Preserve every stream while configuration is unknown.
	}
	d, ok := s.days[stream]
	return d, ok
}

// Set records (or clears, when days < 0) a per-stream retention override and persists it.
func (s *retentionOverrideStore) Set(stream string, days int) error {
	if s == nil || stream == "" {
		return fmt.Errorf("retention store or stream is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return s.loadErr
	}
	if strings.TrimSpace(stream) != stream || days > maxRetentionDays {
		return fmt.Errorf("invalid retention setting")
	}
	previous, existed := s.days[stream]
	if days < 0 {
		delete(s.days, stream)
	} else {
		s.days[stream] = days
	}
	if err := s.persistLocked(); err != nil {
		if existed {
			s.days[stream] = previous
		} else {
			delete(s.days, stream)
		}
		return err
	}
	log.Printf("retention_override_set stream=%s days=%d", stream, days)
	return nil
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

func (s *retentionOverrideStore) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(s.days)
	if err != nil {
		return err
	}
	return s.persister.Save(data)
}

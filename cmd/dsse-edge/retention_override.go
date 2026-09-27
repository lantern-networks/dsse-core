package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"
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
	writeMu            cpWriterMutex
	pendingVersion     map[string]uint64
	nextPendingVersion uint64
	sharedKnown        bool
	mu                 sync.RWMutex
	days               map[string]int  // confirmed stream -> retention days (0 = keep forever)
	pendingForever     map[string]bool // local only; do not include in persistence
	loadErr            error
	persister          blobstore.Persister
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
	s.sharedKnown = true
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
	return s.HealthContext(context.Background())
}

func (s *retentionOverrideStore) HealthContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if err := s.refreshSharedContext(ctx); err != nil {
		return err
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
	if err := s.refreshShared(); err != nil {
		return 0, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil || s.pendingForever[stream] {
		return 0, true // Preserve every stream while configuration is unknown.
	}
	d, ok := s.days[stream]
	return d, ok
}

// Set records (or clears, when days < 0) a per-stream retention override and persists it.
// Caller holds writeMu, which also excludes destructive operations. mu is
// only for brief state snapshots; file I/O must not delay status or pending intent.
func (s *retentionOverrideStore) setLocal(stream string, days int) error {
	s.mu.RLock()
	if s.loadErr != nil {
		err := s.loadErr
		s.mu.RUnlock()
		return err
	}
	candidate := make(map[string]int, len(s.days)+1)
	for k, v := range s.days {
		candidate[k] = v
	}
	version := s.pendingVersion[stream]
	s.mu.RUnlock()
	if days < 0 {
		delete(candidate, stream)
	} else {
		candidate[stream] = days
	}
	raw, err := json.Marshal(candidate)
	if err == nil && s.persister != nil {
		err = s.persister.Save(raw)
	}
	if err != nil {
		if days == 0 {
			s.rememberPendingForever(stream)
		}
		return err
	}
	s.mu.Lock()
	s.days = candidate
	if s.pendingVersion[stream] == version {
		delete(s.pendingForever, stream)
		delete(s.pendingVersion, stream)
	}
	s.mu.Unlock()
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

func (s *retentionOverrideStore) Set(stream string, days int) error {
	return s.SetContext(context.Background(), stream, days)
}

func (s *retentionOverrideStore) PendingForever() []string {
	out := []string{}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for stream := range s.pendingForever {
		out = append(out, stream)
	}
	sort.Strings(out)
	return out
}

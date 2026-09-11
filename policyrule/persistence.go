package policyrule

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// persistedRules is the snapshot of authored rules.
type persistedRules struct {
	Seq   int                        `json:"seq"`
	Rules map[string]map[string]Rule `json:"rules"`
}

// SetStatePath enables durable file persistence (the historical behaviour) at path; empty disables it. A
// back-compat convenience over SetPersister(blobstore.FilePersister{...}).
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or Postgres): the store loads any previously-
// authored rules and persists the whole snapshot after every mutation, so East-West / Egress rules authored in
// the Console survive a restart — and, with a shared Postgres persister, a CP failover.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	if p == nil {
		return nil
	}
	return s.loadLocked()
}

func (s *Store) loadLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := s.persister.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap persistedRules
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Rules != nil {
		s.rules = snap.Rules
	}
	if snap.Seq > s.seq {
		s.seq = snap.Seq
	}
	return nil
}

// persistLocked snapshots the authored rules to the persister. The error MUST reach the mutating caller:
// swallowing it here meant an authored deny rule was acknowledged (200) while nothing hit disk, so the rule
// silently vanished on the next restart — enforcement loss with a green UI. Caller holds s.mu.
func (s *Store) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(persistedRules{Seq: s.seq, Rules: s.rules}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal authored-rules snapshot: %w", err)
	}
	if err := s.persister.Save(data); err != nil {
		return fmt.Errorf("persist authored rules: %w", err)
	}
	return nil
}

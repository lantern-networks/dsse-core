package policyrule

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	if _, shared := p.(contextUpdater); shared {
		raw, err := p.Load()
		if err != nil {
			return ErrPersistence
		}
		n, err := s.sharedCandidateLocked(raw)
		if err != nil {
			return ErrPersistence
		}
		if !reflect.DeepEqual(s.rules, n.rules) {
			s.generation++
		}
		s.rules, s.seq, s.persister = n.rules, n.seq, p
		return nil
	}
	candidate := &Store{rules: cloneRules(s.rules), seq: s.seq, persister: p}
	if err := candidate.loadLocked(); err != nil {
		return err
	}
	s.rules, s.seq, s.persister = candidate.rules, candidate.seq, p
	return nil
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

// ErrPersistence means the candidate was not adopted; the storage result may need reconciliation.
var ErrPersistence = errors.New("authored-rule persistence is unconfirmed")

// Caller holds s.mu. Save before exposing the candidate or moving its generation.
func (s *Store) saveCandidateLocked(next map[string]map[string]Rule, seq int) error {
	if s.persister != nil {
		data, err := json.MarshalIndent(persistedRules{Seq: seq, Rules: next}, "", "  ")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPersistence, err)
		}
		if err := s.persister.Save(data); err != nil {
			return fmt.Errorf("%w: %v", ErrPersistence, err)
		}
	}
	if !reflect.DeepEqual(s.rules, next) {
		s.generation++
	}
	s.rules, s.seq = next, seq
	return nil
}

func cloneRule(r Rule) Rule {
	r.Source = append([]string(nil), r.Source...)
	r.Destination = append([]string(nil), r.Destination...)
	r.AllowedToolIDs = append([]string(nil), r.AllowedToolIDs...)
	r.Action.RequiredAMR = append([]string(nil), r.Action.RequiredAMR...)
	if r.Action.DLP != nil {
		dlp := *r.Action.DLP
		dlp.Identifiers = append([]string(nil), dlp.Identifiers...)
		r.Action.DLP = &dlp
	}
	return r
}
func cloneRules(rules map[string]map[string]Rule) map[string]map[string]Rule {
	out := make(map[string]map[string]Rule, len(rules))
	for tenant, rows := range rules {
		out[tenant] = make(map[string]Rule, len(rows))
		for id, r := range rows {
			out[tenant][id] = cloneRule(r)
		}
	}
	return out
}

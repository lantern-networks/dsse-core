package assetcatalog

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrSharedUpdateUnconfirmed is safe for an admin response; the underlying
// storage error may contain connection details and must not be returned there.
var ErrSharedUpdateUnconfirmed = errors.New("asset catalog shared update was not confirmed")

// The CP's Postgres blob serializes this edit under a row lock. A plain
// Load/Save pair cannot do so across two control-plane processes.
type sharedUpdater interface {
	Update(func([]byte) ([]byte, error)) error
}

func (s *Store) getSharedUpdater() (sharedUpdater, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	update, ok := s.persister.(sharedUpdater)
	return update, ok
}

// Caller holds s.mu. Keep the Edge's enrolled-derived entries while adopting
// the latest CP-authored state; only authored entries are saved to shared storage.
func (s *Store) sharedCandidateLocked(raw []byte) (*Store, error) {
	var snap persistedCatalog
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, fmt.Errorf("invalid shared asset catalog snapshot: %w", err)
		}
	}
	candidate := NewStore()
	candidate.seq, candidate.generation = snap.Seq, snap.Generation
	// Older snapshots have no generation field. During a rolling upgrade, do
	// not move this process's bundle generation backwards on its first shared
	// edit or refresh; later snapshots carry the adopted counter.
	if s.generation > candidate.generation {
		candidate.generation = s.generation
	}
	if s.seq > candidate.seq {
		candidate.seq = s.seq
	}
	candidate.builtInEndpoints, candidate.builtInGroups, candidate.builtInServices = s.builtInEndpoints, s.builtInGroups, s.builtInServices
	if snap.Endpoints != nil {
		candidate.endpoints = snap.Endpoints
	}
	if snap.Groups != nil {
		candidate.groups = snap.Groups
	}
	if snap.Services != nil {
		candidate.services = snap.Services
	}
	if snap.Aliases != nil {
		candidate.aliases = snap.Aliases
	}
	for tenant, entries := range s.endpoints {
		for id, endpoint := range entries {
			if endpoint.Source != SourceEnrolled {
				continue
			}
			if _, exists := candidate.endpoints[tenant][id]; exists {
				return nil, fmt.Errorf("shared asset catalog overlaps an enrolled endpoint")
			}
			if candidate.endpoints[tenant] == nil {
				candidate.endpoints[tenant] = map[string]Endpoint{}
			}
			endpoint.Alias = candidate.claimAliasLocked(tenant, endpoint.Alias, id)
			candidate.endpoints[tenant][id] = endpoint
		}
	}
	return candidate, nil
}

// RefreshShared makes a standby CP's reads and bundle feed reflect a peer's
// confirmed write. File-backed Edge stores already receive authored snapshots
// through the config bundle and do not reload their file on each read.
func (s *Store) RefreshShared() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(sharedUpdater); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return fmt.Errorf("refresh shared asset catalog: %w", err)
	}
	candidate, err := s.sharedCandidateLocked(raw)
	if err != nil {
		return err
	}
	s.seq, s.generation = candidate.seq, candidate.generation
	s.endpoints, s.groups, s.services, s.aliases = candidate.endpoints, candidate.groups, candidate.services, candidate.aliases
	return nil
}

func sharedCatalogMutation[T any](s *Store, update sharedUpdater, apply func(*Store) (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var candidate *Store
	var result T
	var mutationErr error
	err := update.Update(func(raw []byte) ([]byte, error) {
		var err error
		candidate, err = s.sharedCandidateLocked(raw)
		if err != nil {
			return nil, err
		}
		result, err = apply(candidate)
		if err != nil {
			mutationErr = err
			return nil, err
		}
		return candidate.marshalLocked()
	})
	if err != nil {
		var zero T
		if mutationErr != nil {
			return zero, mutationErr
		}
		return zero, ErrSharedUpdateUnconfirmed
	}
	s.seq, s.generation = candidate.seq, candidate.generation
	s.endpoints, s.groups, s.services, s.aliases = candidate.endpoints, candidate.groups, candidate.services, candidate.aliases
	return result, nil
}

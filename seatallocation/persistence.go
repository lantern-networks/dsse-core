package seatallocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

const stateSchemaVersion = "dsse.seat_allocations.v1"

type stateFile struct {
	SchemaVersion string                `json:"schema_version"`
	Allocations   map[string]Allocation `json:"allocations"`
}

// SetPersister makes the store durable and loads what is already there. Call once at boot.
//
// An allocation is operator configuration, and losing it on restart would not degrade gracefully: every tenant
// would read as zero seats and no device anywhere could enrol until an operator re-entered the whole
// distribution. That is why this store belongs with the config stores the durable-by-default guard covers.
func (s *Store) SetPersister(p blobstore.Persister) error {
	if s == nil || p == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := p.Load()
	if err != nil {
		return fmt.Errorf("load seat allocations: %w", err)
	}
	if data != nil {
		allocations, err := decodeAllocations(data)
		if err != nil {
			return err
		}
		s.allocations = allocations
	}
	// A failed load must not replace either live state or its working persistence target.
	s.persister = p
	return nil
}

// SetStateFile is the file-backed convenience used by the reference deployment.
func (s *Store) SetStateFile(path string) error {
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// ErrPersistence means the management change was not confirmed by storage.
var ErrPersistence = errors.New("seat allocation persistence failed")

func (s *Store) saveCandidateLocked(candidate map[string]Allocation) error {
	if s.persister == nil {
		return nil
	}
	raw, err := json.Marshal(stateFile{SchemaVersion: stateSchemaVersion, Allocations: candidate})
	if err == nil {
		err = s.persister.Save(raw)
	}
	if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
		log.Printf("seat_allocations persist: saved without atomic replacement: %v", err)
		return nil
	}
	if err != nil {
		log.Printf("seat_allocations persist: save failed: %v", err)
		return ErrPersistence
	}
	return nil
}

func decodeAllocations(data []byte) (map[string]Allocation, error) {
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode seat allocations: %w", err)
	}
	if state.SchemaVersion != stateSchemaVersion || state.Allocations == nil {
		return nil, errors.New("invalid seat allocation snapshot")
	}
	for key, a := range state.Allocations {
		if key == "" || strings.ToLower(strings.TrimSpace(a.TenantID)) != key || a.Seats < 0 {
			return nil, errors.New("invalid seat allocation entry")
		}
	}
	return state.Allocations, nil
}

// ReloadFromStore is called before publishing leadership. A missing row cannot
// silently erase a previously loaded allocation set.
func (s *Store) ReloadFromStore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persister == nil {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return err
	}
	candidate := map[string]Allocation{}
	if raw == nil {
		if len(s.allocations) > 0 {
			return errors.New("seat allocation snapshot disappeared")
		}
	} else {
		candidate, err = decodeAllocations(raw)
		if err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(s.allocations, candidate) {
		s.allocations = candidate
		s.generation.Add(1)
	}
	return nil
}

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (s *Store) mutateLocked(ctx context.Context, edit func(map[string]Allocation) error) error {
	var candidate map[string]Allocation
	if p, ok := s.persister.(contextUpdater); ok {
		var editErr error
		err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			candidate = map[string]Allocation{}
			if raw != nil {
				var err error
				candidate, err = decodeAllocations(raw)
				if err != nil {
					return nil, err
				}
			} else if len(s.allocations) > 0 {
				return nil, errors.New("seat allocation snapshot disappeared")
			}
			editErr = edit(candidate)
			if editErr != nil {
				return nil, editErr
			}
			return json.Marshal(stateFile{SchemaVersion: stateSchemaVersion, Allocations: candidate})
		})
		if err != nil {
			if editErr != nil {
				return editErr
			}
			log.Printf("seat_allocations persist: update failed: %v", err)
			return ErrPersistence
		}
	} else {
		candidate = make(map[string]Allocation, len(s.allocations))
		for key, a := range s.allocations {
			candidate[key] = a
		}
		if err := edit(candidate); err != nil {
			return err
		}
		if reflect.DeepEqual(s.allocations, candidate) {
			return nil
		}
		if err := s.saveCandidateLocked(candidate); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(s.allocations, candidate) {
		s.allocations = candidate
		s.generation.Add(1)
	}
	return nil
}

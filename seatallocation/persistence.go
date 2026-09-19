package seatallocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
		var state stateFile
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode seat allocations: %w", err)
		}
		if state.SchemaVersion != stateSchemaVersion || state.Allocations == nil {
			return errors.New("invalid seat allocation snapshot")
		}
		for key, allocation := range state.Allocations {
			if key == "" || strings.ToLower(strings.TrimSpace(allocation.TenantID)) != key || allocation.Seats < 0 {
				return errors.New("invalid seat allocation entry")
			}
		}
		s.allocations = state.Allocations
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

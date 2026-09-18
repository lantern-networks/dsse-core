package seatallocation

import (
	"encoding/json"
	"errors"
	"log"

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
func (s *Store) SetPersister(p blobstore.Persister) {
	if s == nil || p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	s.loadLocked()
}

// SetStateFile is the file-backed convenience used by the reference deployment.
func (s *Store) SetStateFile(path string) {
	s.SetPersister(blobstore.FilePersister{Path: path})
}

func (s *Store) loadLocked() {
	data, err := s.persister.Load()
	if err != nil || len(data) == 0 {
		return
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		// Keep whatever is in memory rather than starting from empty: an empty allocation set stops enrolment
		// everywhere, which is a worse answer to a corrupt file than carrying on and saying so loudly.
		log.Printf("seat_allocations persist: load failed, keeping current state: %v", err)
		return
	}
	if state.Allocations != nil {
		s.allocations = state.Allocations
	}
}

func (s *Store) persistLocked() {
	if s == nil || s.persister == nil {
		return
	}
	data, err := json.Marshal(stateFile{SchemaVersion: stateSchemaVersion, Allocations: s.allocations})
	if err != nil {
		log.Printf("seat_allocations persist: marshal failed: %v", err)
		return
	}
	if err := s.persister.Save(data); err != nil {
		// Saved-but-not-atomically is not a failure. Reporting it as one would tell an operator their
		// change was lost when it was written; saying nothing would hide that an interrupted write could
		// truncate it. Both are worth exactly one accurate sentence.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("seat_allocations persist: saved, but NOT atomically — %v", err)
		} else {
			log.Printf("seat_allocations persist: save failed: %v", err)
		}
	}
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
	if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
		log.Printf("seat_allocations persist: saved without atomic replacement: %v", err)
		return nil
	}
	if err != nil {
		log.Printf("seat_allocations persist: save failed: %v", err)
		return ErrPersistence
	}
	return nil
}

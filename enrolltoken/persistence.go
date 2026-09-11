package enrolltoken

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/lantern-networks/dsse-core/blobstore"
)

const stateSchemaVersion = "dsse.enrolment_tokens.v1"

type stateFile struct {
	SchemaVersion string           `json:"schema_version"`
	Tokens        map[string]Token `json:"tokens"`
}

// SetPersister makes the store durable and loads whatever is already there. Call once at boot.
//
// For this store durability is not a convenience: the tokens map is what records that a one-time credential has
// been SPENT. An in-memory-only store would un-spend every used token on restart, so a copied installer config
// would work again after any Edge bounce — which is exactly the property one-time is supposed to remove. The same
// applies to revocations. That is why this follows the enrolled-inventory pattern rather than inventing one.
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
		// Refuse to start from a half-understood state: silently continuing with an EMPTY token set would mark
		// every previously-spent token unspent again.
		log.Printf("enrolment_tokens persist: load failed, keeping current state: %v", err)
		return
	}
	if state.Tokens == nil {
		return
	}
	s.tokens = state.Tokens
	s.byHash = make(map[string]string, len(state.Tokens))
	for id, t := range state.Tokens {
		if t.Hash != "" {
			s.byHash[t.Hash] = id
		}
	}
}

func (s *Store) persistLocked() {
	if s == nil || s.persister == nil {
		return
	}
	data, err := json.Marshal(stateFile{SchemaVersion: stateSchemaVersion, Tokens: s.tokens})
	if err != nil {
		log.Printf("enrolment_tokens persist: marshal failed: %v", err)
		return
	}
	if err := s.persister.Save(data); err != nil {
		// Saved-but-not-atomically is not a failure. Reporting it as one would tell an operator their
		// change was lost when it was written; saying nothing would hide that an interrupted write could
		// truncate it. Both are worth exactly one accurate sentence.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("enrolment_tokens persist: saved, but NOT atomically — %v", err)
		} else {
			log.Printf("enrolment_tokens persist: save failed: %v", err)
		}
	}
}

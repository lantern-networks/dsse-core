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
	if err != nil {
		s.stateErr = ErrStateUnavailable
		return
	}
	if len(data) == 0 {
		return
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		// Refuse to start from a half-understood state: silently continuing with an EMPTY token set would mark
		// every previously-spent token unspent again.
		s.stateErr = ErrStateUnavailable
		log.Printf("enrolment_tokens persist: load failed, keeping current state: %v", err)
		return
	}
	if state.Tokens == nil || state.SchemaVersion != stateSchemaVersion {
		s.stateErr = ErrStateUnavailable
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

// Health reports a latched persistence failure. Recreate and reconcile the store before resuming.
func (s *Store) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateErr
}

func (s *Store) copyTokensLocked() map[string]Token {
	next := make(map[string]Token, len(s.tokens))
	for id, tok := range s.tokens {
		next[id] = tok
	}
	return next
}

// Persist before publishing any issuance, consumption, revocation or removal.
func (s *Store) commitTokensLocked(next map[string]Token) error {
	if s.stateErr != nil {
		return s.stateErr
	}
	if s.persister != nil {
		data, err := json.Marshal(stateFile{SchemaVersion: stateSchemaVersion, Tokens: next})
		if err == nil {
			err = s.persister.Save(data)
		}
		if err != nil && !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			s.stateErr = ErrStateUnavailable
			log.Printf("enrolment_tokens persist: save failed: %v", err)
			return s.stateErr
		}
		if err != nil {
			log.Printf("enrolment_tokens persist: saved, but NOT atomically — %v", err)
		}
	}
	s.tokens = next
	s.byHash = make(map[string]string, len(next))
	for id, tok := range next {
		if tok.Hash != "" {
			s.byHash[tok.Hash] = id
		}
	}
	s.generation.Add(1)
	return nil
}

package policycandidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// ErrPersistence means the requested candidate snapshot could not be confirmed saved.
var ErrPersistence = errors.New("policy candidate persistence failed")

// SetStatePath enables durable file persistence at path (historical behaviour); empty = in-memory only. A
// back-compat convenience over SetPersister(blobstore.FilePersister{...}).
func (store *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return store.SetPersister(nil)
	}
	return store.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): a detected candidate
// survives a restart (an unreviewed candidate cannot silently vanish) — and, on a shared persister, a CP
// failover.
func (store *Store) SetPersister(p blobstore.Persister) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.dirty {
		return fmt.Errorf("%w: retry saving before replacing storage", ErrPersistence)
	}
	if p == nil {
		store.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		store.persister = p
		return nil
	}
	var snapshot map[string]map[string]Candidate
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if snapshot != nil {
		store.candidates = snapshot
	}
	store.persister = p
	return nil
}

func (store *Store) cloneLocked() map[string]map[string]Candidate {
	next := make(map[string]map[string]Candidate, len(store.candidates))
	for tenant, entries := range store.candidates {
		next[tenant] = make(map[string]Candidate, len(entries))
		for id, candidate := range entries {
			next[tenant][id] = copyCandidate(candidate)
		}
	}
	return next
}

// Caller holds mu across save and publication. An uncertain save leaves live state
// unchanged and prevents changing the writer until a subsequent save is confirmed.
func (store *Store) commitLocked(next map[string]map[string]Candidate) error {
	if store.persister != nil {
		data, err := json.MarshalIndent(next, "", "  ")
		if err == nil {
			err = store.persister.Save(data)
		}
		if err != nil {
			store.dirty = true
			return fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	store.candidates = next
	store.dirty = false
	return nil
}

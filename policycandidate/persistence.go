package policycandidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

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
	store.persister = p
	if p == nil {
		return nil
	}
	return store.loadLocked()
}

func (store *Store) loadLocked() error {
	if store.persister == nil {
		return nil
	}
	data, err := store.persister.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snapshot map[string]map[string]Candidate
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if snapshot != nil {
		store.candidates = snapshot
	}
	return nil
}

// persistLocked snapshots the candidates to the persister. The error MUST reach the mutating caller: a
// swallowed Save meant a detected candidate (or an admin review verdict) was acknowledged while nothing hit
// disk, silently vanishing on restart. Caller holds store.mu.
func (store *Store) persistLocked() error {
	if store.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(store.candidates, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy-candidate snapshot: %w", err)
	}
	if err := store.persister.Save(data); err != nil {
		// The public FilePersister uses this sentinel only after writing the new snapshot.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("policy candidate snapshot saved with reduced durability")
			return nil
		}
		return fmt.Errorf("persist policy candidates: %w", err)
	}
	return nil
}

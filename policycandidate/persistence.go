package policycandidate

import (
	"errors"
	"fmt"
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
	if store.dirty || store.sharedUncertain {
		return fmt.Errorf("%w: retry saving before replacing storage", ErrPersistence)
	}
	if p == nil {
		store.persister = nil
		store.sharedKnown = false
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if data == nil {
		store.persister = p
		store.sharedKnown = false
		return nil
	}
	snapshot, receipts, err := decodeCandidateRow(data)
	if err != nil {
		return err
	}
	store.sharedKnown = true
	store.candidates = snapshot
	store.receipts = receipts
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

// Caller holds mu across save and publication. A known file replacement remains
// visible, but an unconfirmed save prevents replacing the writer until confirmed.
func (store *Store) commitLocked(next map[string]map[string]Candidate) error {
	return store.commitWithReceiptsLocked(next, store.receipts)
}

func (store *Store) commitWithReceiptsLocked(next map[string]map[string]Candidate, receipts map[string]ReportReceipt) error {
	if store.persister != nil {
		data, err := encodeCandidateRow(next, receipts)
		if err == nil {
			err = blobstore.UnconfirmedSave(store.persister.Save(data))
		}
		if err != nil {
			if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
				store.candidates, store.receipts = next, receipts
			}
			store.dirty = true
			return fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	store.candidates = next
	store.receipts = receipts
	store.dirty = false
	return nil
}

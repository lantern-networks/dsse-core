package steerexclusion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// File-backed durable persistence for admin-managed steer exclusions.
//
// This is the file shape of the Persistence seam (the Postgres shape lives in cmd/edge). It keeps the WHOLE
// policy set as an in-memory map guarded by a mutex and, on every Upsert/Delete, re-serializes the full set and
// writes it back through a blobstore.Persister. blobstore.FilePersister makes that write atomic (temp file +
// rename), so a crash mid-write never leaves a torn snapshot.
//
// Why a file backend at all: durability-critical stores default to in-memory and are wiped on every Edge
// restart, silently discarding the admin's exclusions. This backend lets a deployment point the store at a file
// path so admin-set exclusions survive a restart, WITHOUT dragging in Postgres — the enforcement Edge is
// deliberately zero-DB and never reads the control plane's database.

// OnPersistError receives save errors and confirmed in-place-write warnings.
// Upsert/Delete also return unconfirmed-save errors; the hook must not panic.
var OnPersistError func(error)

// filePersistSnapshot is the on-disk shape: the full policy set. The store owns its own marshaling; the blob is
// opaque to blobstore.
type filePersistSnapshot struct {
	Policies []*Policy `json:"policies"`
}

// FilePersistence is a file-backed implementation of Persistence.
type FilePersistence struct {
	mu        sync.Mutex
	persister blobstore.Persister
	byID      map[string]*Policy
}

// NewFilePersistence returns a file-backed Persistence writing its snapshot to path via an atomic temp+rename.
func NewFilePersistence(path string) *FilePersistence {
	return &FilePersistence{
		persister: blobstore.FilePersister{Path: path},
		byID:      map[string]*Policy{},
	}
}

// LoadAll reads the snapshot and returns every persisted policy. A missing or empty snapshot (first boot) yields
// an empty slice and no error. A parse failure RETURNS the error so the caller fails closed — refusing to start
// is correct, because starting empty would silently drop every exclusion the admin ever set.
func (f *FilePersistence) LoadAll(ctx context.Context) ([]*Policy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	data, err := f.persister.Load()
	if err != nil {
		return nil, fmt.Errorf("load steer exclusion snapshot: %w", err)
	}
	if len(data) == 0 {
		f.byID = map[string]*Policy{}
		return nil, nil
	}
	var snap filePersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse steer exclusion snapshot: %w", err)
	}
	fresh := map[string]*Policy{}
	out := make([]*Policy, 0, len(snap.Policies))
	for _, p := range snap.Policies {
		if p == nil || p.ID == "" {
			continue
		}
		stored := clonePolicy(*p)
		fresh[p.ID] = &stored
		copy := clonePolicy(stored)
		out = append(out, &copy)
	}
	f.byID = fresh
	return out, nil
}

// Upsert stages a new snapshot and publishes it only after a confirmed save.
func (f *FilePersistence) Upsert(ctx context.Context, p *Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old := f.byID[p.ID]; old != nil && old.TenantID != p.TenantID {
		return ErrTenantConflict
	}
	candidate := f.candidateLocked()
	stored := clonePolicy(*p)
	candidate[p.ID] = &stored
	return f.saveLocked(candidate, "upsert", p.ID)
}

func (f *FilePersistence) Delete(ctx context.Context, id, tenantID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old := f.byID[id]; old == nil || old.TenantID != tenantID {
		return nil
	}
	candidate := f.candidateLocked()
	delete(candidate, id)
	return f.saveLocked(candidate, "delete", id)
}

func (f *FilePersistence) candidateLocked() map[string]*Policy {
	candidate := make(map[string]*Policy, len(f.byID))
	for id, p := range f.byID {
		candidate[id] = p
	}
	return candidate
}

// saveLocked retains the previous cache on error. This does not prove the disk
// is unchanged: a writer can save the bytes and then report uncertain durability.
func (f *FilePersistence) saveLocked(candidate map[string]*Policy, op, id string) error {
	policies := make([]*Policy, 0, len(candidate))
	for _, p := range candidate {
		policies = append(policies, p)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	data, err := json.Marshal(filePersistSnapshot{Policies: policies})
	if err == nil {
		err = f.persister.Save(data)
	}
	if err != nil {
		err = fmt.Errorf("save steer exclusion snapshot (%s %s): %w", op, id, err)
		reportPersistError(err)
		if !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return err
		}
	}
	f.byID = candidate
	return nil
}

func reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

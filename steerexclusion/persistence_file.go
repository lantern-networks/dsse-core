package steerexclusion

import (
	"context"
	"encoding/json"
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

// OnPersistError, when set, is called if a snapshot fails to save. A dropped save is invisible and expensive:
// the Upsert/Delete returns success, the admin sees the change take effect, and the next Edge restart silently
// forgets it. This hook surfaces that so it is not lost. Must not panic.
//
// It does NOT fail the operation: the in-memory set is already updated and serving, and rejecting an admin's
// change because the disk is momentarily unhappy is the worse failure. (A LoadAll parse failure is different —
// that fails closed, because starting empty would silently drop every exclusion the admin ever set.)
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
	f.byID = map[string]*Policy{}
	if len(data) == 0 {
		return nil, nil
	}
	var snap filePersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse steer exclusion snapshot: %w", err)
	}
	out := make([]*Policy, 0, len(snap.Policies))
	for _, p := range snap.Policies {
		if p == nil || p.ID == "" {
			continue
		}
		f.byID[p.ID] = p
		out = append(out, p)
	}
	return out, nil
}

// Upsert stores the policy and rewrites the whole snapshot. A save failure is routed to OnPersistError and does
// NOT fail the operation (the in-memory set is already updated and serving).
func (f *FilePersistence) Upsert(ctx context.Context, p *Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := *p
	f.byID[stored.ID] = &stored
	f.saveLocked("upsert", stored.ID)
	return nil
}

// Delete removes the policy and rewrites the whole snapshot. A save failure is routed to OnPersistError and does
// NOT fail the operation.
func (f *FilePersistence) Delete(ctx context.Context, id, tenantID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.byID[id]; p != nil && p.TenantID == tenantID {
		delete(f.byID, id)
	}
	f.saveLocked("delete", id)
	return nil
}

// saveLocked re-serializes the full policy set and writes it back atomically. The CALLER must hold f.mu. A save
// failure is reported via OnPersistError, never returned. Policies are emitted in a stable (id-sorted) order so
// the snapshot is deterministic.
func (f *FilePersistence) saveLocked(op, id string) {
	policies := make([]*Policy, 0, len(f.byID))
	for _, p := range f.byID {
		policies = append(policies, p)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })

	data, err := json.Marshal(filePersistSnapshot{Policies: policies})
	if err != nil {
		reportPersistError(fmt.Errorf("marshal steer exclusion snapshot (%s %s): %w", op, id, err))
		return
	}
	if err := f.persister.Save(data); err != nil {
		reportPersistError(fmt.Errorf("save steer exclusion snapshot (%s %s): %w", op, id, err))
	}
}

func reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

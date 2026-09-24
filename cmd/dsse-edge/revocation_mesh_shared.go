package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type meshSharedPersister interface {
	blobstore.Persister
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// An unconfirmed enqueue may retry only against the version it tried to replace.
// Otherwise an old process could resurrect a request already consumed by a peer.
type meshPendingIntent struct {
	base, entry revocationMeshOutboxEntry
	authority   context.Context
}

func (o *revocationMeshOutbox) shared() meshSharedPersister {
	p, _ := o.persister.(meshSharedPersister)
	return p
}
func meshSame(a, b revocationMeshOutboxEntry) bool { a.sequence = 0; b.sequence = 0; return a == b }
func (o *revocationMeshOutbox) decodeShared(raw []byte) (map[string]revocationMeshOutboxEntry, error) {
	result := map[string]revocationMeshOutboxEntry{}
	if raw == nil {
		if o.sharedKnown {
			return nil, errMeshOutboxLoad
		}
		return result, nil
	}
	o.sharedKnown = true
	entries, err := decodeMeshOutboxSnapshot(raw)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		result[revocationMeshOutboxKey(e.Region, e.Identity)] = e
	}
	return result, nil
}

// writeMu guards the shared transaction, the uncertainty latch and local intents;
// mu guards only publication, so slow storage does not block snapshot readers.
func (o *revocationMeshOutbox) publishShared(next map[string]revocationMeshOutboxEntry) {
	next = maps.Clone(next)
	for k, intent := range o.unsaved {
		if !meshLeaseCurrent(intent.authority) {
			delete(o.unsaved, k)
			continue
		}
		next[k] = intent.entry
	}
	o.mu.Lock()
	o.pending = next
	o.mu.Unlock()
}
func (o *revocationMeshOutbox) mutateShared(ctx context.Context, edit func(map[string]revocationMeshOutboxEntry) error) (map[string]revocationMeshOutboxEntry, error) {
	if o.sharedUncertain {
		return nil, errMeshOutboxSave
	}
	var next map[string]revocationMeshOutboxEntry
	ready := false
	err := o.shared().UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		var err error
		next, err = o.decodeShared(raw)
		if err != nil {
			return nil, err
		}
		if err = edit(next); err != nil {
			return nil, err
		}
		data, err := json.Marshal(sortedMeshOutbox(next))
		ready = err == nil
		return data, err
	})
	if err != nil {
		if ready && !errors.Is(err, blobstore.ErrWriteNotCommitted) {
			o.sharedUncertain = true
		}
		return nil, errors.Join(errMeshOutboxSave, err)
	}
	o.sharedKnown = true
	return next, nil
}
func (o *revocationMeshOutbox) enqueueShared(ctx context.Context, e revocationMeshOutboxEntry) (revocationMeshOutboxEntry, string, error) {
	if !meshLeaseCurrent(ctx) {
		return e, "unconfirmed", errors.Join(errMeshOutboxSave, blobstore.ErrWriteNotCommitted)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return e, "unconfirmed", errMeshOutboxSave
	}
	e.Revision = hex.EncodeToString(id)
	e.sequence = 0
	// Validate caller-produced entries with the same decoder used at restart.
	raw, _ := json.Marshal([]revocationMeshOutboxEntry{e})
	if _, err := decodeMeshOutboxSnapshot(raw); err != nil {
		return e, "unconfirmed", err
	}
	key := revocationMeshOutboxKey(e.Region, e.Identity)
	base := o.pending[key]
	if prior, ok := o.unsaved[key]; ok {
		base = prior.base
	}
	next, err := o.mutateShared(ctx, func(current map[string]revocationMeshOutboxEntry) error {
		base = current[key]
		current[key] = e
		return nil
	})
	if err != nil {
		if !meshLeaseCurrent(ctx) {
			return e, "unconfirmed", err
		}
		o.unsaved[key] = meshPendingIntent{base: base, entry: e, authority: context.WithoutCancel(ctx)}
		o.mu.Lock()
		o.pending = maps.Clone(o.pending)
		o.pending[key] = e
		o.mu.Unlock()
		return e, "unconfirmed", err
	}
	delete(o.unsaved, key)
	o.publishShared(next)
	return e, "saved", nil
}
func (o *revocationMeshOutbox) ackShared(ctx context.Context, e revocationMeshOutboxEntry) (bool, string, error) {
	key := revocationMeshOutboxKey(e.Region, e.Identity)
	if !meshSame(o.pending[key], e) {
		return false, "not_attempted", nil
	}
	removed := false
	next, err := o.mutateShared(ctx, func(current map[string]revocationMeshOutboxEntry) error {
		target := current[key]
		intent, unsaved := o.unsaved[key]
		if meshSame(target, e) || (unsaved && meshSame(intent.entry, e) && meshSame(target, intent.base)) {
			delete(current, key)
			removed = true
		}
		return nil
	})
	if err != nil {
		return false, "unconfirmed", err
	}
	delete(o.unsaved, key)
	o.publishShared(next)
	return removed, "saved", nil
}
func (o *revocationMeshOutbox) retryShared(ctx context.Context, e revocationMeshOutboxEntry) (bool, string, error) {
	key := revocationMeshOutboxKey(e.Region, e.Identity)
	if !meshSame(o.pending[key], e) {
		return false, "not_attempted", nil
	}
	if o.sharedUncertain {
		return true, "unconfirmed", errMeshOutboxSave
	}
	intent, unsaved := o.unsaved[key]
	if !unsaved {
		if err := o.refreshShared(); err != nil {
			return true, "unconfirmed", err
		}
		return meshSame(o.pending[key], e), "not_attempted", nil
	}
	currentEntry := false
	next, err := o.mutateShared(ctx, func(current map[string]revocationMeshOutboxEntry) error {
		if meshSame(current[key], intent.base) {
			current[key] = e
			currentEntry = true
		}
		return nil
	})
	if err != nil {
		return true, "unconfirmed", err
	}
	delete(o.unsaved, key)
	o.publishShared(next)
	return currentEntry, "saved", nil
}
func (o *revocationMeshOutbox) refreshShared() error {
	if o.sharedUncertain {
		return errMeshOutboxLoad
	}
	raw, err := o.persister.Load()
	if err != nil {
		return errMeshOutboxLoad
	}
	next, err := o.decodeShared(raw)
	if err != nil {
		return err
	}
	if raw != nil {
		o.sharedKnown = true
	}
	o.publishShared(next)
	return nil
}
func (o *revocationMeshOutbox) pendingForResume() ([]revocationMeshOutboxEntry, error) {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.shared() != nil {
		if err := o.refreshShared(); err != nil {
			return nil, err
		}
	}
	return o.snapshot(), nil
}

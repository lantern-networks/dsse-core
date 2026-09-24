package main

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// revocationMeshOutboxEntry is one pending cross-region push, keyed by (Region, Identity).
// A re-revoke replaces the earlier entry. Completion must match this enqueue and
// confirm saving its removal. Only successfully saved state can survive a restart.
// Un-revoke is deliberately not mesh-propagated, so the outbox only holds revokes.
type revocationMeshOutboxEntry struct {
	Region       string `json:"region"`
	URL          string `json:"url"`
	Identity     string `json:"identity"`
	Reason       string `json:"reason"`
	OriginRegion string `json:"origin_region"`
	EnqueuedAt   string `json:"enqueued_at"`
	Revision     string `json:"revision,omitempty"`
	// Process-local revision binds completion to this exact enqueue, even for ABA.
	sequence uint64
}

// revocationMeshOutbox retains pending cross-region deliveries and unconfirmed ACK cleanup.
// It saves the whole pending set on enqueue/ack via a blobstore.Persister. Failed
// saves remain eligible for retry; a nil persister provides memory-only operation.
type revocationMeshOutbox struct {
	writeMu         sync.Mutex   // writers and storage; always before mu
	mu              sync.RWMutex // published maps only, never held across storage
	nextSequence    uint64
	retrySave       bool
	sharedKnown     bool
	sharedUncertain bool
	unsaved         map[string]meshPendingIntent
	persister       blobstore.Persister
	pending         map[string]revocationMeshOutboxEntry
}

func revocationMeshOutboxKey(region, identity string) string { return region + "\x00" + identity }

// newRevocationMeshOutbox loads any persisted pending pushes so a restart resumes them. A nil persister yields an
// empty memory-only outbox.
func newRevocationMeshOutbox(p blobstore.Persister) (*revocationMeshOutbox, error) {
	o := &revocationMeshOutbox{persister: p, unsaved: map[string]meshPendingIntent{}, pending: map[string]revocationMeshOutboxEntry{}}
	if p == nil {
		return o, nil
	}
	data, err := p.Load()
	if err != nil {
		return nil, errMeshOutboxLoad
	}
	if data == nil {
		return o, nil
	}
	o.sharedKnown = true
	entries, err := decodeMeshOutboxSnapshot(data)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		o.nextSequence++
		e.sequence = o.nextSequence
		o.pending[revocationMeshOutboxKey(e.Region, e.Identity)] = e
	}
	return o, nil
}

// enqueue retains the pending delivery in memory if saving fails. Delivery can
// still protect the peer; retries report and retry the unconfirmed snapshot.
func (o *revocationMeshOutbox) enqueue(e revocationMeshOutboxEntry) (revocationMeshOutboxEntry, string, error) {
	return o.enqueueContext(captureCPWriteLease(context.Background()), e)
}
func (o *revocationMeshOutbox) enqueueContext(ctx context.Context, e revocationMeshOutboxEntry) (revocationMeshOutboxEntry, string, error) {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.shared() != nil {
		return o.enqueueShared(ctx, e)
	}
	o.nextSequence++
	e.sequence = o.nextSequence
	candidate := maps.Clone(o.pending)
	candidate[revocationMeshOutboxKey(e.Region, e.Identity)] = e
	o.mu.Lock()
	o.pending = candidate
	o.mu.Unlock()
	persistence, err := o.persistLocked(candidate)
	return e, persistence, err
}

func (o *revocationMeshOutbox) isCurrent(e revocationMeshOutboxEntry) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	current, ok := o.pending[revocationMeshOutboxKey(e.Region, e.Identity)]
	if o.shared() != nil {
		return ok && meshSame(current, e)
	}
	return ok && current == e
}

// ack compares the captured enqueue revision, and publishes removal only after a
// confirmed save. An old completion cannot remove a replacement at the same key.
func (o *revocationMeshOutbox) ack(e revocationMeshOutboxEntry) (bool, string, error) {
	return o.ackContext(captureCPWriteLease(context.Background()), e)
}
func (o *revocationMeshOutbox) ackContext(ctx context.Context, e revocationMeshOutboxEntry) (bool, string, error) {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.shared() != nil {
		return o.ackShared(ctx, e)
	}
	key := revocationMeshOutboxKey(e.Region, e.Identity)
	if current, ok := o.pending[key]; !ok || current != e {
		return false, "not_attempted", nil
	}
	candidate := maps.Clone(o.pending)
	delete(candidate, key)
	persistence, err := o.persistLocked(candidate)
	if err != nil {
		return false, persistence, err
	}
	o.mu.Lock()
	o.pending = candidate
	o.mu.Unlock()
	return true, persistence, nil
}

// Retry persistence without changing the enqueue revision. All pending entries
// share a snapshot, so any confirmed save also resolves earlier enqueue failures.
func (o *revocationMeshOutbox) retryPending(e revocationMeshOutboxEntry) (bool, string, error) {
	return o.retryPendingContext(captureCPWriteLease(context.Background()), e)
}
func (o *revocationMeshOutbox) retryPendingContext(ctx context.Context, e revocationMeshOutboxEntry) (bool, string, error) {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.shared() != nil {
		return o.retryShared(ctx, e)
	}
	if current, ok := o.pending[revocationMeshOutboxKey(e.Region, e.Identity)]; !ok || current != e {
		return false, "not_attempted", nil
	}
	if !o.retrySave {
		return true, "not_attempted", nil
	}
	persistence, err := o.persistLocked(o.pending)
	return true, persistence, err
}

func (o *revocationMeshOutbox) snapshot() []revocationMeshOutboxEntry {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return sortedMeshOutbox(o.pending)
}
func sortedMeshOutbox(pending map[string]revocationMeshOutboxEntry) []revocationMeshOutboxEntry {
	out := make([]revocationMeshOutboxEntry, 0, len(pending))
	for _, e := range pending {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Region != out[j].Region {
			return out[i].Region < out[j].Region
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

var errMeshOutboxSave = errors.New("cannot confirm revocation mesh outbox persistence")

// Requires writeMu, not mu. Published maps are immutable between replacements.
func (o *revocationMeshOutbox) persistLocked(pending map[string]revocationMeshOutboxEntry) (string, error) {
	if o.persister == nil {
		o.retrySave = false
		return "volatile", nil
	}
	o.retrySave = true
	data, err := json.Marshal(sortedMeshOutbox(pending))
	if err != nil {
		return "unconfirmed", errMeshOutboxSave
	}
	if err = o.persister.Save(data); err != nil {
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			o.retrySave = false
			return "saved_non_atomic", nil
		}
		return "unconfirmed", errMeshOutboxSave
	}
	o.retrySave = false
	return "saved", nil
}

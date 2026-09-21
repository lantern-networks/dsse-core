package eastwestobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type sharedPersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func decodeShared(raw []byte, known bool) (map[string]map[string]FlowObservation, error) {
	if raw == nil && !known {
		return map[string]map[string]FlowObservation{}, nil
	}
	var flows map[string]map[string]FlowObservation
	if len(raw) == 0 || json.Unmarshal(raw, &flows) != nil || flows == nil {
		return nil, fmt.Errorf("observation shared inventory unavailable")
	}
	for tenant, rows := range flows {
		if tenant == "" || rows == nil {
			return nil, fmt.Errorf("invalid observation tenant")
		}
		for id, o := range rows {
			first, e1 := time.Parse(time.RFC3339, o.FirstSeen)
			last, e2 := time.Parse(time.RFC3339, o.LastSeen)
			if o.TenantID != tenant || o.ObservationID != id || o.Destination == "" || o.Source == "" || o.Count < 1 || id != ObservationKey(o.Source, o.Destination, o.ServiceFamily, o.Port) || e1 != nil || e2 != nil || first.After(last) {
				return nil, fmt.Errorf("invalid shared observation")
			}
		}
	}
	return flows, nil
}
func cloneFlows(src map[string]map[string]FlowObservation) map[string]map[string]FlowObservation {
	dst := map[string]map[string]FlowObservation{}
	for tenant, rows := range src {
		dst[tenant] = map[string]FlowObservation{}
		for id, o := range rows {
			dst[tenant][id] = o
		}
	}
	return dst
}

// Only newly observed increments are merged, never counts loaded from a peer.
func mergePending(dst, pending map[string]map[string]FlowObservation) error {
	for tenant, rows := range pending {
		if dst[tenant] == nil {
			dst[tenant] = map[string]FlowObservation{}
		}
		for id, delta := range rows {
			old, ok := dst[tenant][id]
			if !ok {
				delta.Covered = false
				dst[tenant][id] = delta
				continue
			}
			if delta.Count > math.MaxInt-old.Count {
				return fmt.Errorf("observation count overflow")
			}
			firstOld, _ := time.Parse(time.RFC3339, old.FirstSeen)
			firstNew, _ := time.Parse(time.RFC3339, delta.FirstSeen)
			lastOld, _ := time.Parse(time.RFC3339, old.LastSeen)
			lastNew, _ := time.Parse(time.RFC3339, delta.LastSeen)
			count := old.Count + delta.Count
			first := old.FirstSeen
			if firstNew.Before(firstOld) {
				first = delta.FirstSeen
			}
			if !lastNew.Before(lastOld) {
				old = delta
			}
			old.Count = count
			old.FirstSeen = first
			old.Covered = false
			dst[tenant][id] = old
		}
	}
	return nil
}
func (s *Store) persistSharedLocked(ctx context.Context, p sharedPersister) error {
	if s.sharedUncertain {
		return fmt.Errorf("observation commit uncertain; reconcile persisted inventory before recreating store")
	}
	var next map[string]map[string]FlowObservation
	prepared := false
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		var e error
		next, e = decodeShared(raw, s.sharedKnown)
		if e != nil {
			return nil, e
		}
		if e = mergePending(next, s.sharedPending); e != nil {
			return nil, e
		}
		view := &Store{flows: next, retention: s.retention}
		view.pruneLocked(time.Now())
		out, e := json.Marshal(next)
		prepared = e == nil
		return out, e
	})
	if err != nil {
		// Snapshot equality cannot prove that OUR increment committed: an independent
		// writer may have produced the same count and timestamp. Never infer a receipt.
		if prepared && !errors.Is(err, blobstore.ErrWriteNotCommitted) {
			s.sharedUncertain = true
		}
		return fmt.Errorf("observation shared flush unconfirmed: %w", err)
	}
	s.flows = next
	s.sharedPending = map[string]map[string]FlowObservation{}
	s.sharedKnown = true
	s.dirty = false
	return nil
}

// RefreshShared returns a checked observation view including unsaved local
// sightings. It does not assert their durability. An uncertain additive commit
// blocks read/adoption until reconciliation, rather than double-counting it.
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(sharedPersister); !ok {
		return nil
	}
	if s.sharedUncertain {
		return fmt.Errorf("observation commit requires reconciliation")
	}
	raw, e := s.persister.Load()
	if e != nil {
		return e
	}
	next, e := decodeShared(raw, s.sharedKnown)
	if e != nil {
		return e
	}
	if e = mergePending(next, s.sharedPending); e != nil {
		return e
	}
	s.flows = next
	s.sharedKnown = s.sharedKnown || raw != nil
	s.pruneLocked(time.Now())
	return nil
}

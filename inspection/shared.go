package inspection

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type sharedPersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func decodeSharedSnapshot(raw []byte, known bool) (storeSnapshot, error) {
	if raw == nil && !known {
		return storeSnapshot{Events: map[string]model.InspectionEvent{}}, nil
	}
	var snap storeSnapshot
	if len(raw) == 0 || json.Unmarshal(raw, &snap) != nil || snap.Events == nil {
		return snap, fmt.Errorf("inspection shared snapshot unavailable")
	}
	seen := map[string]bool{}
	for _, id := range snap.Order {
		ev, ok := snap.Events[id]
		if !ok || id == "" || ev.ID != id || ev.TenantID == "" || seen[id] {
			return snap, fmt.Errorf("invalid inspection shared order")
		}
		seen[id] = true
	}
	if len(seen) != len(snap.Events) {
		return snap, fmt.Errorf("incomplete inspection shared order")
	}
	return snap, nil
}

// Pending IDs, not a stale full snapshot, are merged under the shared row lock.
// The cache is observational: a local event remains visible while its flush is
// pending, but failed writes keep dirty state and cannot erase another CP's data.
// Caller holds mu across this bounded shared transaction.
func (s *Store) persistSharedLocked(ctx context.Context, p sharedPersister) error {
	var next storeSnapshot
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		var err error
		next, err = decodeSharedSnapshot(raw, s.sharedKnown)
		if err != nil {
			return nil, err
		}
		if err = s.mergePendingLocked(&next); err != nil {
			return nil, err
		}
		view := &Store{events: next.Events, order: next.Order, capacity: s.capacity, retention: s.retention}
		view.pruneLocked(time.Now())
		view.order = evictFIFO(view.order, len(view.events), view.capacity, func(k string) { delete(view.events, k) })
		next = storeSnapshot{Events: view.events, Order: view.order}
		return json.Marshal(next)
	})
	if err != nil {
		return fmt.Errorf("inspection shared flush unconfirmed: %w", err)
	}
	s.events, s.order = next.Events, next.Order
	s.sharedPending = map[string]bool{}
	s.sharedKnown = true
	s.dirty = false
	return nil
}
func (s *Store) mergePendingLocked(next *storeSnapshot) error {
	for _, id := range s.order {
		if !s.sharedPending[id] {
			continue
		}
		ev, ok := s.events[id]
		if !ok {
			continue
		}
		if previous, exists := next.Events[id]; exists {
			if previous.TenantID != ev.TenantID {
				return fmt.Errorf("inspection event belongs to another tenant")
			}
		} else {
			next.Order = append(next.Order, id)
		}
		next.Events[id] = ev
	}
	return nil
}

// RefreshShared obtains a checked shared snapshot while preserving local events
// which are waiting for periodic flush. It does not claim that those events have
// been saved. File/WAL stores keep their existing node-local view.
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(sharedPersister); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return fmt.Errorf("inspection shared read unavailable: %w", err)
	}
	next, err := decodeSharedSnapshot(raw, s.sharedKnown)
	if err != nil {
		return err
	}
	if err = s.mergePendingLocked(&next); err != nil {
		return err
	}
	s.events, s.order = next.Events, next.Order
	s.sharedKnown = s.sharedKnown || raw != nil
	s.pruneLocked(time.Now())
	s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k); delete(s.sharedPending, k) })
	return nil
}

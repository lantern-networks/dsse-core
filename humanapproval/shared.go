package humanapproval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"log"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type updater interface {
	Update(func([]byte) ([]byte, error)) error
}

var errNoChange = errors.New("authorization state unchanged")

func decodeSnapshot(data []byte) (map[string]model.HumanApprovalEvent, error) {
	var snap map[string]model.HumanApprovalEvent
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, fmt.Errorf("invalid human approval snapshot")
	}
	fresh := make(map[string]model.HumanApprovalEvent, len(snap))
	for savedKey, event := range snap {
		if err := validKey(event.TenantID, event.ID); err != nil {
			return nil, err
		}
		key := approvalKey(event.TenantID, event.ID)
		if savedKey != event.ID && savedKey != key {
			return nil, fmt.Errorf("invalid saved human approval key")
		}
		if _, found := fresh[key]; found {
			return nil, fmt.Errorf("duplicate saved human approval")
		}
		fresh[key] = event
	}
	return fresh, nil

}
func (s *Store) publishLocked(next map[string]model.HumanApprovalEvent) {

	s.events = next
}

// editLocked edits the latest shared row. File writers keep their existing
// durability contract. Failed candidates are never published as successful writes.
func (s *Store) editLocked(ctx context.Context, edit func(map[string]model.HumanApprovalEvent) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		log.Printf("authorization persistence: %v", err)
		return ErrPersistence
	}
	var next map[string]model.HumanApprovalEvent
	var mutationErr error
	shared := false
	build := func(raw []byte) ([]byte, error) {
		var err error
		if raw == nil {
			if s.authorityKnown {
				return nil, fmt.Errorf("authorization authority disappeared")
			}
			next = cloneEvents(s.events)
		} else {
			next, err = decodeSnapshot(raw)
			if err != nil {
				return nil, err
			}
			if shared {
				s.authorityKnown = true
			}
		}
		s.applyPendingLocked(next)
		if err = edit(next); err != nil {
			mutationErr = err
			return nil, err
		}
		return json.Marshal(next)
	}
	var err error
	switch p := s.persister.(type) {
	case contextUpdater:
		shared = true
		err = p.UpdateContext(ctx, build)
	case updater:
		shared = true
		err = p.Update(build)
	default:
		var raw []byte
		raw, err = json.Marshal(s.events)
		if err == nil {
			raw, err = build(raw)
		}
		if err == nil && p != nil {
			err = p.Save(raw)
		}
	}
	if errors.Is(mutationErr, errNoChange) && errors.Is(err, errNoChange) {
		s.publishLocked(next)
		return nil
	}
	if err != nil {
		if mutationErr != nil {
			return mutationErr
		}
		if shared || !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			log.Printf("authorization persistence: %v", err)
			return ErrPersistence
		}
	}
	s.publishLocked(next)
	if s.persister != nil {
		s.authorityKnown = true
	}
	s.pendingRevocations = nil
	return nil
}

// RefreshShared refuses missing or malformed established authority. It does not
// reload file-backed edge stores, whose state is updated by bundle application.
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.persister.(type) {
	case contextUpdater, updater:
	default:
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		log.Printf("authorization persistence: %v", err)
		return ErrPersistence
	}
	if raw == nil {
		if s.authorityKnown {
			return fmt.Errorf("%w: authority disappeared", ErrPersistence)
		}
		return nil
	}
	next, err := decodeSnapshot(raw)
	if err != nil {
		log.Printf("authorization persistence: %v", err)
		return ErrPersistence
	}
	s.applyPendingLocked(next)
	s.publishLocked(next)
	s.authorityKnown = true
	return nil
}

// An unconfirmed revoke is a local denial latch. Overlay only records still
// present in authority: a refresh must neither revive approval nor undo erasure.
func (s *Store) applyPendingLocked(next map[string]model.HumanApprovalEvent) {
	for key, reason := range s.pendingRevocations {
		if event, ok := next[key]; ok {
			event.ApprovalResult = "revoked"
			event.Reason = reason
			next[key] = event
		}
	}
}

func (s *Store) GetForTenantContext(ctx context.Context, tenant, id string) (model.HumanApprovalEvent, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return model.HumanApprovalEvent{}, false, err
	}
	if err := s.RefreshShared(); err != nil {
		return model.HumanApprovalEvent{}, false, err
	}
	if validKey(tenant, id) != nil {
		return model.HumanApprovalEvent{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.events[approvalKey(tenant, id)]
	return v, ok, nil
}

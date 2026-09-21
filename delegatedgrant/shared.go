package delegatedgrant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"log"
	"reflect"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type updater interface {
	Update(func([]byte) ([]byte, error)) error
}

var errNoChange = errors.New("authorization state unchanged")
var ErrAbsent = errors.New("delegated access grant is absent")

func decodeSnapshot(data []byte) (map[string]model.DelegatedAccessGrant, error) {
	var snap map[string]model.DelegatedAccessGrant
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, fmt.Errorf("invalid delegated grant snapshot")
	}
	fresh := make(map[string]model.DelegatedAccessGrant, len(snap))
	for savedKey, grant := range snap {
		if err := validKey(grant.TenantID, grant.ID); err != nil {
			return nil, err
		}
		key := grantKey(grant.TenantID, grant.ID)
		if savedKey != grant.ID && savedKey != key {
			return nil, fmt.Errorf("invalid saved delegated grant key")
		}
		if _, found := fresh[key]; found {
			return nil, fmt.Errorf("duplicate saved delegated grant")
		}
		fresh[key] = grant
	}
	return fresh, nil

}
func (s *Store) publishLocked(next map[string]model.DelegatedAccessGrant) {
	if !reflect.DeepEqual(s.grants, next) {
		s.generation++
	}
	s.grants = next
}

// editLocked edits the latest shared row. File writers keep their existing
// durability contract. Failed candidates are never published as successful writes.
func (s *Store) editLocked(ctx context.Context, edit func(map[string]model.DelegatedAccessGrant) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		log.Printf("authorization persistence: %v", err)
		return ErrPersistence
	}
	var next map[string]model.DelegatedAccessGrant
	var mutationErr error
	shared := false
	build := func(raw []byte) ([]byte, error) {
		var err error
		if raw == nil {
			if s.authorityKnown {
				return nil, fmt.Errorf("authorization authority disappeared")
			}
			next = cloneGrants(s.grants)
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
		raw, err = json.Marshal(s.grants)
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
	// An unrelated save may confirm present denials, but cannot release an
	// absent latch: a later recreation of the same identity must remain denied.
	for key := range s.pendingRevocations {
		if grant, ok := next[key]; ok && grant.Status == "revoked" {
			delete(s.pendingRevocations, key)
		}
	}
	s.publishLocked(next)
	if s.persister != nil {
		s.authorityKnown = true
	}

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

func (s *Store) GetForTenantContext(ctx context.Context, tenant, id string) (model.DelegatedAccessGrant, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return model.DelegatedAccessGrant{}, false, err
	}
	if err := s.RefreshShared(); err != nil {
		return model.DelegatedAccessGrant{}, false, err
	}
	if validKey(tenant, id) != nil {
		return model.DelegatedAccessGrant{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.grants[grantKey(tenant, id)]
	return v, ok, nil
}

// Overlay only existing records. Peer erasure must not resurrect a grant.
func (s *Store) applyPendingLocked(next map[string]model.DelegatedAccessGrant) {
	for key, pending := range s.pendingRevocations {
		if grant, ok := next[key]; ok {
			at := pending.at
			grant.Status, grant.RevokedAt, grant.RevocationReason = "revoked", &at, stringPtr(pending.reason)
			next[key] = grant
		}
	}
}

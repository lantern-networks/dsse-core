package policy

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"strings"
)

func (s *Store) SetServerInitiatedEnabledConfirmed(tenant string, enabled bool) error {
	return s.SetServerInitiatedEnabledContext(context.Background(), tenant, enabled)
}
func (s *Store) SetServerInitiatedEnabledContext(ctx context.Context, tenant string, enabled bool) error {
	if s == nil {
		return ErrPolicyPersistence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		f.ServerInitiatedEnabled[strings.TrimSpace(tenant)] = enabled
		return nil
	})
}
func (s *Store) UpsertLegacyExceptionConfirmed(tenant string, ex model.LegacyException) error {
	_, err := s.MutateLegacyExceptionContext(context.Background(), tenant, ex.ID, func(model.LegacyException) (model.LegacyException, error) { return ex, nil })
	return err
}
func (s *Store) MutateLegacyExceptionConfirmed(tenant, id string, edit func(model.LegacyException) (model.LegacyException, error)) (model.LegacyException, error) {
	return s.MutateLegacyExceptionContext(context.Background(), tenant, id, edit)
}

// Partial edits merge with the committed row under the same transaction as the save.
func (s *Store) MutateLegacyExceptionContext(ctx context.Context, tenant, id string, edit func(model.LegacyException) (model.LegacyException, error)) (model.LegacyException, error) {
	if s == nil {
		return model.LegacyException{}, ErrPolicyPersistence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant = strings.TrimSpace(tenant)
	var candidate model.LegacyException
	err := s.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		list := f.LegacyExceptions[tenant]
		index := -1
		current := model.LegacyException{ID: id, TenantID: tenant, Status: "active"}
		for i, item := range list {
			if item.ID == id {
				index = i
				current = item
				break
			}
		}
		var err error
		candidate, err = edit(current)
		if err != nil {
			return err
		}
		if candidate.ID != id {
			return fmt.Errorf("exception identity cannot change during update")
		}
		candidate.TenantID = tenant
		if index < 0 {
			list = append(list, candidate)
		} else {
			list[index] = candidate
		}
		f.LegacyExceptions[tenant] = list
		return nil
	})
	if err != nil {
		return model.LegacyException{}, err
	}
	return candidate, nil
}
func (s *Store) RemoveLegacyExceptionConfirmed(tenant, id string) (bool, error) {
	return s.RemoveLegacyExceptionContext(context.Background(), tenant, id)
}
func (s *Store) RemoveLegacyExceptionContext(ctx context.Context, tenant, id string) (bool, error) {
	if s == nil {
		return false, ErrPolicyPersistence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	removed := false
	err := s.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		list := f.LegacyExceptions[tenant]
		for i, item := range list {
			if item.ID == id {
				f.LegacyExceptions[tenant] = append(list[:i], list[i+1:]...)
				removed = true
				break
			}
		}
		return nil
	})
	return removed && err == nil, err
}

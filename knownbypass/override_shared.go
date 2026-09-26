package knownbypass

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
)

type sharedOverridePersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (s *OverrideStore) authoritativeLocked(raw []byte) (map[string]map[string]Override, error) {
	if raw == nil {
		if len(s.overrides) != 0 {
			return nil, fmt.Errorf("%w: shared override authority is missing", ErrPersistence)
		}
		return map[string]map[string]Override{}, nil
	}
	return decodeOverrideSnapshot(raw)
}

func (s *OverrideStore) mutateLocked(ctx context.Context, edit func(map[string]map[string]Override)) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	if shared, ok := s.persister.(sharedOverridePersister); ok {
		var next map[string]map[string]Override
		err := shared.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var err error
			next, err = s.authoritativeLocked(raw)
			if err != nil {
				return nil, err
			}
			edit(next)
			return json.Marshal(next)
		})
		if err != nil {
			s.dirty = true
			return fmt.Errorf("%w: %w", ErrPersistence, err)
		}
		s.overrides = next
		s.dirty = false
		return nil
	}
	next := s.cloneLocked()
	edit(next)
	if !s.dirty && reflect.DeepEqual(next, s.overrides) {
		return nil
	}
	return s.commitLocked(next)
}

// RefreshShared refuses unreadable authority while retaining the last live
// snapshot. Its changed result allows the caller to reapply engine selections.
func (s *OverrideStore) RefreshShared() (bool, error) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(sharedOverridePersister); !ok {
		return false, nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	next, err := s.authoritativeLocked(raw)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	changed := !reflect.DeepEqual(next, s.overrides)
	s.overrides = next
	s.dirty = false
	return changed, nil
}

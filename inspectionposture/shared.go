package inspectionposture

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
)

type sharedPersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// UpdateContext applies a partial edit to the authoritative posture. Returned
// snapshots describe the attempted edit; live state changes only after saving.
func (s *Store) UpdateContext(ctx context.Context, edit func(Posture) (Posture, error)) (Posture, Posture, error) {
	return s.updateContext(ctx, edit, false)
}

// InitializeContext preserves a posture created by another process during boot.
func (s *Store) InitializeContext(ctx context.Context, seed Posture) (Posture, error) {
	_, next, err := s.updateContext(ctx, func(Posture) (Posture, error) { return seed, nil }, true)
	return next, err
}

func (s *Store) SetContext(ctx context.Context, p Posture) (Posture, error) {
	_, next, err := s.UpdateContext(ctx, func(Posture) (Posture, error) { return p, nil })
	return next, err
}

func (s *Store) updateContext(ctx context.Context, edit func(Posture) (Posture, error), initialize bool) (before, next Posture, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err = ctx.Err(); err != nil {
		return before, next, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	var editErr error
	prepare := func(p Posture) error {
		before = clonePosture(p)
		next, editErr = edit(clonePosture(p))
		if editErr == nil {
			next, editErr = Validate(next)
		}
		return editErr
	}
	if shared, ok := s.persister.(sharedPersister); ok {
		err = shared.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var p Posture
			if raw == nil {
				if s.initialized {
					return nil, fmt.Errorf("shared inspection posture is missing")
				}
				p = s.Get()
			} else {
				_, decoded, e := decodeSnapshot(raw, true)
				if e != nil {
					return nil, e
				}
				p = decoded
				if initialize {
					before = clonePosture(p)
					next = clonePosture(p)
					return json.Marshal(next)
				}
			}
			if e := prepare(p); e != nil {
				return nil, e
			}
			return json.Marshal(next)
		})
	} else {
		if err = prepare(s.Get()); err == nil {
			err = s.persist(next)
		}
	}
	if editErr != nil {
		return before, next, editErr
	}
	if err != nil {
		return before, next, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	s.initialized = true
	s.adopt(next)
	return clonePosture(before), clonePosture(next), nil
}

func (s *Store) adopt(next Posture) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !reflect.DeepEqual(s.posture, next)
	if changed {
		s.posture = clonePosture(next)
		s.generation++
	}
	return changed
}

// RefreshShared refuses an absent or unreadable authority without changing the
// last confirmed live state or generation.
func (s *Store) RefreshShared() (bool, error) {
	if s == nil {
		return false, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, ok := s.persister.(sharedPersister); !ok {
		return false, nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	if raw == nil {
		return false, fmt.Errorf("%w: shared inspection posture is missing", ErrPersistence)
	}
	_, next, err := decodeSnapshot(raw, true)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrPersistence, err)
	}
	s.initialized = true
	return s.adopt(next), nil
}

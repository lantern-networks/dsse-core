package vlan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

type sharedPersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// ErrNotFound deliberately does not disclose whether another tenant owns the ID.
var ErrNotFound = errors.New("network definition is absent")

func decodeSnapshot(data []byte) (vlanPersistSnapshot, error) {
	var snap vlanPersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return snap, err
	}
	if snap.Objects == nil || snap.Policies == nil {
		return snap, errors.New("network snapshot is incomplete")
	}
	for id, o := range snap.Objects {
		if strings.TrimSpace(id) == "" || id != o.ID {
			return snap, errors.New("network object identity differs from its key")
		}
	}
	for id, p := range snap.Policies {
		if strings.TrimSpace(id) == "" || id != p.ID {
			return snap, errors.New("network policy identity differs from its key")
		}
	}
	return snap, nil
}

func (s *Store) adoptLocked(snap vlanPersistSnapshot) {
	if !reflect.DeepEqual(s.objects, snap.Objects) || !reflect.DeepEqual(s.policies, snap.Policies) {
		s.objects, s.policies = snap.Objects, snap.Policies
		s.generation.Add(1)
	}
}

// Shared absence can initialize a genuinely empty store, but must never resurrect
// a populated process cache after the authoritative row has disappeared.
func (s *Store) sharedSnapshotLocked(data []byte) (vlanPersistSnapshot, error) {
	if len(data) == 0 {
		if len(s.objects)+len(s.policies) != 0 {
			return vlanPersistSnapshot{}, errors.New("network authority is missing")
		}
		return vlanPersistSnapshot{Objects: map[string]model.VLANObject{}, Policies: map[string]model.VLANBoundaryPolicy{}}, nil
	}
	return decodeSnapshot(data)
}

func (s *Store) mutateLocked(ctx context.Context, edit func(*vlanPersistSnapshot) error) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	next := vlanPersistSnapshot{Objects: maps.Clone(s.objects), Policies: maps.Clone(s.policies)}
	var err error
	if shared, ok := s.persister.(sharedPersister); ok {
		err = shared.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var err error
			next, err = s.sharedSnapshotLocked(raw)
			if err != nil {
				return nil, err
			}
			if err = edit(&next); err != nil {
				return nil, err
			}
			return json.Marshal(next)
		})
	} else {
		if err = edit(&next); err != nil {
			return err
		}
		// No-op file deletion need not create a new file or fail on a read-only volume.
		if reflect.DeepEqual(next.Objects, s.objects) && reflect.DeepEqual(next.Policies, s.policies) {
			return nil
		}
		err = s.saveCandidateLocked(next.Objects, next.Policies)
	}
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		s.reportPersistError(err)
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.adoptLocked(next)
	return nil
}

// RefreshShared checks authority before a management read or signed distribution.
// File-backed Edge consumers keep their independently applied snapshot.
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
	if err == nil {
		var snap vlanPersistSnapshot
		snap, err = s.sharedSnapshotLocked(raw)
		if err == nil {
			s.adoptLocked(snap)
			return nil
		}
	}
	return fmt.Errorf("%w: %v", ErrPersistence, err)
}

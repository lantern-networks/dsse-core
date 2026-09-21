package grantstore

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type updater interface {
	Update(func([]byte) ([]byte, error)) error
}

func (s *Store) sharedLocked() bool {
	switch s.persister.(type) {
	case contextUpdater, updater:
		return true
	}
	return false
}
func decodeShared(raw []byte) (map[string]Grant, error) {
	var out map[string]Grant
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, ErrInvalidGrant
	}
	for id, g := range out {
		if id != g.GrantID {
			return nil, ErrInvalidGrant
		}
		if err := validateGrant(g); err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Store) publishLocked(next map[string]Grant) {
	if !reflect.DeepEqual(s.grants, next) {
		s.generation++
	}
	s.grants = cloneGrants(next)
}
func (s *Store) overlayPending(next map[string]Grant) error {
	for id, g := range s.pending {
		if old, ok := next[id]; ok {
			if old.TenantID != g.TenantID {
				return ErrConflict
			}
			old.Revoked = true
			next[id] = old
		} else {
			next[id] = cloneGrant(g)
		}
	}
	return nil
}

// mutateShared holds the latest authority row throughout the edit. New allows
// become visible only after commit. Failed denials remain local and retryable.
func (s *Store) mutateShared(ctx context.Context, edit func(*Store) error) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sharedLocked() {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var next *Store
	var denials map[string]Grant
	var editErr error
	build := func(raw []byte) ([]byte, error) {
		var rows map[string]Grant
		var err error
		if raw == nil {
			if s.authorityKnown {
				return nil, ErrPersistence
			}
			rows = cloneGrants(s.grants)
		} else {
			rows, err = decodeShared(raw)
			if err != nil {
				return nil, err
			}
			s.authorityKnown = true
		}
		if err = s.overlayPending(rows); err != nil {
			return nil, err
		}
		before := cloneGrants(rows)
		next = NewStore()
		next.grants = rows
		if editErr = edit(next); editErr != nil {
			return nil, editErr
		}
		denials = make(map[string]Grant)
		for id, g := range next.grants {
			if prev, ok := before[id]; g.Revoked && (!ok || !prev.Revoked) {
				denials[id] = cloneGrant(g)
			}
		}
		return json.Marshal(next.grants)
	}
	var err error
	switch p := s.persister.(type) {
	case contextUpdater:
		err = p.UpdateContext(ctx, build)
	case updater:
		if ctx.Err() != nil {
			err = ctx.Err()
		} else {
			err = p.Update(build)
		}
	}
	if err != nil {
		if editErr != nil {
			return true, editErr
		}
		if len(denials) > 0 {
			if s.pending == nil {
				s.pending = make(map[string]Grant)
			}
			for id, g := range denials {
				s.pending[id] = g
				s.grants[id] = g
			}
			s.dirty = true
			s.generation++
		}
		return true, ErrPersistence
	}
	s.publishLocked(next.grants)
	s.pending = nil
	s.dirty = false
	s.authorityKnown = true
	return true, nil
}
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sharedLocked() {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return ErrPersistence
	}
	if raw == nil {
		if s.authorityKnown {
			return ErrPersistence
		}
		return nil
	}
	rows, err := decodeShared(raw)
	if err != nil {
		return ErrPersistence
	}
	if err = s.overlayPending(rows); err != nil {
		return ErrPersistence
	}
	s.publishLocked(rows)
	s.authorityKnown = true
	return nil
}
func (s *Store) MintContext(ctx context.Context, g Grant, ttl time.Duration, now time.Time) (Grant, error) {
	var out Grant
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; out, e = c.Mint(g, ttl, now); return e })
	if !handled {
		return s.mintLocal(g, ttl, now)
	}
	if err != nil {
		return Grant{}, err
	}
	return out, nil
}
func (s *Store) RevokeForTenantContext(ctx context.Context, tenant, id string) (Grant, bool, error) {
	tenant = strings.TrimSpace(tenant)
	id = strings.TrimSpace(id)
	var out Grant
	var found bool
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; out, found, e = c.RevokeForTenant(tenant, id); return e })
	if !handled {
		return s.revokeForTenantLocal(tenant, id)
	}
	if err != nil {
		// A nonzero result is an applied local denial, never merely a candidate.
		s.mu.RLock()
		g, applied := s.pending[id]
		s.mu.RUnlock()
		if applied && g.TenantID == tenant {
			return cloneGrant(g), true, err
		}
		return Grant{}, false, err
	}
	return out, found, nil
}
func (s *Store) MergeCheckedContext(ctx context.Context, incoming []Grant, now time.Time) (int, int, error) {
	var added, updated, denialAdded, denialUpdated int
	handled, err := s.mutateShared(ctx, func(c *Store) error {
		before := cloneGrants(c.grants)
		var e error
		added, updated, e = c.MergeChecked(incoming, now)
		if e == nil {
			for id, g := range c.grants {
				prev, exists := before[id]
				if g.Revoked && (!exists || !prev.Revoked) {
					if exists {
						denialUpdated++
					} else {
						denialAdded++
					}
				}
			}
		}
		return e
	})
	if !handled {
		return s.mergeLocal(incoming, now)
	}
	if err != nil {
		return denialAdded, denialUpdated, err
	}
	return added, updated, nil
}
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	var n int
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; n, e = c.RemoveTenantChecked(tenant); return e })
	if !handled {
		return s.removeTenantLocal(tenant)
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ListChecked distinguishes authority failure from an empty tenant.
func (s *Store) ListChecked(tenant string) ([]Grant, error) {
	if err := s.RefreshShared(); err != nil {
		return nil, err
	}
	return s.listLocal(tenant), nil
}
func (s *Store) ListAllChecked() ([]Grant, error) {
	if err := s.RefreshShared(); err != nil {
		return nil, err
	}
	return s.listAllLocal(), nil
}

package grantstore

import (
	"context"
	"encoding/json"
	"errors"
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
func pendingGrantKey(tenant, id string) string { return tenant + "\x00" + id }

func (s *Store) overlayPending(next map[string]Grant) {
	for _, g := range s.pending {
		if old, ok := next[g.GrantID]; ok && old.TenantID == g.TenantID {
			old.Revoked = true
			next[g.GrantID] = old
		}
	}
}

type sharedGrantMutation struct {
	revokeTenant, revokeID string
	eraseTenant            string
}

// mutateShared holds the latest authority row throughout the edit. New allows
// become visible only after commit. Failed denials remain local and retryable.
func (s *Store) mutateShared(ctx context.Context, edit func(*Store) error, options ...sharedGrantMutation) (bool, error) {
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
	callbackStarted := false
	var option sharedGrantMutation
	if len(options) > 0 {
		option = options[0]
	}
	build := func(raw []byte) ([]byte, error) {
		callbackStarted = true
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
		s.overlayPending(rows)
		before := cloneGrants(rows)
		next = NewStore()
		next.grants = rows
		if editErr = edit(next); editErr != nil {
			return nil, editErr
		}
		// An absent latch must also guard admission after the edit callback.
		for _, pending := range s.pending {
			if g, ok := next.grants[pending.GrantID]; ok && g.TenantID == pending.TenantID && !g.Revoked {
				editErr = ErrConflict
				return nil, editErr
			}
		}
		denials = make(map[string]Grant)
		for id, g := range next.grants {
			if prev, ok := before[id]; g.Revoked && (!ok || !prev.Revoked) {
				denials[pendingGrantKey(g.TenantID, id)] = cloneGrant(g)
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
		// A transaction/lease refusal can precede the callback. Deny only the
		// known target in this tenant; never turn an unknown ID into a record.
		if !callbackStarted && option.revokeTenant != "" {
			if g, ok := s.grants[option.revokeID]; ok && g.TenantID == option.revokeTenant {
				g.Revoked = true
				denials = map[string]Grant{pendingGrantKey(g.TenantID, g.GrantID): g}
			}
		}
		if len(denials) > 0 {
			if s.pending == nil {
				s.pending = make(map[string]Grant)
			}
			nextLocal := cloneGrants(s.grants)
			for key, g := range denials {
				s.pending[key] = g
				if old, ok := nextLocal[g.GrantID]; !ok || old.TenantID == g.TenantID {
					nextLocal[g.GrantID] = g
				}
			}
			s.publishLocked(nextLocal)
			s.dirty = true
		}
		return true, ErrPersistence
	}
	s.publishLocked(next.grants)
	for key, g := range s.pending {
		committed, present := next.grants[g.GrantID]
		if (present && committed.TenantID == g.TenantID && committed.Revoked) || (option.eraseTenant != "" && g.TenantID == option.eraseTenant) {
			delete(s.pending, key)
		}
	}
	s.dirty = len(s.pending) > 0
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
	s.overlayPending(rows)
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
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; out, found, e = c.RevokeForTenant(tenant, id); return e }, sharedGrantMutation{revokeTenant: tenant, revokeID: id})
	if !handled {
		return s.revokeForTenantLocal(tenant, id)
	}
	if err != nil {
		// A nonzero result is an applied local denial, never merely a candidate.
		s.mu.RLock()
		g, applied := s.pending[pendingGrantKey(tenant, id)]
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
		added, updated, e = c.MergeChecked(s.withoutLatchedGrants(incoming, before), now)
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
		if !errors.Is(err, ErrPersistence) {
			return 0, 0, err
		}
		return denialAdded, denialUpdated, err
	}
	return added, updated, nil
}
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	var n int
	handled, err := s.mutateShared(ctx, func(c *Store) error { var e error; n, e = c.RemoveTenantChecked(tenant); return e }, sharedGrantMutation{eraseTenant: strings.TrimSpace(tenant)})
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

// withoutLatchedGrants drops reported grants this process holds an unconfirmed
// denial for, when the latest row no longer has them (a peer erased them). An
// Edge keeps reporting such a grant until it expires; admitting it would revive
// an erased record, and refusing it refused the whole batch, so no other grant
// that Edge reported was ever admitted. Caller holds s.mu (mutateShared).
func (s *Store) withoutLatchedGrants(incoming []Grant, current map[string]Grant) []Grant {
	if len(s.pending) == 0 {
		return incoming
	}
	out := make([]Grant, 0, len(incoming))
	for _, g := range incoming {
		if _, latched := s.pending[pendingGrantKey(g.TenantID, g.GrantID)]; latched && !g.Revoked {
			if _, present := current[g.GrantID]; !present {
				continue
			}
		}
		out = append(out, g)
	}
	return out
}

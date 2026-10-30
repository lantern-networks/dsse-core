package grantstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"sort"
	"strings"
	"time"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type updater interface {
	Update(func([]byte) ([]byte, error)) error
}
type conditionalLoader interface {
	LoadIfUnchanged([32]byte) ([]byte, bool, error)
}

func (s *Store) sharedLocked() bool {
	switch s.persister.(type) {
	case contextUpdater, updater:
		return true
	}
	return false
}
func decodeShared(raw []byte) (map[string]Grant, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrInvalidGrant
	}
	var out map[string]Grant
	var version int
	if value, exists := fields["schema_version"]; exists && json.Unmarshal(value, &version) == nil {
		if (version != 2 && version != 3) || json.Unmarshal(fields["grants"], &out) != nil || out == nil {
			return nil, ErrInvalidGrant
		}
	} else if json.Unmarshal(raw, &out) != nil || out == nil {
		return nil, ErrInvalidGrant
	}
	for id, g := range out {
		if id != g.GrantID {
			return nil, ErrInvalidGrant
		}
		if err := validateGrant(g); err != nil {
			if g.ReauthenticateAfter != "" {
				return nil, err
			}
			log.Printf("access_grant_restore invalid_legacy_row_skipped=true")
			delete(out, id)
			continue
		}
	}
	return out, nil
}

// A scalar version makes a legacy map[string]Grant reader reject the document
// instead of dropping new authorization fields and writing a weakened snapshot.
// Shared atomic writers re-read this format inside their mutation transaction.
func encodeGrantSnapshot(rows map[string]Grant) ([]byte, error) {
	return json.Marshal(struct {
		Version int              `json:"schema_version"`
		Grants  map[string]Grant `json:"grants"`
	}{3, rows})
}

func (s *Store) publishLocked(next map[string]Grant) {
	var changed bool
	var rows map[string]Grant
	var index reauthenticationReadIndex
	_ = s.withAuthorizationReaders(func() error {
		changed = !reflect.DeepEqual(s.grants, next)
		rows = cloneGrants(next)
		if changed {
			index = newReauthenticationReadIndex(next)
		}
		return nil
	})
	if changed {
		s.fences = index
		s.generation++
	}
	s.grants = rows
}
func pendingGrantKey(tenant, id string) string { return tenant + "\x00" + id }

func (s *Store) overlayPending(next map[string]Grant) {
	// A failed transaction may have created a synthetic tenant-wide denial.
	// Retain it while that tenant still exists, but never resurrect an erased
	// tenant whose entire grant/fence authority has been removed.
	tenants := make(map[string]bool)
	for _, g := range next {
		tenants[g.TenantID] = true
	}
	for _, g := range s.pending {
		if old, ok := next[g.GrantID]; ok && old.TenantID == g.TenantID {
			old.Revoked = true
			old.ReauthenticateAfter = laterBoundary(old.ReauthenticateAfter, g.ReauthenticateAfter)
			old = cloneGrant(old)
			if g.ConsumedAt != "" {
				old.ConsumedAt = g.ConsumedAt
			}
			next[g.GrantID] = old
		} else if !ok && tenants[g.TenantID] && g.Revoked && g.ReauthenticateAfter != "" && fenceSelector(g) == (reauthenticationSelector{tenant: g.TenantID}) {
			next[g.GrantID] = cloneGrant(g)
		}
	}
}

type sharedGrantMutation struct {
	revokeTenant, revokeID string
	eraseTenant            string
	reauthenticateAt       time.Time
}

// mutateShared holds the latest authority row throughout the edit. New allows
// become visible only after commit. Failed denials remain local and retryable.
func (s *Store) mutateShared(ctx context.Context, edit func(*Store) error, options ...sharedGrantMutation) (bool, error) {
	// File/standalone readers and writers do not wait for an unrelated shared
	// transaction. Recheck after acquiring the writer gate for shared stores.
	s.mu.RLock()
	shared := s.sharedLocked()
	s.mu.RUnlock()
	if !shared {
		return false, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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
	var committedDigest [32]byte
	callbackStarted := false
	observedAuthority := s.authorityKnown
	var option sharedGrantMutation
	if len(options) > 0 {
		option = options[0]
	}
	build := func(raw []byte) ([]byte, error) {
		callbackStarted = true
		var rows map[string]Grant
		var err error
		if raw == nil {
			if observedAuthority {
				return nil, ErrPersistence
			}
			rows = cloneGrants(s.grants)
		} else {
			rows, err = decodeShared(raw)
			if err != nil {
				return nil, err
			}
			observedAuthority = true
		}
		s.overlayPending(rows)
		before := cloneGrants(rows)
		next = NewStore()
		next.grants = rows
		next.rebuildReauthenticationIndexLocked()
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
			if prev, ok := before[id]; g.Revoked && (!ok || !prev.Revoked || g.ReauthenticateAfter != prev.ReauthenticateAfter) {
				denials[pendingGrantKey(g.TenantID, id)] = cloneGrant(g)
			}
		}
		if len(denials) > 0 {
			s.mu.Lock()
			s.latchDenialsLocked(denials)
			s.mu.Unlock()
		}
		encoded, err := encodeGrantSnapshot(next.grants)
		if err == nil {
			committedDigest = sha256.Sum256(encoded)
		}
		return encoded, err
	}
	var err error
	persister := s.persister
	err = s.withAuthorizationReaders(func() error {
		switch p := persister.(type) {
		case contextUpdater:
			return p.UpdateContext(ctx, build)
		case updater:
			if ctx.Err() != nil {
				return ctx.Err()
			} else {
				return p.Update(build)
			}
		}
		return ErrPersistence
	})
	s.authorityKnown = s.authorityKnown || observedAuthority
	if err != nil {
		if editErr != nil {
			return true, editErr
		}
		// A transaction/lease refusal can precede the callback. Deny only the
		// known target in this tenant; never turn an unknown ID into a record.
		if !callbackStarted && option.revokeTenant != "" {
			if g, ok := s.grants[option.revokeID]; ok && g.TenantID == option.revokeTenant {
				g.Revoked = true
				if !option.reauthenticateAt.IsZero() && g.ReauthenticateAfter == "" {
					g.ReauthenticateAfter = option.reauthenticateAt.UTC().Format(time.RFC3339Nano)
					g = cloneGrant(g)
				}
				denials = map[string]Grant{pendingGrantKey(g.TenantID, g.GrantID): g}
			}
		}
		if len(denials) > 0 {
			s.latchDenialsLocked(denials)
		}
		return true, ErrPersistence
	}
	s.publishLocked(next.grants)
	for key, g := range s.pending {
		committed, present := next.grants[g.GrantID]
		if (present && committed.TenantID == g.TenantID && committed.Revoked && laterBoundary(committed.ReauthenticateAfter, g.ReauthenticateAfter) == committed.ReauthenticateAfter) || (option.eraseTenant != "" && g.TenantID == option.eraseTenant) {
			delete(s.pending, key)
		}
	}
	s.dirty = len(s.pending) > 0
	s.authorityKnown = true
	s.authorityDigest = committedDigest
	s.readRefreshAt, s.readRefreshErr = time.Now(), nil
	return true, nil
}

// Caller holds writeMu and mu. A transaction may block after its callback;
// deny immediately and retain the latch if commit becomes ambiguous.
func (s *Store) latchDenialsLocked(denials map[string]Grant) {
	if s.pending == nil {
		s.pending = make(map[string]Grant)
	}
	var nextLocal map[string]Grant
	_ = s.withAuthorizationReaders(func() error { nextLocal = cloneGrants(s.grants); return nil })
	for key, g := range denials {
		s.pending[key] = cloneGrant(g)
		if old, ok := nextLocal[g.GrantID]; !ok || old.TenantID == g.TenantID {
			nextLocal[g.GrantID] = cloneGrant(g)
		}
	}
	s.publishLocked(nextLocal)
	s.dirty = true
}

// A read decoded against an older local generation must never overwrite a
// newer mint/denial or a re-bound persistence source.
var errRefreshSuperseded = errors.New("shared snapshot superseded by a local writer")

func (s *Store) RefreshShared() error {
	return s.refreshShared(false)
}

// Snapshot readers already hold the writer gate so a local login cannot
// repeatedly supersede their one authority read. Authorization reads retain
// the existing nonblocking refresh path and freshness bound.
func (s *Store) refreshShared(writerLocked bool) error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	if !s.sharedLocked() {
		s.mu.RUnlock()
		return nil
	}
	p, generation, epoch, known, digest := s.persister, s.generation, s.persistenceEpoch, s.authorityKnown, s.authorityDigest
	s.mu.RUnlock()
	started := time.Now()
	var raw []byte
	var unchanged bool
	var err error
	if loader, ok := p.(conditionalLoader); ok {
		raw, unchanged, err = loader.LoadIfUnchanged(digest)
	} else {
		raw, err = p.Load()
	}
	if err != nil {
		return ErrPersistence
	}
	if raw == nil && known && !unchanged {
		return ErrPersistence
	}
	hash := digest
	var rows map[string]Grant
	if !unchanged {
		hash = sha256.Sum256(raw)
	}
	if hash != digest {
		if raw == nil {
			rows = make(map[string]Grant)
		} else {
			rows, err = decodeShared(raw)
			if err != nil {
				return ErrPersistence
			}
		}
	}
	// Ordinary refresh loads without the writer gate, then rejects a superseded
	// result. A checked snapshot instead reserves that gate before loading so
	// continuous local logins cannot starve its generation/row capture. Neither
	// path holds the authorization lock over shared I/O; data-path reads retain
	// their independent freshness bound.
	if !writerLocked {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation || s.persistenceEpoch != epoch {
		return errRefreshSuperseded
	}
	if hash != digest {
		_ = s.withAuthorizationReaders(func() error { s.overlayPending(rows); return nil })
		s.publishLocked(rows)
		s.authorityDigest = hash
	}
	s.authorityKnown = s.authorityKnown || raw != nil
	// The age starts before I/O, never after a slow load/decode/commit wait.
	s.readRefreshAt, s.readRefreshErr = started, nil
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

// Process valid, correctly attributed denials before conflicting admissions.
func (s *Store) MergeCheckedContext(ctx context.Context, incoming []Grant, now time.Time) (int, int, error) {
	return s.mergeBatchContext(ctx, incoming, now, false)
}

// MergeAuthorityEvidence is reserved for a snapshot whose CP signature was
// verified by the caller. Peer grant reports must use MergeCheckedContext.
func (s *Store) MergeAuthorityEvidence(incoming []Grant, now time.Time) (int, int, error) {
	return s.mergeBatchContext(context.Background(), incoming, now, true)
}

func (s *Store) mergeBatchContext(ctx context.Context, incoming []Grant, now time.Time, authorityEvidence bool) (int, int, error) {
	var denials []Grant
	for _, g := range incoming {
		if g.Revoked && validateGrant(g) == nil {
			s.mu.RLock()
			old, exists := s.grants[g.GrantID]
			s.mu.RUnlock()
			if !exists || old.TenantID == g.TenantID {
				denials = append(denials, g)
			}
		}
	}
	a, u := 0, 0
	if len(denials) > 0 {
		var err error
		a, u, err = s.mergeCheckedContext(ctx, denials, now)
		if err != nil {
			return a, u, err
		}
	}
	b, v, err := s.mergeCheckedContextWithEvidence(ctx, incoming, now, authorityEvidence)
	return a + b, u + v, err
}
func (s *Store) mergeCheckedContext(ctx context.Context, incoming []Grant, now time.Time) (int, int, error) {
	return s.mergeCheckedContextWithEvidence(ctx, incoming, now, false)
}
func (s *Store) mergeCheckedContextWithEvidence(ctx context.Context, incoming []Grant, now time.Time, authorityEvidence bool) (int, int, error) {
	if s.unchangedSharedReport(ctx, incoming) {
		return 0, 0, nil
	}
	var added, updated, denialAdded, denialUpdated int
	handled, err := s.mutateShared(ctx, func(c *Store) error {
		before := cloneGrants(c.grants)
		var e error
		added, updated, e = c.mergeLocalWithEvidence(s.withoutLatchedGrants(incoming, before), now, authorityEvidence)
		if e == nil {
			for id, g := range c.grants {
				prev, exists := before[id]
				if g.Revoked && (!exists || !prev.Revoked || g.ReauthenticateAfter != prev.ReauthenticateAfter) {
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
		return s.mergeLocalWithEvidence(incoming, now, authorityEvidence)
	}
	if err != nil {
		if !errors.Is(err, ErrPersistence) {
			return 0, 0, err
		}
		return denialAdded, denialUpdated, err
	}
	return added, updated, nil
}

// A periodic Edge report often repeats grants already held by the CP. Confirm
// the shared authority before skipping its write transaction: the local map
// alone may predate a revocation or an authority failure. Any uncertainty uses
// the original transactional merge, which validates the complete batch.
func (s *Store) unchangedSharedReport(ctx context.Context, incoming []Grant) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	s.mu.RLock()
	shared := s.sharedLocked()
	s.mu.RUnlock()
	if !shared || s.RefreshShared() != nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.sharedLocked() || len(s.pending) != 0 {
		return false
	}
	for _, raw := range incoming {
		current, ok := s.grants[raw.GrantID]
		if !ok || !reflect.DeepEqual(current, cloneGrant(raw)) {
			return false
		}
	}
	return true
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
	rows, _, err := s.SnapshotAllChecked()
	return rows, err
}

// SnapshotGenerationChecked captures a checked lower bound for a subsequent
// snapshot stream without copying every row twice. Local writes may advance
// this bound after return but cannot invalidate the completed authority read.
func (s *Store) SnapshotGenerationChecked() (uint64, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.refreshShared(true); err != nil {
		return 0, err
	}
	return s.ConfigGeneration(), nil
}

// SnapshotAllChecked returns independent rows and their local generation from
// the same read lock. A writer may advance the authority after this boundary;
// it must not relabel these rows or invalidate a transfer already in progress.
func (s *Store) SnapshotAllChecked() ([]Grant, uint64, error) {
	s.writeMu.Lock()
	if err := s.refreshShared(true); err != nil {
		s.writeMu.Unlock()
		return nil, 0, err
	}
	s.mu.RLock()
	rows := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		rows = append(rows, cloneGrant(g))
	}
	generation := s.generation
	s.mu.RUnlock()
	s.writeMu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].GrantID < rows[j].GrantID })
	return rows, generation, nil
}

// withoutLatchedGrants drops reported grants this process holds an unconfirmed
// denial for, when the latest row no longer has them (a peer erased them). An
// Edge keeps reporting such a grant until it expires; admitting it would revive
// an erased record, and refusing it refused the whole batch, so no other grant
// that Edge reported was ever admitted. Caller holds writeMu (mutateShared).
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

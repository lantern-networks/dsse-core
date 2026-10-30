package grantstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/runtimequota"
)

var ErrReauthenticationRequired = errors.New("authentication predates administrator revocation")

// Fences have no time-based expiry. If distinct active selectors reach this
// threshold, consolidate to a stricter tenant-wide boundary, never reject a
// revocation. Replay tombstones stay until their independent retention horizon.
const MaxReauthenticationFencesPerTenant = 4096

type reauthenticationSelector struct {
	tenant, idp, issuer, user, device, principal, scope string
}

func fenceSelector(g Grant) reauthenticationSelector {
	return reauthenticationSelector{g.TenantID, g.IdPID, g.Issuer, g.UserID, g.DeviceID, g.OSPrincipal, g.Scope}
}

type reauthenticationFenceCutoff struct {
	id string
	at time.Time
}
type reauthenticationFenceIndex map[reauthenticationSelector]reauthenticationFenceCutoff

// Build once per prune, rather than scanning every tenant's rows for every
// expired fence. Exact selectors keep wildcard restrictions separate.
func indexReauthenticationFences(rows map[string]Grant) reauthenticationFenceIndex {
	index := make(reauthenticationFenceIndex)
	for id, g := range rows {
		at, err := time.Parse(time.RFC3339Nano, g.ReauthenticateAfter)
		if !g.Revoked || g.ReauthenticateAfter == "" {
			continue
		}
		if err != nil {
			at = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		key := fenceSelector(g)
		old, ok := index[key]
		if !ok || at.After(old.at) || (at.Equal(old.at) && id > old.id) {
			index[key] = reauthenticationFenceCutoff{id, at}
		}
	}
	return index
}

// Only a wider selector may replace a narrow one. In particular a narrow
// selector does NOT subsume a wildcard, even though an unknown login subject
// conservatively matches both during admission.
func redundantReauthenticationFence(g Grant, index reauthenticationFenceIndex) bool {
	at, err := time.Parse(time.RFC3339Nano, g.ReauthenticateAfter)
	if err != nil || !g.Revoked {
		return false
	}
	key := fenceSelector(g)
	values := [6]string{key.idp, key.issuer, key.user, key.device, key.principal, key.scope}
	var covered func(int, [6]string) bool
	covered = func(i int, v [6]string) bool {
		if i == len(v) {
			parent := reauthenticationSelector{key.tenant, v[0], v[1], v[2], v[3], v[4], v[5]}
			newest, ok := index[parent]
			return ok && newest.id != g.GrantID && !newest.at.Before(at)
		}
		if covered(i+1, v) {
			return true
		}
		if v[i] != "" {
			v[i] = ""
			return covered(i+1, v)
		}
		return false
	}
	return covered(0, values)
}

// The boundary deliberately survives OS logout, provider configuration edits,
// original-grant expiry, and replacement grant IDs. Empty legacy selectors are
// conservative wildcards. A wide replacement scope cannot evade a narrow fence.
func reauthenticationMatches(fence, subject Grant, scope string) bool {
	if fence.TenantID != subject.TenantID {
		return false
	}
	for _, pair := range [][2]string{{fence.IdPID, subject.IdPID}, {fence.Issuer, subject.Issuer}, {fence.UserID, subject.UserID}, {fence.DeviceID, subject.DeviceID}, {fence.OSPrincipal, subject.OSPrincipal}} {
		if pair[0] != "" && pair[1] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return fence.Scope == "" || scope == "" || fence.Scope == scope
}

// ReauthenticationAfterChecked reads authority, never treating a failed read as
// no revocation. An unknown subject at browser start is a conservative selector;
// callback and the atomic mint use the verified subject instead.
func (s *Store) ReauthenticationAfterChecked(subject Grant, scope string) (time.Time, error) {
	if err := s.RefreshShared(); err != nil {
		return time.Time{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reauthenticationAfterLocked(subject, scope), nil
}

// AuthorizationFresh is a final gate against other, previously minted IDs.
func (s *Store) AuthorizationFresh(g Grant, scope string) bool {
	fresh, _ := s.AuthorizationFreshChecked(g, scope)
	return fresh
}

// AuthorizationFreshChecked preserves a shared-store read failure for callers
// that must avoid mistaking an unavailable authority for a missing grant.
func (s *Store) AuthorizationFreshChecked(g Grant, scope string) (bool, error) {
	return s.authorizationFreshAtChecked(g, scope, time.Now().UTC())
}
func (s *Store) authorizationFreshAt(g Grant, scope string, now time.Time) bool {
	fresh, _ := s.authorizationFreshAtChecked(g, scope, now)
	return fresh
}
func (s *Store) authorizationFreshAtChecked(g Grant, scope string, now time.Time) (bool, error) {
	if err := s.refreshForRead(); err != nil {
		return false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authorizationFreshLocked(g, scope, now), nil
}

func (s *Store) requireReauthenticationLocal(tenant, id string, now time.Time) (Grant, bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok || g.TenantID != tenant {
		return Grant{}, false, nil
	}
	if g.ReauthenticateAfter == "" {
		if now.IsZero() || now.Unix() <= 0 {
			return Grant{}, false, ErrInvalidGrant
		}
		g.Revoked = true
		g.ReauthenticateAfter = now.UTC().Format(time.RFC3339Nano)
		g = cloneGrant(g)
		s.grants[id] = g
		s.rebuildReauthenticationIndexLocked()
		s.consolidateReauthenticationFencesLocked(tenant, now)
		s.generation++
		s.dirty = true
	}
	if err := s.persistLocked(); err != nil {
		return cloneGrant(g), true, err
	}
	return cloneGrant(g), true, nil
}

// A synthetic denial uses the existing protected grant format; it can never
// authorize traffic and older readers cannot erase its freshness boundary.
func (s *Store) consolidateReauthenticationFencesLocked(tenant string, now time.Time) {
	threshold := runtimequota.CountDefault("DSSE_REAUTHENTICATION_FENCE_COMPACTION_THRESHOLD", MaxReauthenticationFencesPerTenant)
	if threshold == 0 || s.fences.count(tenant) <= threshold {
		return
	}
	var at time.Time
	for _, scopes := range s.fences[tenant] {
		for _, entries := range scopes {
			for _, c := range entries {
				if c.at.After(at) {
					at = c.at
				}
			}
		}
	}
	wide, exists := s.fences[tenant][""][""][reauthenticationSelector{tenant: tenant}]
	id := wide.id
	if !exists {
		for n := 0; ; n++ {
			hash := sha256.Sum256([]byte(fmt.Sprintf("DSSE reauthentication boundary v1\x00%s\x00%d", tenant, n)))
			id = fmt.Sprintf("reauth-%x", hash)
			if _, taken := s.grants[id]; !taken {
				break
			}
		}
		s.grants[id] = Grant{GrantID: id, TenantID: tenant, Revoked: true, IssuedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(time.Second).UTC().Format(time.RFC3339)}
	}
	g := s.grants[id]
	g.ReauthenticateAfter = at.UTC().Format(time.RFC3339Nano)
	s.grants[id] = cloneGrant(g)
	// Expired, subsumed fences may leave now; live/recent grant IDs remain as
	// replay tombstones even when their boundary is represented by the wide row.
	index := indexReauthenticationFences(s.grants)
	for id, g := range s.grants {
		if g.TenantID == tenant && prunableGrant(g, index, now) {
			delete(s.grants, id)
		}
	}
	s.rebuildReauthenticationIndexLocked()
}

// Only explicit administration calls this method. Consumption and ordinary
// per-ID revocation retain their existing meanings and never create a fence.
func (s *Store) RequireReauthenticationForTenantContext(ctx context.Context, tenant, id string, now time.Time) (Grant, bool, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if tenant == "" || id == "" || now.IsZero() || now.Unix() <= 0 {
		return Grant{}, false, ErrInvalidGrant
	}
	var out Grant
	var found bool
	handled, err := s.mutateShared(ctx, func(c *Store) error {
		var e error
		out, found, e = c.requireReauthenticationLocal(tenant, id, now)
		return e
	}, sharedGrantMutation{revokeTenant: tenant, revokeID: id, reauthenticateAt: now})
	if !handled {
		return s.requireReauthenticationLocal(tenant, id, now)
	}
	if err != nil {
		s.mu.RLock()
		g, applied := s.pending[pendingGrantKey(tenant, id)]
		s.mu.RUnlock()
		if applied {
			return cloneGrant(g), true, err
		}
		return Grant{}, false, err
	}
	return out, found, nil
}

func laterBoundary(a, b string) string {
	x, _ := time.Parse(time.RFC3339Nano, a)
	y, _ := time.Parse(time.RFC3339Nano, b)
	if y.After(x) {
		return b
	}
	return a
}

func addReauthenticationFeature(g *Grant) {
	if g.ReauthenticateAfter != "" && !slices.Contains(g.RequiredFeatures, FeatureRevocationReauthentication) {
		g.RequiredFeatures = append(append([]string(nil), g.RequiredFeatures...), FeatureRevocationReauthentication)
	}
}

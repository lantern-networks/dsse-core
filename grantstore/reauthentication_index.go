package grantstore

import "time"

// Built only on fence mutations, restore, or publication. Authorization reads
// neither parse timestamps nor scan grants belonging to other tenants/users.
type reauthenticationReadIndex map[string]map[string]map[string]reauthenticationFenceIndex

func newReauthenticationReadIndex(rows map[string]Grant) reauthenticationReadIndex {
	all := indexReauthenticationFences(rows)
	out := make(reauthenticationReadIndex)
	for selector, cutoff := range all {
		wide, ok := all[reauthenticationSelector{tenant: selector.tenant}]
		if ok && wide.id != cutoff.id && !wide.at.Before(cutoff.at) {
			continue
		}
		if out[selector.tenant] == nil {
			out[selector.tenant] = make(map[string]map[string]reauthenticationFenceIndex)
		}
		if out[selector.tenant][selector.user] == nil {
			out[selector.tenant][selector.user] = make(map[string]reauthenticationFenceIndex)
		}
		if out[selector.tenant][selector.user][selector.scope] == nil {
			out[selector.tenant][selector.user][selector.scope] = make(reauthenticationFenceIndex)
		}
		out[selector.tenant][selector.user][selector.scope][selector] = cutoff
	}
	return out
}

func (s *Store) rebuildReauthenticationIndexLocked() {
	s.fences = newReauthenticationReadIndex(s.grants)
}

func (index reauthenticationReadIndex) after(subject Grant, scope string) time.Time {
	var boundary time.Time
	scan := func(entries reauthenticationFenceIndex) {
		for selector, cutoff := range entries {
			fence := Grant{TenantID: selector.tenant, IdPID: selector.idp, Issuer: selector.issuer, UserID: selector.user, DeviceID: selector.device, OSPrincipal: selector.principal, Scope: selector.scope}
			if reauthenticationMatches(fence, subject, scope) && cutoff.at.After(boundary) {
				boundary = cutoff.at
			}
		}
	}
	scanUser := func(scopes map[string]reauthenticationFenceIndex) {
		if scope != "" {
			scan(scopes[scope])
			scan(scopes[""])
		} else {
			for _, entries := range scopes {
				scan(entries)
			}
		}
	}
	users := index[subject.TenantID]
	if subject.UserID != "" {
		scanUser(users[subject.UserID])
		scanUser(users[""])
	} else {
		for _, scopes := range users {
			scanUser(scopes)
		}
	}
	return boundary
}

func (s *Store) reauthenticationAfterLocked(subject Grant, scope string) time.Time {
	return s.fences.after(subject, scope)
}

func (s *Store) authorizationFreshLocked(g Grant, scope string, now time.Time) bool {
	after := s.reauthenticationAfterLocked(g, scope)
	if after.IsZero() {
		return true
	}
	auth, err := time.Parse(time.RFC3339, g.AuthTime)
	return err == nil && auth.After(after) && !auth.After(now)
}

// Count effective selectors, excluding rows covered by a tenant-wide cutoff.
func (index reauthenticationReadIndex) count(tenant string) int {
	n := 0
	for _, scopes := range index[tenant] {
		for _, entries := range scopes {
			n += len(entries)
		}
	}
	return n
}

// ReauthenticationScope reports when bounded compaction widened this particular
// revocation, so the management response can make the extra reauthentication visible.
func (s *Store) ReauthenticationScope(g Grant) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wide, ok := s.fences[g.TenantID][""][""][reauthenticationSelector{tenant: g.TenantID}]
	cutoff, err := time.Parse(time.RFC3339Nano, g.ReauthenticateAfter)
	if ok && err == nil && !wide.at.Before(cutoff) {
		return "tenant"
	}
	return "approval"
}

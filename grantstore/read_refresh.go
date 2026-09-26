package grantstore

import (
	"strings"
	"time"
)

// Data-path reads share one refresh for up to five seconds. Explicit checked
// administration and publication refreshes still consult current authority.
func (s *Store) refreshForRead() error {
	if s == nil {
		return nil
	}
	s.readRefreshMu.Lock()
	defer s.readRefreshMu.Unlock()
	if time.Since(s.readRefreshAt) < 5*time.Second {
		return s.readRefreshErr
	}
	s.readRefreshErr = s.RefreshShared()
	s.readRefreshAt = time.Now()
	return s.readRefreshErr
}

func (s *Store) GetForAuthorization(id string) (Grant, bool) {
	if s.refreshForRead() != nil {
		return Grant{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[strings.TrimSpace(id)]
	return cloneGrant(g), ok
}
func (s *Store) ValidForAuthorization(id string, now time.Time) bool {
	g, ok := s.GetForAuthorization(id)
	if !ok || g.Revoked {
		return false
	}
	exp, e := time.Parse(time.RFC3339, g.ExpiresAt)
	return e == nil && now.Before(exp)
}
func (s *Store) ListForAuthorization(tenant string) []Grant {
	if s.refreshForRead() != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.grants {
		if g.TenantID == tenant {
			out = append(out, cloneGrant(g))
		}
	}
	return out
}

package grantstore

import (
	"errors"
	"strings"
	"time"
)

// Data-path reads never wait for a shared snapshot. Refresh proactively halfway
// through the existing five-second bound. If the snapshot is older than that
// bound, fail closed immediately; a blocked/failed load never extends its age.
// Explicit checked administration still calls synchronous RefreshShared.
func (s *Store) refreshForRead() error { return s.refreshForReadWithin(5 * time.Second) }
func (s *Store) refreshForReadWithin(maxAge time.Duration) error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	shared, at, err := s.sharedLocked(), s.readRefreshAt, s.readRefreshErr
	s.mu.RUnlock()
	if !shared {
		return nil
	}
	now := time.Now()
	age := now.Sub(at)
	if at.IsZero() || age >= maxAge/2 || err != nil {
		s.readRefreshMu.Lock()
		if !s.readRefreshRunning && (s.readRefreshAttempt.IsZero() || now.Sub(s.readRefreshAttempt) >= maxAge/2) {
			s.readRefreshRunning = true
			s.readRefreshAttempt = now
			go func() {
				e := s.RefreshShared()
				if e != nil && !errors.Is(e, errRefreshSuperseded) {
					s.mu.Lock()
					if s.readRefreshAt.Equal(at) {
						s.readRefreshErr = e
					}
					s.mu.Unlock()
				}
				s.readRefreshMu.Lock()
				s.readRefreshRunning = false
				s.readRefreshMu.Unlock()
			}()
		}
		s.readRefreshMu.Unlock()
	}
	if err != nil || at.IsZero() || age >= maxAge {
		return ErrPersistence
	}
	return nil
}

func (s *Store) GetForAuthorization(id string) (Grant, bool) {
	if s.refreshForRead() != nil {
		return Grant{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[strings.TrimSpace(id)]
	return cloneGrant(g), ok && g.Supported() && s.authorizationFreshLocked(g, g.Scope, time.Now().UTC())
}
func (s *Store) ValidForAuthorization(id string, now time.Time) bool {
	g, ok := s.GetForAuthorization(id)
	if !ok || g.Revoked || !g.Supported() {
		return false
	}
	exp, e := time.Parse(time.RFC3339, g.ExpiresAt)
	return e == nil && now.Before(exp)
}
func (s *Store) ListForAuthorization(tenant string) []Grant {
	rows, _ := s.ListForAuthorizationChecked(tenant)
	return rows
}

// ListForAuthorizationChecked distinguishes an empty, fresh authority from an
// unavailable shared store. Callers starting a login ceremony need that difference.
func (s *Store) ListForAuthorizationChecked(tenant string) ([]Grant, error) {
	return s.listForAuthorizationWithinChecked(tenant, 5*time.Second)
}

func (s *Store) listForAuthorizationWithin(tenant string, maxAge time.Duration) []Grant {
	rows, _ := s.listForAuthorizationWithinChecked(tenant, maxAge)
	return rows
}

func (s *Store) listForAuthorizationWithinChecked(tenant string, maxAge time.Duration) ([]Grant, error) {
	if err := s.refreshForReadWithin(maxAge); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.grants {
		if g.TenantID == tenant && g.Supported() {
			out = append(out, cloneGrant(g))
		}
	}
	return out, nil
}

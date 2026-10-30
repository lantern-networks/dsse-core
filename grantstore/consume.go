package grantstore

import (
	"context"
	"time"
)

// ConsumeAuthenticationRequest confirms a single authorization release. The
// revoked row is also its consumption tombstone. Match the evidence evaluated
// by the caller inside the authority transaction; ambiguous commit is denial.
func (s *Store) ConsumeAuthenticationRequest(ctx context.Context, expected Grant, now time.Time) (bool, error) {
	if expected.AuthenticationRequestID == "" {
		return false, ErrInvalidGrant
	}
	consumed := false
	handled, err := s.mutateShared(ctx, func(c *Store) error {
		var e error
		consumed, e = c.consumeAuthenticationLocal(expected, now)
		return e
	})
	if !handled {
		return s.consumeAuthenticationLocal(expected, now)
	}
	if err != nil {
		return false, err
	}
	return consumed, nil
}

func (s *Store) consumeAuthenticationLocal(expected Grant, now time.Time) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[expected.GrantID]
	expiry, e := time.Parse(time.RFC3339, g.ExpiresAt)
	if !ok || !g.Supported() || g.Revoked || !sameAuthorization(g, expected) || e != nil || !now.Before(expiry) || !s.authorizationFreshLocked(g, g.Scope, now) {
		return false, nil
	}
	// A duplicated ceremony at another Portal cannot issue a second allowance.
	for _, other := range s.grants {
		if other.TenantID == g.TenantID && other.AuthenticationRequestID == g.AuthenticationRequestID && other.Revoked {
			return false, nil
		}
	}
	g.ConsumedAt = now.UTC().Format(time.RFC3339)
	s.grants[g.GrantID] = g
	_, _, err := s.revokeLocked(g.GrantID)
	if err != nil {
		return false, err
	}
	return true, nil
}

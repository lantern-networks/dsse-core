package idpregistry

import (
	"strings"
	"time"
)

const authorizationRefreshInterval = 250 * time.Millisecond

// ResolveForAuthorization coalesces concurrent held-flow polling. Administrative
// reads and callback/provider checks still use uncached Resolve/Get. A failed
// refresh remains a denial, never a fallback to a last-known successful snapshot.
// Changes made to this Store are visible immediately; peer changes have at most
// this read interval of additional latency.
func (s *Store) ResolveForAuthorization(tenant, required string) (Connection, bool) {
	if s == nil {
		return Connection{}, false
	}
	s.authReadMu.Lock()
	if s.authReadAt.IsZero() || time.Since(s.authReadAt) >= authorizationRefreshInterval {
		s.authReadErr = s.RefreshShared()
		s.authReadAt = time.Now()
	}
	err := s.authReadErr
	s.authReadMu.Unlock()
	if err != nil {
		return Connection{}, false
	}
	tenant, required = strings.TrimSpace(tenant), strings.TrimSpace(required)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if required == "" {
		required = s.defaults[tenant]
	}
	c, ok := s.connections[tenant][required]
	c.VerifiedDomains = append([]string(nil), c.VerifiedDomains...)
	c.DeviceUserBindings = append([]DeviceUserBinding(nil), c.DeviceUserBindings...)
	return c, ok
}

package humanapproval

import (
	"github.com/lantern-networks/dsse-core/model"
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

func (s *Store) GetForAuthorization(tenant, id string) (model.HumanApprovalEvent, bool) {
	if s == nil || validKey(tenant, id) != nil || s.refreshForRead() != nil {
		return model.HumanApprovalEvent{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.events[approvalKey(tenant, id)]
	return v, ok
}

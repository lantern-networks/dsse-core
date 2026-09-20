package policy

import (
	"context"
	"github.com/lantern-networks/dsse-core/decision"
	"strings"
)

func (s *Store) ApplyEastWestUpdateConfirmed(tenant string, rules *[]decision.EastWestRule, ttl *int, enabled, unmatched *bool) error {
	return s.ApplyEastWestUpdateContext(context.Background(), tenant, rules, ttl, enabled, unmatched)
}

// Save all explicitly supplied fields in one latest-row transaction.
func (s *Store) ApplyEastWestUpdateContext(ctx context.Context, tenant string, rules *[]decision.EastWestRule, ttl *int, enabled, unmatched *bool) error {
	if s == nil {
		return ErrPolicyPersistence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant = strings.TrimSpace(tenant)
	return s.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		if rules != nil {
			f.EastWestRules[tenant] = append([]decision.EastWestRule(nil), (*rules)...)
		}
		if ttl != nil {
			f.EastWestMaxGrantTTL[tenant] = max(0, *ttl)
		}
		if enabled != nil {
			f.EastWestEnabled[tenant] = *enabled
		}
		if unmatched != nil {
			f.EastWestAllowUnmatched[tenant] = *unmatched
		}
		return nil
	})
}

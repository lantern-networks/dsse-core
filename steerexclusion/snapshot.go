package steerexclusion

import (
	"fmt"
	"strings"
)

// ListSchema identifies a complete tenant-scoped list, including a deliberate
// empty array. Missing, null, or foreign data must never revoke the held set.
const ListSchema = "admin_steer_exclusions.v1"

// ValidateTenantPolicies checks the complete set before a replacement can begin.
// It does not normalize or reassign incoming data to a different tenant.
func ValidateTenantPolicies(tenantID string, policies []Policy) error {
	if tenantID == "" || strings.TrimSpace(tenantID) != tenantID {
		return fmt.Errorf("a canonical tenant_id is required")
	}
	if policies == nil {
		return fmt.Errorf("steer_exclusions must be an explicit array")
	}
	seen := make(map[string]bool, len(policies))
	for i, p := range policies {
		if p.ID == "" || strings.TrimSpace(p.ID) != p.ID || seen[p.ID] {
			return fmt.Errorf("invalid or duplicate policy id at row %d", i)
		}
		seen[p.ID] = true
		if p.TenantID != tenantID {
			return fmt.Errorf("policy tenant mismatch at row %d", i)
		}
		if !validScope[p.ScopeType] || strings.TrimSpace(p.ScopeID) != p.ScopeID || (p.ScopeType == scopeTenant && p.ScopeID != "") || (p.ScopeType != scopeTenant && p.ScopeID == "") {
			return fmt.Errorf("invalid policy scope at row %d", i)
		}
		if p.Status != statusActive {
			return fmt.Errorf("invalid policy status at row %d", i)
		}
		if len(p.ExcludedAppSigningIDs) == 0 {
			return fmt.Errorf("empty app identifiers at row %d", i)
		}
		apps := map[string]bool{}
		for _, id := range p.ExcludedAppSigningIDs {
			if id == "" || strings.TrimSpace(id) != id || apps[id] {
				return fmt.Errorf("invalid or duplicate app identifier at row %d", i)
			}
			apps[id] = true
		}
	}
	return nil
}

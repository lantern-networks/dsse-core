package releasedv031

import (
	"strings"
	"time"
)

// This predicate is copied verbatim from the released commit cited in README.
type federatedAuthGate struct {
	grants   *Store
	tenantID string
}

func GateAccepts(s *Store, tenant, device, acr string) bool {
	return (&federatedAuthGate{grants: s, tenantID: tenant}).hasLiveGrantFor(tenant, device, acr)
}

func (g *federatedAuthGate) hasLiveGrantFor(tenantID, deviceID, requiredACR string) bool {
	if g == nil || g.grants == nil {
		return false
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = g.tenantID
	}
	deviceID = strings.TrimSpace(deviceID)
	requiredACR = strings.TrimSpace(requiredACR)
	now := time.Now().UTC()
	for _, gr := range g.grants.ListForAuthorization(strings.TrimSpace(tenantID)) {
		expires, err := time.Parse(time.RFC3339, gr.ExpiresAt)
		if gr.Revoked || err != nil || !now.Before(expires) {
			continue
		}
		if deviceID != "" && strings.TrimSpace(gr.DeviceID) != "" && gr.DeviceID != deviceID {
			continue // a grant bound to a different device does not satisfy this device
		}
		if requiredACR != "" && strings.TrimSpace(gr.ACR) != requiredACR {
			continue // a grant minted at a weaker (or absent) assurance does not satisfy a step-up-gated resource
		}
		return true
	}
	return false
}

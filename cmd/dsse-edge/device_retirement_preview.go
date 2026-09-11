package main

import (
	"strings"
	"time"
)

// A read-only preview uses the exact candidate transformation and admission gate
// used by the POST. It never persists or authorizes a later POST: that request
// must remeasure the fleet and compare the durable authority again.
type deviceRetirementPreview struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	CheckedAt string `json:"checked_at"`
}

func previewDeviceRetirement(snapshot *tenantDeviceAuthority, tenant string, gates []pkiTransitionAdmission) deviceRetirementPreview {
	key := strings.ToLower(strings.TrimSpace(tenant))
	before := copyAuthority(snapshot.cas[key])
	candidate := newTenantDeviceAuthority(encodeAuthoritySnapshot(snapshot.cas), nil, snapshot.now)
	_, err := candidate.RetirePrevious(key)
	if err == nil {
		err = requirePKIAdmission(gates, pkiAuthorityTransition{Kind: "device", Action: "retire-previous", Tenant: key, DeviceBefore: before, DeviceAfter: copyAuthority(candidate.cas[key])})
	}
	out := deviceRetirementPreview{Allowed: err == nil, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if err != nil {
		out.Reason = err.Error()
	}
	return out
}

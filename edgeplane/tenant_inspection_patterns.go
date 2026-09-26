package edgeplane

import (
	"strconv"
	"strings"
)

// InspectionPatterns is a complete host-selection snapshot, not an additive
// tenant overlay. A tenant may remove a curated bypass without changing others.
type InspectionPatterns struct {
	Intercept []string
	Bypass    []string
	// Keys are exact, transport-authenticated device identities within this tenant.
	InterceptByDevice map[string][]string
	BypassByDevice    map[string][]string
}

func copyDeviceInspectionPatterns(input map[string][]string, normalize bool) map[string][]string {
	var out map[string][]string
	for device, hosts := range input {
		if device == "" || device != strings.TrimSpace(device) {
			continue
		}
		copy := append([]string{}, hosts...)
		if normalize {
			copy = NormalizedNetworkExtensionLabTLSHostPatterns(copy)
		}
		if len(copy) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[device] = copy
	}
	return out
}

// ReplaceInspectionPatterns publishes the deployment fallback and every tenant's
// complete selection together. Deleted tenants do not retain stale exceptions.
func (interception *NetworkExtensionLabTLSInterception) ReplaceInspectionPatterns(defaults InspectionPatterns, tenants map[string]InspectionPatterns) {
	if interception == nil {
		return
	}
	normalize := func(p InspectionPatterns) InspectionPatterns {
		return InspectionPatterns{Intercept: NormalizedNetworkExtensionLabTLSHostPatterns(p.Intercept), Bypass: NormalizedNetworkExtensionLabTLSHostPatterns(p.Bypass), InterceptByDevice: copyDeviceInspectionPatterns(p.InterceptByDevice, true), BypassByDevice: copyDeviceInspectionPatterns(p.BypassByDevice, true)}
	}
	defaults = normalize(defaults)
	// Device selectors require a tenant owner; fallback state is shared.
	defaults.InterceptByDevice, defaults.BypassByDevice = nil, nil
	next := make(map[string]InspectionPatterns, len(tenants))
	for tenant, patterns := range tenants {
		// Empty/ambiguous tenant keys must never change the deployment fallback.
		if tenant != "" && tenant == strings.TrimSpace(tenant) {
			next[tenant] = normalize(patterns)
		}
	}
	interception.hostMu.Lock()
	defer interception.hostMu.Unlock()
	interception.hosts, interception.bypassHosts = defaults.Intercept, defaults.Bypass
	interception.tenantPatterns = next
}

// Caller holds hostMu. Published slices are immutable after replacement.
func (interception *NetworkExtensionLabTLSInterception) inspectionPatternsLocked(tenant string) InspectionPatterns {
	if p, ok := interception.tenantPatterns[tenant]; ok && tenant != "" {
		return p
	}
	return InspectionPatterns{Intercept: interception.hosts, Bypass: interception.bypassHosts}
}

// InspectionPatternsForTenant exposes the same selection used by Matches. All
// arrays and device maps are copied under one lock so reads cannot mix revisions.
func (interception *NetworkExtensionLabTLSInterception) InspectionPatternsForTenant(tenant string) InspectionPatterns {
	if interception == nil {
		return InspectionPatterns{Intercept: []string{}, Bypass: []string{}}
	}
	interception.hostMu.RLock()
	defer interception.hostMu.RUnlock()
	p := interception.inspectionPatternsLocked(tenant)
	return InspectionPatterns{Intercept: append([]string{}, p.Intercept...), Bypass: append([]string{}, p.Bypass...), InterceptByDevice: copyDeviceInspectionPatterns(p.InterceptByDevice, false), BypassByDevice: copyDeviceInspectionPatterns(p.BypassByDevice, false)}
}

// Length-prefixing keeps tenant and host identities distinct even for unusual IDs.
func pinStateKey(tenant, host string) string { return strconv.Itoa(len(tenant)) + ":" + tenant + host }

// SetTenantCertPinCandidateEmitter carries the authenticated route owner into
// candidate attribution. The legacy callback is used only when this is unset.
func (interception *NetworkExtensionLabTLSInterception) SetTenantCertPinCandidateEmitter(emit func(tenant, host string)) {
	if interception == nil {
		return
	}
	interception.mu.Lock()
	defer interception.mu.Unlock()
	interception.certPinTenantEmitter = emit
}

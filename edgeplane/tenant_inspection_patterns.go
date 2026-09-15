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
}

// ReplaceInspectionPatterns publishes the deployment fallback and every tenant's
// complete selection together. Deleted tenants do not retain stale exceptions.
func (interception *NetworkExtensionLabTLSInterception) ReplaceInspectionPatterns(defaults InspectionPatterns, tenants map[string]InspectionPatterns) {
	if interception == nil {
		return
	}
	normalize := func(p InspectionPatterns) InspectionPatterns {
		return InspectionPatterns{Intercept: NormalizedNetworkExtensionLabTLSHostPatterns(p.Intercept), Bypass: NormalizedNetworkExtensionLabTLSHostPatterns(p.Bypass)}
	}
	defaults = normalize(defaults)
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

// InspectionPatternsForTenant exposes the same selection used by Matches. Both
// arrays are copied under one lock so administrative reads cannot mix revisions.
func (interception *NetworkExtensionLabTLSInterception) InspectionPatternsForTenant(tenant string) InspectionPatterns {
	if interception == nil {
		return InspectionPatterns{Intercept: []string{}, Bypass: []string{}}
	}
	interception.hostMu.RLock()
	defer interception.hostMu.RUnlock()
	p := interception.inspectionPatternsLocked(tenant)
	return InspectionPatterns{Intercept: append([]string{}, p.Intercept...), Bypass: append([]string{}, p.Bypass...)}
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

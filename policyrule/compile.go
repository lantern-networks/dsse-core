package policyrule

import (
	"sort"
	"strings"
)

// AddressResolver resolves catalog subject IDs to destination addresses.
type AddressResolver interface {
	EndpointAddresses(tenant string, ids []string) []string
}

// InspectionHostSelection preserves device restrictions separately from the
// host patterns applying to any source. Empty/unresolved sources are not Any.
// Risk and authored-rule precedence are not evaluated by this projection.
type InspectionHostSelection struct {
	AnySource []string
	ByDevice  map[string][]string
}

// EgressInspectionHosts projects one inspection axis into TLS/443 selectors.
// Device identities come from the tenant's catalog, never a user/agent selector
// or the endpoint's self-reported OS username. Identity-only rules cannot be
// applied at this pre-TLS layer; they contribute no device or shared host entry.
func EgressInspectionHosts(tenant string, rules []Rule, resolver AddressResolver, inspection string) InspectionHostSelection {
	all := map[string]bool{}
	devices := map[string]map[string]bool{}
	if inspection != InspectionInspect && inspection != InspectionBypass {
		return InspectionHostSelection{AnySource: []string{}}
	}
	for _, r := range rules {
		if (r.TenantID != "" && r.TenantID != tenant) || r.Plane != PlaneEgress || r.Status != StatusActive || r.Action.Inspection != inspection || r.Action.Access == AccessDeny || !inspectionServiceApplies(tenant, r.ServiceID, resolver) {
			continue
		}
		hosts := resolver.EndpointAddresses(tenant, r.Destination)
		if IsAnySubject(r.Source) {
			for _, host := range hosts {
				all[host] = true
			}
			continue
		}
		source, ok := resolver.(interface {
			SourceDeviceTokens(tenant string, ids []string) []string
		})
		if !ok {
			continue
		}
		var ids []string
		for _, id := range r.Source {
			// Reserved identity namespaces are never looked up as device catalog IDs.
			if id != strings.TrimSpace(id) || id == "" || strings.HasPrefix(id, IdentityGroupPrefix) || strings.HasPrefix(id, IdentityUserPrefix) || strings.HasPrefix(id, AgentPrefix) {
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			continue
		}
		for _, device := range source.SourceDeviceTokens(tenant, ids) {
			if device == "" || device != strings.TrimSpace(device) {
				continue
			}
			if devices[device] == nil {
				devices[device] = map[string]bool{}
			}
			for _, host := range hosts {
				devices[device][host] = true
			}
		}
	}
	sorted := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for value := range set {
			out = append(out, value)
		}
		sort.Strings(out)
		return out
	}
	result := InspectionHostSelection{AnySource: sorted(all)}
	for device, set := range devices {
		if len(set) == 0 {
			continue
		}
		if result.ByDevice == nil {
			result.ByDevice = map[string][]string{}
		}
		result.ByDevice[device] = sorted(set)
	}
	return result
}

// EgressBypassFQDNs returns only bypass hosts applying to any source. Device
// exceptions must be applied separately using EgressInspectionHosts.ByDevice.
func EgressBypassFQDNs(tenant string, rules []Rule, resolver AddressResolver) []string {
	return EgressInspectionHosts(tenant, rules, resolver, InspectionBypass).AnySource
}

// EgressInspectFQDNs returns only inspect hosts applying to any source. Under
// bypass-default, device-specific inspect hosts must remain scoped to that device.
func EgressInspectFQDNs(tenant string, rules []Rule, resolver AddressResolver) []string {
	return EgressInspectionHosts(tenant, rules, resolver, InspectionInspect).AnySource
}

// InspectionSourceWarning explains source selectors that cannot be represented
// by the TLS device selector. It does not change the access-policy compilation.
func InspectionSourceWarning(tenant string, rule Rule, resolver AddressResolver) string {
	if rule.Plane != PlaneEgress || IsAnySubject(rule.Source) || rule.Action.Access == AccessDeny {
		return ""
	}
	for _, id := range rule.Source {
		id = strings.TrimSpace(id)
		if strings.HasPrefix(id, IdentityGroupPrefix) || strings.HasPrefix(id, IdentityUserPrefix) || strings.HasPrefix(id, AgentPrefix) {
			return "identity_context_unavailable"
		}
	}
	if source, ok := resolver.(interface {
		SourceDeviceTokens(string, []string) []string
	}); ok {
		for _, device := range source.SourceDeviceTokens(tenant, rule.Source) {
			if device != "" && device == strings.TrimSpace(device) {
				return ""
			}
		}
	}
	return "no_resolved_device"
}

// The transparent TLS engine handles TCP/443. An SSH or UDP/443 rule must not
// change whether that traffic is decrypted. Empty service means Any; a named
// service requires positive resolution, never a fallback to HTTPS.
func inspectionServiceApplies(tenant, serviceID string, resolver AddressResolver) bool {
	if serviceID == "" {
		return true
	}
	transport, ok := resolver.(interface {
		ServiceIncludesTransport(tenant, serviceID, protocol string, port int) bool
	})
	return ok && transport.ServiceIncludesTransport(tenant, serviceID, "tcp", 443)
}

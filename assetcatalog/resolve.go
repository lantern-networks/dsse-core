package assetcatalog

import (
	"sort"
	"strings"
)

// ResolvePlatforms expands a set of subject ids (endpoint or group ids) to the distinct platforms of the
// endpoints they denote, plus the aliases of the macOS endpoints among them. An endpoint id denotes itself;
// a group id expands to its resolved members. Unknown ids and platform-less (network) endpoints contribute
// nothing. Both return slices are sorted and de-duplicated.
//
// The edge uses this to enforce the east-west inbound constraint — inbound is enforceable on Windows WFP
// only — before saving a rule: macOS-only receivers are a hard error, a mixed set yields a warning naming
// the uncovered macOS receivers. Keeping the platform lookup here (next to the catalog) lets the rule layer
// stay address-agnostic.
func (s *Store) ResolvePlatforms(tenant string, ids []string) (platforms []string, macAliases []string) {
	// Expand each id to concrete endpoint ids (the methods lock internally, so don't hold s.mu here).
	var endpointIDs []string
	for _, id := range ids {
		if _, ok := s.GetEndpoint(tenant, id); ok {
			endpointIDs = append(endpointIDs, id)
			continue
		}
		endpointIDs = append(endpointIDs, s.ResolveGroupMembers(tenant, id)...)
	}

	platformSet := map[string]bool{}
	macSet := map[string]bool{}
	for _, id := range endpointIDs {
		ep, ok := s.GetEndpoint(tenant, id)
		if !ok {
			continue
		}
		if ep.Platform != "" {
			platformSet[ep.Platform] = true
		}
		if ep.Platform == "macos" {
			macSet[ep.Alias] = true
		}
	}
	for p := range platformSet {
		platforms = append(platforms, p)
	}
	for a := range macSet {
		macAliases = append(macAliases, a)
	}
	sort.Strings(platforms)
	sort.Strings(macAliases)
	return platforms, macAliases
}

// EndpointAddresses expands a set of subject ids (endpoint or group ids) to the FQDN/IP addresses of the
// NETWORK endpoints they denote. Steered-device endpoints (no address) and unknown ids contribute nothing.
// Returns a sorted, de-duplicated list. Used to compile authored rules whose destinations are addressed by
// host (e.g. egress inspection-bypass → the engine's raw-forward host set).
func (s *Store) EndpointAddresses(tenant string, ids []string) []string {
	var endpointIDs []string
	for _, id := range ids {
		if _, ok := s.GetEndpoint(tenant, id); ok {
			endpointIDs = append(endpointIDs, id)
			continue
		}
		endpointIDs = append(endpointIDs, s.ResolveGroupMembers(tenant, id)...)
	}
	set := map[string]bool{}
	for _, id := range endpointIDs {
		ep, ok := s.GetEndpoint(tenant, id)
		if !ok {
			continue
		}
		if addr := ep.Address; addr != "" {
			set[addr] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// SourceDeviceTokens expands subject ids (endpoint or group ids) to the device identities of the steered
// endpoints they denote (groups expand to members). Network endpoints (no identity) contribute nothing.
// These match an east-west rule's SourceDevices against req.DeviceID, so source is restricted to specific
// devices. Sorted and de-duplicated.
func (s *Store) SourceDeviceTokens(tenant string, ids []string) []string {
	var endpointIDs []string
	for _, id := range ids {
		if _, ok := s.GetEndpoint(tenant, id); ok {
			endpointIDs = append(endpointIDs, id)
			continue
		}
		endpointIDs = append(endpointIDs, s.ResolveGroupMembers(tenant, id)...)
	}
	set := map[string]bool{}
	for _, id := range endpointIDs {
		ep, ok := s.GetEndpoint(tenant, id)
		if !ok {
			continue
		}
		if ep.Identity != "" {
			set[ep.Identity] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// DestinationTokens expands subject ids (endpoint or group ids) to the tokens an east-west rule's
// Destinations field is matched on: a network endpoint contributes its address (FQDN/IP); any other
// endpoint contributes its alias. Groups expand to their members. Sorted and de-duplicated.
func (s *Store) DestinationTokens(tenant string, ids []string) []string {
	var endpointIDs []string
	for _, id := range ids {
		if _, ok := s.GetEndpoint(tenant, id); ok {
			endpointIDs = append(endpointIDs, id)
			continue
		}
		endpointIDs = append(endpointIDs, s.ResolveGroupMembers(tenant, id)...)
	}
	set := map[string]bool{}
	for _, id := range endpointIDs {
		ep, ok := s.GetEndpoint(tenant, id)
		if !ok {
			continue
		}
		if ep.Address != "" {
			set[ep.Address] = true
		} else if ep.Alias != "" {
			set[ep.Alias] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ServiceProtocols returns the east-west protocol family/families a service denotes. A service is named by
// protocol (e.g. "smb"); v1 uses the service alias lowercased as the protocol token. Empty serviceID (or an
// unknown service) returns nil = "any east-west protocol".
func (s *Store) ServiceProtocols(tenant, serviceID string) []string {
	if strings.TrimSpace(serviceID) == "" {
		return nil
	}
	for _, svc := range s.ListServices(tenant) {
		if svc.ID == serviceID {
			return []string{strings.ToLower(strings.TrimSpace(svc.Alias))}
		}
	}
	return nil
}

// ServicePorts returns the destination ports a service denotes (e.g. SSH -> [22]). Empty serviceID or an
// unknown service returns nil (the caller applies the egress default). Used to scope a compiled egress policy
// to the rule's service port — without it, a rule authored for one service matches every port.
func (s *Store) ServicePorts(tenant, serviceID string) []int {
	if strings.TrimSpace(serviceID) == "" {
		return nil
	}
	for _, svc := range s.ListServices(tenant) {
		if svc.ID == serviceID {
			ports := make([]int, 0, len(svc.Ports))
			for _, p := range svc.Ports {
				if p.Port > 0 {
					ports = append(ports, p.Port)
				}
			}
			return ports
		}
	}
	return nil
}

// ServiceIncludesTransport resolves an exact protocol/port pair without losing
// the protocol as ServicePorts does. An absent or unresolved service never
// grants a transport-specific inspection exception.
func (s *Store) ServiceIncludesTransport(tenant, serviceID, protocol string, port int) bool {
	if s == nil || strings.TrimSpace(serviceID) == "" {
		return false
	}
	for _, p := range s.ServiceTransportPorts(tenant, serviceID)[protocol] {
		if p == port {
			return true
		}
	}
	return false
}

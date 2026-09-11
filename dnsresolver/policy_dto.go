package dnsresolver

import (
	"fmt"
	"sort"
	"strings"
)

// admin DNS-policy API: lets an operator read and hot-apply the Edge DNS ruleset (deny / sinkhole /
// stub-IP / ECH-strip) at runtime, instead of it being fixed at process start from env. This is the
// API-first management surface for DNS control. The conversion below is a pure function so the
// validation (IP parsing, name normalization, deny/sinkhole precedence collisions) is unit-testable
// without standing up the resolver or the HTTP server.

const adminDNSPolicySchemaVersion = "admin_dns_policy.v1"

// PolicyDTO is the on-the-wire shape of the DNS ruleset. deny is a sorted list (set semantics);
// sinkhole/stub map a name to a controlled IPv4. Names match the domain AND its subdomains (domain-tree),
// same as the resolver's runtime semantics.
type PolicyDTO struct {
	SchemaVersion string            `json:"schema_version"`
	Deny          []string          `json:"deny"`
	Sinkhole      map[string]string `json:"sinkhole"`
	StubIPv4      map[string]string `json:"stub_ipv4"`
	// ECHStrip is a TRI-STATE pointer so a PUT that omits ech_strip keeps the secure default (ON) instead of
	// silently disabling it. The startup default is ON (decrypt-all reachability — see newEdgeDNSResolverFromEnv);
	// a DNS-policy PUT fully replaces the policy, so a plain bool here would flip ech_strip OFF the first time an
	// operator saves any DNS rule without ticking the box. nil => default ON; explicit false => opt out.
	ECHStrip *bool `json:"ech_strip,omitempty"`
	// ForwardZones route internal DNS zones (e.g. an AD domain) to a connector for resolution — the Edge can't
	// reach the internal DNS directly. Part of the DNS policy so it persists + hot-applies with the rest.
	ForwardZones []ForwardZoneDTO `json:"forward_zones,omitempty"`
}

// ForwardZoneDTO is the on-the-wire shape of a TENANT-level conditional-forward rule: an internal zone and the
// internal DNS server that answers it. No connector field — the Edge picks the connector that reaches the
// internal DNS server via its route layer.
type ForwardZoneDTO struct {
	Zone     string `json:"zone"`
	Upstream string `json:"upstream"` // the internal DNS server, e.g. "10.10.0.10:53"
}

// PolicyToDTO renders a policy for GET (deny keys sorted for a stable response).
func PolicyToDTO(p Policy) PolicyDTO {
	deny := make([]string, 0, len(p.deny))
	for name := range p.deny {
		deny = append(deny, name)
	}
	sort.Strings(deny)
	sinkhole := map[string]string{}
	for k, v := range p.sinkhole {
		sinkhole[k] = v
	}
	stub := map[string]string{}
	for k, v := range p.stubIPv4 {
		stub[k] = v
	}
	echStrip := p.ECHStripValue() // GET returns the concrete current state (always set)
	var zones []ForwardZoneDTO
	for _, fz := range p.forwardZones {
		zones = append(zones, ForwardZoneDTO{Zone: fz.Zone, Upstream: fz.Upstream})
	}
	return PolicyDTO{
		SchemaVersion: adminDNSPolicySchemaVersion,
		Deny:          deny,
		Sinkhole:      sinkhole,
		StubIPv4:      stub,
		ECHStrip:      &echStrip,
		ForwardZones:  zones,
	}
}

// ECHStripValue exposes the toggle (kept as a method so the DTO conversion reads symmetrically).
func (p Policy) ECHStripValue() bool { return p.echStrip }

// PolicyFromDTO validates + normalizes an inbound ruleset into a Policy. It rejects empty names and
// non-IPv4 sinkhole/stub targets (a bad IP would silently fall through to upstream — fail-open — so we
// reject it loudly), and rejects a name that is BOTH denied and sinkholed (ambiguous intent; deny would
// win at runtime but the operator should say which they mean).
func PolicyFromDTO(dto PolicyDTO) (Policy, error) {
	echStrip := true // default ON; an explicit ech_strip:false opts out
	if dto.ECHStrip != nil {
		echStrip = *dto.ECHStrip
	}
	p := Policy{
		deny:     map[string]bool{},
		sinkhole: map[string]string{},
		stubIPv4: map[string]string{},
		echStrip: echStrip,
	}
	for _, raw := range dto.Deny {
		name := NormalizeQName(raw)
		if name == "" {
			return Policy{}, fmt.Errorf("deny entry must not be empty")
		}
		p.deny[name] = true
	}
	for raw, ip := range dto.Sinkhole {
		name := NormalizeQName(raw)
		if name == "" {
			return Policy{}, fmt.Errorf("sinkhole entry must not be empty")
		}
		if parseIPv4(ip) == nil {
			return Policy{}, fmt.Errorf("sinkhole %q: %q is not a valid IPv4 address", name, ip)
		}
		if p.deny[name] {
			return Policy{}, fmt.Errorf("%q is both denied and sinkholed; pick one", name)
		}
		p.sinkhole[name] = ip
	}
	for raw, ip := range dto.StubIPv4 {
		name := NormalizeQName(raw)
		if name == "" {
			return Policy{}, fmt.Errorf("stub_ipv4 entry must not be empty")
		}
		if parseIPv4(ip) == nil {
			return Policy{}, fmt.Errorf("stub_ipv4 %q: %q is not a valid IPv4 address", name, ip)
		}
		p.stubIPv4[name] = ip
	}
	for _, fz := range dto.ForwardZones {
		zone := NormalizeQName(fz.Zone)
		if zone == "" {
			return Policy{}, fmt.Errorf("forward_zones entry must have a zone")
		}
		up := strings.TrimSpace(fz.Upstream)
		if up == "" {
			return Policy{}, fmt.Errorf("forward_zones %q: upstream (the internal DNS server, e.g. 10.10.0.10:53) is required", zone)
		}
		p.forwardZones = append(p.forwardZones, ForwardZone{Zone: zone, Upstream: up})
	}
	return p, nil
}

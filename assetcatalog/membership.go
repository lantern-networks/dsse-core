package assetcatalog

import (
	"net"
	"strings"
)

// endpointMatchesRule reports whether an endpoint satisfies a group's dynamic membership rule. A nil/zero
// field is "any"; every set field must match (AND).
func endpointMatchesRule(e Endpoint, r MembershipRule) bool {
	if r.Platform != nil && !strings.EqualFold(strings.TrimSpace(e.Platform), strings.TrimSpace(*r.Platform)) {
		return false
	}
	if r.Steered != nil && e.Steered != *r.Steered {
		return false
	}
	if r.Tag != "" && !hasTag(e.Tags, r.Tag) {
		return false
	}
	if r.Subnet != "" && !addressInSubnet(e.Address, r.Subnet) {
		return false
	}
	return true
}

func hasTag(tags []string, tag string) bool {
	tag = strings.TrimSpace(tag)
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), tag) {
			return true
		}
	}
	return false
}

// addressInSubnet reports whether the endpoint's address (an IP, optionally with a /prefix) falls within
// the given CIDR. A non-IP address (e.g. an FQDN) never matches a subnet rule.
func addressInSubnet(address, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(address)
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ipnet.Contains(ip)
}

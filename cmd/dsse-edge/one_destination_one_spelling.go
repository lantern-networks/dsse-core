package main

import (
	"net/netip"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// ipv4HostWithoutMapping returns an IPv4-mapped IPv6 address ("::ffff:10.0.0.1") as the IPv4 address it is.
// Anything else — a name, an IPv4 address, a real IPv6 address — is returned unchanged.
func ipv4HostWithoutMapping(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4In6() {
		return host
	}
	return addr.Unmap().String()
}

// observedDestinationFor is the destination an observed flow is recorded under: the name its address was
// resolved from when the decision request carries one, and what the device sent otherwise.
func observedDestinationFor(host string, req model.DecisionRequest) string {
	if name := strings.TrimSpace(req.FQDN); name != "" {
		if _, err := netip.ParseAddr(host); err == nil {
			return strings.TrimSuffix(name, ".")
		}
	}
	return host
}

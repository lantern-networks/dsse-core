package installprofile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// ExactHTTPSPassthroughEndpoint is an operator-authored, signed exception for a
// dedicated HTTPS IdP. It is not a suffix/domain rule: the macOS agent checks the
// original hostname, the resolved numeric destination, and TCP/443 for each flow.
type ExactHTTPSPassthroughEndpoint struct {
	Hostname  string   `json:"hostname"`
	Addresses []string `json:"addresses"`
}

// ParseExactHTTPSPassthroughEndpoints is used at CP startup. A malformed option
// must stop profile issuance, not silently become an empty list or a broad bypass.
// Empty input means there is no exception; an explicit JSON [] has the same effect.
func ParseExactHTTPSPassthroughEndpoints(raw string) ([]ExactHTTPSPassthroughEndpoint, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var endpoints []ExactHTTPSPassthroughEndpoint
	if err := dec.Decode(&endpoints); err != nil {
		return nil, fmt.Errorf("exact HTTPS passthrough endpoints: %w", err)
	}
	if endpoints == nil {
		return nil, fmt.Errorf("exact HTTPS passthrough endpoints: expected a JSON array")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("exact HTTPS passthrough endpoints: trailing JSON or invalid input")
	}
	return ValidateExactHTTPSPassthroughEndpoints(endpoints)
}

// ValidateExactHTTPSPassthroughEndpoints accepts only exact lowercase DNS names
// and canonical numeric addresses. It deliberately performs no DNS lookup: the
// endpoint verifies the host's current DNS answer against these signed addresses
// at startup and on refresh, and refuses the exception if they have drifted.
func ValidateExactHTTPSPassthroughEndpoints(input []ExactHTTPSPassthroughEndpoint) ([]ExactHTTPSPassthroughEndpoint, error) {
	out := make([]ExactHTTPSPassthroughEndpoint, 0, len(input))
	seenHosts := map[string]bool{}
	for i, endpoint := range input {
		host := endpoint.Hostname
		if !validExactDNSHostname(host) || seenHosts[host] {
			return nil, fmt.Errorf("exact HTTPS passthrough endpoint %d: invalid or duplicate hostname", i)
		}
		if len(endpoint.Addresses) == 0 {
			return nil, fmt.Errorf("exact HTTPS passthrough endpoint %d: no numeric addresses", i)
		}
		seenHosts[host] = true
		seenAddresses := map[netip.Addr]bool{}
		addresses := make([]string, 0, len(endpoint.Addresses))
		for _, raw := range endpoint.Addresses {
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" || address.String() != raw || seenAddresses[address] {
				return nil, fmt.Errorf("exact HTTPS passthrough endpoint %d: invalid, noncanonical, or duplicate numeric address", i)
			}
			seenAddresses[address] = true
			addresses = append(addresses, raw)
		}
		out = append(out, ExactHTTPSPassthroughEndpoint{Hostname: host, Addresses: addresses})
	}
	return out, nil
}

// ValidateExactHTTPSPassthroughAgainstBroadDomains refuses a signed narrow
// exception that a separately authored domain rule would silently widen to
// every port and address. The macOS provider evaluates both kinds of rule.
func ValidateExactHTTPSPassthroughAgainstBroadDomains(endpoints []ExactHTTPSPassthroughEndpoint, domains []string) error {
	for _, endpoint := range endpoints {
		for _, raw := range domains {
			domain := strings.ToLower(strings.TrimSpace(raw))
			domain = strings.TrimPrefix(domain, "*.")
			domain = strings.TrimPrefix(domain, ".")
			domain = strings.TrimSuffix(domain, ".")
			if domain != "" && (endpoint.Hostname == domain || strings.HasSuffix(endpoint.Hostname, "."+domain)) {
				return fmt.Errorf("exact HTTPS passthrough hostname %q overlaps a domain-wide passthrough rule", endpoint.Hostname)
			}
		}
	}
	return nil
}

func validExactDNSHostname(host string) bool {
	if host == "" || host != strings.ToLower(host) || len(host) > 253 || strings.ContainsAny(host, "*:/@ \t\r\n") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

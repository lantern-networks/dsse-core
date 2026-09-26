package policycandidate

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeCertPinHostname accepts one exact DNS name. This site-registration
// surface must not turn patterns, prefixes or URL syntax into wider bypasses.
func NormalizeCertPinHostname(raw string) (string, error) {
	invalid := func() (string, error) {
		return "", fmt.Errorf("host must be one exact DNS hostname (no IP address, wildcard, URL, port or prefix)")
	}
	host := strings.TrimSpace(raw)
	if host == "" || strings.ContainsAny(host, "*\\/:@?#%[] \t\r\n") {
		return invalid()
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return invalid()
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(ascii) == 0 || len(ascii) > 253 || net.ParseIP(ascii) != nil {
		return invalid()
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid()
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return invalid()
			}
		}
	}
	// Do not treat abbreviated, decimal, octal or hexadecimal IPv4 notation
	// (which browsers can interpret as addresses) as a named destination.
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" {
		return invalid()
	}
	if strings.HasPrefix(last, "0x") && len(last) > 2 && strings.Trim(last[2:], "0123456789abcdef") == "" {
		return invalid()
	}
	return ascii, nil
}

// CertPinBypassTarget derives scope from the destination, never from advisory
// confidence/action labels. An exact Host name stays authoritative; an IP/empty
// Host can use an exact SNI name. Supported IP-only targets require an explicit
// override; an address the current inspection matcher cannot apply is refused.
func CertPinBypassTarget(c Candidate) (target string, highRisk bool, err error) {
	host := normalizeHostValue(c.Host)
	sni := normalizeHostValue(c.SNI)
	if named, e := NormalizeCertPinHostname(host); e == nil {
		return named, false, nil
	}
	ip := net.ParseIP(host)
	if host != "" && ip == nil {
		return "", false, fmt.Errorf("cert-pin destination must be an exact hostname or IP address")
	}
	if sni != "" {
		if named, e := NormalizeCertPinHostname(sni); e == nil {
			return named, false, nil
		}
		if net.ParseIP(sni) == nil {
			return "", false, fmt.Errorf("cert-pin SNI is not an exact hostname")
		}
	}
	if ip != nil {
		if strings.Contains(host, ":") {
			return "", false, fmt.Errorf("IPv6-only cert-pin bypass is unsupported; identify an exact hostname")
		}
		return host, true, nil
	}
	if ip = net.ParseIP(sni); ip != nil {
		if strings.Contains(sni, ":") {
			return "", false, fmt.Errorf("IPv6-only cert-pin bypass is unsupported; identify an exact hostname")
		}
		return sni, true, nil
	}
	return "", false, fmt.Errorf("cert-pin candidate has no exact destination")
}

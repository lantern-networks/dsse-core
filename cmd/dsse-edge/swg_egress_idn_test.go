package main

import (
	"errors"
	"testing"
)

// IDN/Japanese FQDN handling itself is correct (the edge mints the per-SNI leaf, parses the Punycode SNI, and
// matches policy/bypass on it). The real failure for hosts like xn--t8jx73hngb.com (お名前.com) is that the
// ORIGIN sends a non-standard TLS `unrecognized_name` warning for its OWN SNI; strict TLS stacks (Go here, and
// macOS LibreSSL) reject it, lenient ones (Chrome/BoringSSL) tolerate it. Such an origin cannot be decrypted by
// the edge (Go), so the egress surfaces it as a cert-pinning bypass CANDIDATE (Pinned Sites) for an admin to
// adopt — never auto-bypassed. This pins the detector used for that.
func TestSWGEgressIsUnrecognizedName(t *testing.T) {
	if !swgEgressIsUnrecognizedName(errors.New(`Get "https://xn--t8jx73hngb.com/": remote error: tls: unrecognized name`)) {
		t.Fatal("should detect the origin's unrecognized_name alert")
	}
	if swgEgressIsUnrecognizedName(errors.New("dial tcp: connection refused")) {
		t.Fatal("must not match unrelated egress errors")
	}
	if swgEgressIsUnrecognizedName(nil) {
		t.Fatal("nil is not unrecognized_name")
	}
}

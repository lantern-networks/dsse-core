//go:build windows

package main

import "testing"

// The enrolment fold, asserted on the one path that was still dialling a second port. Every agent-facing route
// — enrolment, the trust bundle, the policy key, the runtime copy, the region list — is answered on the
// transport port, and a second agent-facing port must not exist. This
// test is the thing that would have caught 2026-08-26, when the deployment served the bundle on 443, the agent
// dialled 8443, and the device reported wanted=0 while its traffic was being decrypted.
func TestTheBundleIsFetchedOnTheTransportPort(t *testing.T) {
	for _, c := range []struct {
		name      string
		explicit  string
		transport string
		want      string
	}{
		{"the transport's port is kept", "", "edge.example.ts.net:443", "https://edge.example.ts.net:443"},
		{"a non-standard transport port is kept too", "", "edge.example.ts.net:10443", "https://edge.example.ts.net:10443"},
		{"no port on the transport falls back to 443", "", "edge.example.ts.net", "https://edge.example.ts.net:443"},
		{"an explicit URL still wins", "https://elsewhere:9999/", "edge.example.ts.net:443", "https://elsewhere:9999"},
		{"an IPv6 literal keeps its port", "", "[2001:db8::1]:443", "https://[2001:db8::1]:443"},
		{"nothing to derive from yields nothing", "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := trustBundleBaseURL(c.explicit, c.transport); got != c.want {
				t.Fatalf("trustBundleBaseURL(%q, %q) = %q, want %q", c.explicit, c.transport, got, c.want)
			}
		})
	}
}

// A second agent-facing port must not reappear as a constant, which is how the last one survived.
func TestNoSecondAgentFacingPort(t *testing.T) {
	if trustBundleDefaultPort != "443" {
		t.Fatalf("trustBundleDefaultPort = %q — the agent plane is one port (443); a fallback to anything else "+
			"reintroduces the split that made a decrypting deployment look like one that does not inspect",
			trustBundleDefaultPort)
	}
}

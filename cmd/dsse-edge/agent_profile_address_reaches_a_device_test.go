package main

import (
	"net/http"
	"strings"
	"testing"
)

// ★★★ THE SCREEN'S DEFAULT WOULD HAVE TAKEN A REAL MACHINE OFF THE NETWORK (win-dev-1, letter 101,
// 2026-08-26). A deployment brought up on localhost generates "agents.localhost"; on a laptop that is
// 127.0.0.1. With the default posture — fail-closed, which is right — a device applying that profile dials
// itself, reaches no Edge, and stops carrying traffic entirely. It was caught by a person reading the profile
// before applying it, which is not a control.
func TestAnAddressADeviceCannotReachIsRecognised(t *testing.T) {
	cannot := []string{
		"agents.localhost", "https://agents.localhost", "region-a=https://agents.localhost:10443",
		"localhost:443", "https://127.0.0.1:443", "https://[::1]:443", "region-b=https://0.0.0.0:443",
	}
	for _, e := range cannot {
		if addressReachesADevice(e) {
			t.Fatalf("%q was treated as an address a device can reach", e)
		}
	}
	// The guard: real addresses must still pass, or the check refuses every deployment.
	can := []string{
		"https://agents.example.com", "region-a=https://agents.example.com:443",
		"https://203.0.113.120:443", "edge.corp.internal:8443", "https://100.72.135.18",
	}
	for _, e := range can {
		if !addressReachesADevice(e) {
			t.Fatalf("%q was treated as unreachable", e)
		}
	}
}

// A deployment whose every address is loopback refuses to issue, and says what a device would do with it.
func TestAProfileIsRefusedWhenNoAddressReachesADevice(t *testing.T) {
	mux := agentProfileMux(t, true, []regionEndpoint{
		{Region: "region-a", Endpoint: "https://agents.localhost"},
		{Region: "region-b", Endpoint: "https://agents.localhost:10443"},
	})
	code, body := issueProfile(t, mux, "tenant_acme", `{}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a profile no device could use was issued: %d %+v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "dial itself") {
		t.Fatalf("the refusal does not say what a device would do: %q", msg)
	}
}

// ★ AND WHEN SOME ARE USABLE, THE UNUSABLE ONES ARE LEFT OUT rather than carried as places a device will try
// and fail — a device works through them in order, and a loopback entry costs it a timeout every time.
func TestUnreachableAddressesAreLeftOutOfAnIssuedProfile(t *testing.T) {
	mux := agentProfileMux(t, true, []regionEndpoint{
		{Region: "region-a", Endpoint: "https://agents.localhost"},
		{Region: "region-b", Endpoint: "https://agents.example.com"},
	})
	code, body := issueProfile(t, mux, "tenant_acme", `{}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %+v", code, body)
	}
	got := decodeProfilePayload(t, body)
	if len(got.TransportEndpoints) != 1 || !strings.Contains(got.TransportEndpoints[0], "agents.example.com") {
		t.Fatalf("the loopback address was carried into the profile: %+v", got.TransportEndpoints)
	}
	if !strings.Contains(got.TransportURL, "agents.example.com") {
		t.Fatalf("the single-address field points at a loopback address: %q", got.TransportURL)
	}
}

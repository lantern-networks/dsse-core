package main

import (
	"net/http"
	"testing"
)

func TestProfileRejectsEquivalentLoopbackSpellings(t *testing.T) {
	for _, endpoint := range []string{"https://localhost.:443", "https://agents.localhost.:443", "https://[::1%25lo0]:443", "https://[::%25lo0]:443", "https://[::ffff:127.0.0.1]:443", "https://[::ffff:0.0.0.0]:443"} {
		t.Run(endpoint, func(t *testing.T) {
			if addressReachesADevice(endpoint) {
				t.Error("loopback or unspecified endpoint accepted")
			}
			mux := agentProfileMux(t, true, []regionEndpoint{{Region: "region-a", Endpoint: endpoint}})
			code, _ := issueProfile(t, mux, "tenant_acme", `{}`)
			if code != http.StatusServiceUnavailable {
				t.Errorf("unreachable profile issue returned %d", code)
			}
		})
	}
	for _, endpoint := range []string{"https://agents.example.:443", "https://[fe80::1%25en0]:443"} {
		if !addressReachesADevice(endpoint) {
			t.Errorf("non-loopback endpoint rejected: %s", endpoint)
		}
	}
}

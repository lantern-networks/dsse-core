package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestAgentProfileCannotMintEndpointsOutsideTenantCatalog(t *testing.T) {
	for _, endpoint := range []string{"region-b=https://other-region.example.test", "region-a=https://attacker.example.test", "https://agents.example.test"} {
		t.Run(endpoint, func(t *testing.T) {
			mux := agentProfileMux(t, true, []regionEndpoint{{Region: "region-a", Endpoint: "https://agents.example.test"}})
			code, body := issueProfile(t, mux, "tenant-a", `{"transport_endpoints":["`+endpoint+`"]}`)
			if code != http.StatusBadRequest {
				t.Fatalf("unpublished endpoint was signed: status=%d", code)
			}
			_ = body
		})
	}
}

func TestAgentProfileCanReorderAndSelectPublishedEndpoints(t *testing.T) {
	mux := agentProfileMux(t, true, []regionEndpoint{{Region: "region-a", Endpoint: "https://a.example.test"}, {Region: "region-b", Endpoint: "https://b.example.test"}, {Region: "region-c", Endpoint: "https://c.example.test"}})
	code, body := issueProfile(t, mux, "tenant-a", `{"transport_endpoints":["region-b=https://b.example.test","region-a=https://a.example.test"]}`)
	if code != http.StatusOK {
		t.Fatalf("allowed selection: %d %v", code, body)
	}
	if got := strings.Join(decodeProfilePayload(t, body).TransportEndpoints, ","); got != "region-b=https://b.example.test,region-a=https://a.example.test" {
		t.Fatalf("selection changed: %s", got)
	}
}

func TestAgentProfileEmptyAuthoritativeCatalogDoesNotUseFallback(t *testing.T) {
	for _, result := range [][]regionEndpoint{nil, {}} {
		if got := agentProfileEndpoints("https://outside.example.test", "tenant-a", func(string) []regionEndpoint { return result }); len(got) != 0 {
			t.Fatalf("empty tenant catalog became unrestricted fallback: %v", got)
		}
	}
	if got := agentProfileEndpoints("https://single.example.test", "tenant-a", nil); len(got) != 1 || got[0] != "https://single.example.test" {
		t.Fatalf("unconfigured single-region fallback changed: %v", got)
	}
}

package main

import (
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/installprofile"
)

func TestAuthPortalProfileUsesExplicitSharedOrigins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config serverConfig
		want   []string
	}{
		{"one-region", serverConfig{ClientlessBaseURL: "https://portal.example"}, []string{"https://portal.example:443"}},
		{"three-regions", serverConfig{ClientlessBaseURL: "https://portal-a.example", StepUpPortalOrigins: "https://portal-a.example:443,https://portal-b.example;https://portal-c.example:8443", AdminConsoleOrigin: "https://console.example"}, []string{"https://portal-a.example:443", "https://portal-b.example:443", "https://portal-c.example:8443"}},
		{"invalid-not-trusted", serverConfig{ClientlessBaseURL: "http://portal.example", StepUpPortalOrigins: "https://*.example,https://portal.example/path"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tenant := range []string{"first", "second"} {
				got := deploymentFactsFor(tc.config, tenant).StepUpPortalOrigins
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("unexpected origins: %v", got)
				}
			}
		})
	}
}

func TestIssuedProfileCarriesOnlyExplicitExactHTTPSIdPExceptions(t *testing.T) {
	endpoint := installprofile.ExactHTTPSPassthroughEndpoint{
		Hostname: "idp.example.test", Addresses: []string{"203.0.113.10"},
	}
	configured := deploymentFactsFor(serverConfig{
		ExactHTTPSPassthroughEndpoints: []installprofile.ExactHTTPSPassthroughEndpoint{endpoint},
	}, "tenant-a")
	if !reflect.DeepEqual(configured.ExactHTTPSPassthroughEndpoints, []installprofile.ExactHTTPSPassthroughEndpoint{endpoint}) {
		t.Fatalf("explicit dedicated IdP exception was lost: %+v", configured.ExactHTTPSPassthroughEndpoints)
	}
	if len(deploymentFactsFor(serverConfig{}, "tenant-a").ExactHTTPSPassthroughEndpoints) != 0 {
		t.Fatal("an unconfigured deployment must issue no exact HTTPS exception")
	}
}

package main

import (
	"reflect"
	"testing"
)

func TestSignedProfileKeepsEveryDeclaredAuthenticationPortalReachable(t *testing.T) {
	config := serverConfig{AdminConsoleOrigin: "https://console.site.example", AdminConsoleOrigins: "https://console.region-b.site.example", ClientlessBaseURL: "https://portal-edge-a-1.site.example", StepUpPortalOrigins: "https://portal-edge-a-1.site.example,https://portal-edge-a-2.site.example;https://portal-edge-b-1.site.example"}
	got := deploymentFactsFor(config, "tenant-a").PassthroughDomains
	want := []string{"console.site.example", "console.region-b.site.example", "portal-edge-a-1.site.example", "portal-edge-a-2.site.example", "portal-edge-b-1.site.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("signed profile excludes %v, want exact declared control hosts %v", got, want)
	}
	if !reflect.DeepEqual(got, deploymentFactsFor(config, "tenant-b").PassthroughDomains) {
		t.Fatal("tenant-independent portal names changed between tenants")
	}
	if config.AdminConsoleOrigins != "https://console.region-b.site.example" {
		t.Fatal("portal exceptions must not expand Console CORS")
	}
}

func TestPortalProfileRejectsBroadOrRequestDerivedExclusions(t *testing.T) {
	for _, bad := range []string{"https://*.example", "http://portal.example", "https://u:p@portal.example", "https://portal.example/?next=other", "https://portal.example/unrelated", "https://portal.example/#fragment"} {
		if got := deploymentFactsFor(serverConfig{StepUpPortalOrigins: bad}, "tenant-a").PassthroughDomains; len(got) != 0 {
			t.Errorf("invalid origin %q created device-wide passthrough %v", bad, got)
		}
	}
}

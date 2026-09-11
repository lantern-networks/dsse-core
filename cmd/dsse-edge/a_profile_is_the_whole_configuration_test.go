package main

import (
	"strings"
	"testing"
)

// ★★★ A PROFILE AND A ONE-TIME TOKEN MUST BE THE WHOLE OF WHAT A CUSTOMER RECEIVES (2026-08-29, the
// operator's call, made while watching a real Mac refuse to start).
//
// Until this, the device also needed an agent_config.json holding the deployment's anchor, the organization's
// device-CA pin, its interception root, the update pins and a steering-rules file — and nothing in the product
// produced that file. The lab had a script that wrote it by hand, which no customer ever receives, and the
// product's stated answer was "MDM drops it", which makes MDM a requirement rather than a convenience. It was
// invisible because every walk of this lane had used the lab's script.
//
// The test is about ABSENCE being visible: a deployment that has not been given one of these facts must say so
// by leaving it empty, not by shipping a blank that reads as configured on the device.
func TestTheProfileCarriesWhatTheDeviceCannotLearnYet(t *testing.T) {
	const anchor = "-----BEGIN CERTIFICATE-----\nanchor\n-----END CERTIFICATE-----\n"
	config := serverConfig{
		ConnectorEnrollmentEdgeCAPEM: anchor,
		AgentUpdatePins:              []string{"f95090bb"},
		AgentUpdatePublisher:         "M4U8GSBL6C",
	}

	facts := deploymentFactsFor(config, "tenant_momiji")

	if strings.TrimSpace(facts.AnchorPEM) == "" {
		t.Error("the profile carries no anchor — the device has nothing to verify an Edge against, and the " +
			"only other source was a file the product never produced")
	}
	if len(facts.UpdateSigningKeys) == 0 || facts.UpdatePublisherTeamID == "" {
		t.Error("the profile carries no update pin or publisher — an endpoint installer refuses without both, " +
			"and a device that got this far could never be updated")
	}

	// ★ ABSENCE IS AN ANSWER. An organization with no authority of its own is enrolled under the deployment's,
	// and a blank pin that reads as configured would make the device refuse the identity it is handed — at
	// enrolment, on the device, where the reason is not visible from the control plane.
	if facts.DeviceCAPinSHA256 != "" {
		t.Errorf("a deployment holding no per-organization device authority stated a pin anyway: %q",
			facts.DeviceCAPinSHA256)
	}
	if facts.InterceptionRootPEM != "" {
		t.Errorf("a deployment holding no per-organization interception authority stated a root anyway")
	}
	// This deployment authored no exclusions, and this product ships none: the honest answer is nothing, not
	// an invented list.
	if len(facts.SteerExclusions) != 0 {
		t.Errorf("exclusions were invented: %v", facts.SteerExclusions)
	}
}

// ★ AND THE ROUTE THAT ISSUES PROFILES ACTUALLY CALLS IT. The helper is where the facts are gathered; the call
// site is where they reach a device. A helper with no caller is the failure this repository has hit in Go and
// in Swift, and it passes every test of the helper.
func TestTheProfileRouteGathersTheDeploymentsFacts(t *testing.T) {
	// ★ THE PROPERTY, NOT THE SPELLING (2026-08-31). This pinned the exact expression
	// "Deployment: deploymentFactsFor(config, tenant)" and broke the day the route had to hold the result in
	// a variable first — so that it could REFUSE to issue a profile whose organization authorities this node
	// cannot see. The route was more correct and the test failed. Assert the two things that matter: the
	// facts are gathered here, and what is gathered is what the profile carries.
	source := readSourceFile(t, "admin_agent_profile_routes.go")
	gathered := strings.Contains(source, "deploymentFactsFor(config, tenant)")
	carried := strings.Contains(source, "Deployment: deploymentFactsFor(config, tenant)") ||
		strings.Contains(source, "facts := deploymentFactsFor(config, tenant)") && strings.Contains(source, "Deployment: facts")
	if !gathered || !carried {
		t.Error("the profile-issuing route does not fill the deployment's facts, so every profile it signs " +
			"leaves the device needing a file the product does not produce")
	}
}

// ★★★ AND THE DEPLOYMENT NAMES ITS OWN CONSOLE, SO A STEERED DEVICE CAN STILL REACH IT (2026-08-30).
//
// Every corporate device on this product is steered — that is the product. A steered device's traffic goes to
// an Edge, the Edge dials the destination, and the egress guard refuses internal addresses. On a sovereign
// deployment the Console is on the customer's network, so an administrator's own machine loses the Console the
// moment steering comes up — and both remedies are authored IN the Console. These assert the one thing that
// breaks the loop: the profile names the deployment's Console as a destination the device does not steer.
func TestTheProfileNamesThisDeploymentsOwnConsole(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		want         []string
	}{
		{"an origin with a scheme", "https://console.example.test", []string{"console.example.test"}},
		{"an origin with a port", "https://console.example.test:8443", []string{"console.example.test"}},
		{"a bare host", "console.example.test", []string{"console.example.test"}},
		{"upper case is one address, not two", "https://Console.Example.Test", []string{"console.example.test"}},
		// Nothing is guessed. A deployment that never told this Edge where its Console is says nothing, and an
		// empty list keeps meaning "the deployment authored nothing" rather than "we made something up".
		{"no console configured", "", nil},
		{"blank", "   ", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deploymentFactsFor(serverConfig{AdminConsoleOrigin: tc.origin}, "tenant_any").PassthroughDomains
			if len(got) != len(tc.want) {
				t.Fatalf("origin %q -> %v, want %v", tc.origin, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("origin %q -> %v, want %v", tc.origin, got, tc.want)
				}
			}
		})
	}
}

// ★ AND THE DEVICE HAS SOMEWHERE TO PUT IT. The list only means anything if the agent reads it under a key it
// knows and consults it on the flow path — the failure this tree has met in both languages is a value that is
// carried, stored, and never asked. handleNewFlow's own log line is the evidence that it is asked.
func TestTheAgentActuallyConsultsThePassthroughList(t *testing.T) {
	source := readSourceFile(t,
		"../../clients/macos-network-extension/Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
	if !strings.Contains(source, "transparentPassthroughDomainDecision(") ||
		!strings.Contains(source, "pass_through=transparent_passthrough_domain") {
		t.Error("the macOS agent does not decide flows against the passthrough list, so a Console named in " +
			"the profile would be steered anyway — into the Edge that cannot reach it")
	}
}

// ★★★ AND EVERY REGION'S CONSOLE, BECAUSE FAILOVER IS WHEN THIS MATTERS (2026-08-30, the operator: when a
// region fails over, the Console of the region that took over has to open too). A device told only about the
// region that just died loses the Console at the moment an administrator needs it.
func TestTheProfileNamesEveryRegionsConsole(t *testing.T) {
	facts := deploymentFactsFor(serverConfig{
		AdminConsoleOrigin: "https://console.nagoya.example.test",
		// Written the way an operator would: a separator they chose, a duplicate, and one entry that repeats
		// the single origin. None of those should produce a second entry or drop a real one.
		AdminConsoleOrigins: "https://console.nagoya.example.test; https://console.fukuoka.example.test,https://console.fukuoka.example.test:8443",
	}, "tenant_any")
	want := []string{"console.nagoya.example.test", "console.fukuoka.example.test"}
	if len(facts.PassthroughDomains) != len(want) {
		t.Fatalf("profile names %v, want %v", facts.PassthroughDomains, want)
	}
	for i := range want {
		if facts.PassthroughDomains[i] != want[i] {
			t.Fatalf("profile names %v, want %v", facts.PassthroughDomains, want)
		}
	}
	// The surviving region has to be in there, or the failover the operator asked about ends with an
	// administrator who cannot open the Console of the region that took over.
	found := false
	for _, d := range facts.PassthroughDomains {
		if d == "console.fukuoka.example.test" {
			found = true
		}
	}
	if !found {
		t.Error("the region that would take over is not named, so a failover takes the Console with it")
	}
}

// ★ AND THE DEVICE RE-RESOLVES THEM. Naming every region is half of it: on a deployment that fails over under
// ONE name, the name does not change and the address does — and this provider matches an address, because that
// is what a browser hands it. A list resolved once at start is a snapshot of the region that just died.
func TestTheAgentRefreshesWhatThoseNamesResolveTo(t *testing.T) {
	source := readSourceFile(t,
		"../../clients/macos-network-extension/Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift")
	if !strings.Contains(source, "startTransparentPassthroughRefresh(") ||
		!strings.Contains(source, "transparent_passthrough refreshed") {
		t.Error("the macOS agent resolves the never-steer names once and never again, so a region failover " +
			"leaves it passing through the addresses of the region that failed")
	}
}

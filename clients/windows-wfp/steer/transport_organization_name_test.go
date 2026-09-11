package main

import (
	"sync/atomic"
	"testing"
)

// The four sources a device can get its organization's name from, and the order they resolve in. Written as one
// table because the ORDER is the feature — each individual lookup is trivial and none of them is what could go
// wrong.
func nameConfig(configured string) transportConfig {
	return transportConfig{
		enabled:              true,
		host:                 "edge.example:18543",
		serverName:           "edge.example",
		configuredServerName: configured,
		announcedServerName:  &atomic.Pointer[string]{},
		fleetServerName:      &atomic.Pointer[string]{},
		active:               &atomic.Pointer[activeEndpoint]{},
	}
}

func TestTheNameADeviceSendsResolvesInOneOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		announced  string
		fleet      string
		region     string
		want       string
	}{
		{
			name: "a device that has been told nothing sends the address it was given",
			want: "edge.example",
		},
		{
			// The case the install-time field exists for: a device that has never enrolled, so no bundle has
			// ever reached it, and enrolment is the thing that needs a name to select its route.
			name: "before any bundle, the install profile's name is what it has", configured: "lab.dsse.invalid",
			want: "lab.dsse.invalid",
		},
		{
			// An announcement has to be able to move a fleet without reinstalling it, so it outranks the install.
			name:       "an announcement outranks what the install stated",
			configured: "old.dsse.invalid", announced: "lab.dsse.invalid", want: "lab.dsse.invalid",
		},
		{
			name: "the signed region list can state it when no bundle has", configured: "old.dsse.invalid",
			fleet: "lab.dsse.invalid", want: "lab.dsse.invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := nameConfig(tc.configured)
			c.setAnnouncedNames(tc.announced, "")
			c.setFleetServerName(tc.fleet)
			if tc.region != "" {
				c.active.Store(&activeEndpoint{serverName: tc.region})
			}
			if got := c.activeServerName(); got != tc.want {
				t.Fatalf("activeServerName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ★ THE ONE THAT MUST NOT REGRESS. Before the signed region list carried names, a failed-over device had to
// present the REGION's own host name: a region with no certificate for this organization serves the shared one,
// and verifying that against the organization's name refuses it — locking the device out of the region it just
// failed over to, at the one moment it cannot afford that. A fleet that has not adopted the names states none,
// and that silence has to keep meaning exactly what it meant.
func TestWithoutAFleetNameFailoverStillSendsTheRegionsOwnName(t *testing.T) {
	c := nameConfig("lab.dsse.invalid")
	c.setAnnouncedNames("lab.dsse.invalid", "")
	c.setFleetServerName("") // this list states nothing — the pre-2026-08-22 world
	c.active.Store(&activeEndpoint{serverName: "region-b.example"})

	if got := c.activeServerName(); got != "region-b.example" {
		t.Fatalf("a failed-over device on a fleet that promises nothing sent %q; it must send the region's own "+
			"name %q, or it refuses the certificate that region actually serves", got, "region-b.example")
	}
}

// And the promise, once stated, is what lets the device stop falling silent about its organization — which is
// the whole reason a failed-over device could not select an organization-scoped route.
func TestAFleetNamePromiseSurvivesFailover(t *testing.T) {
	c := nameConfig("")
	c.setAnnouncedNames("lab.dsse.invalid", "")
	c.setFleetServerName("lab.dsse.invalid")
	c.active.Store(&activeEndpoint{serverName: "region-b.example"})

	if got := c.activeServerName(); got != "lab.dsse.invalid" {
		t.Fatalf("the signed list promised %q at every region and the device sent %q instead", "lab.dsse.invalid", got)
	}
}

// A deployment that STOPS stating a name means "the shared certificate". A device that kept the last one would
// go on asking for a certificate nobody serves — the same failure the announced-name clear already prevents.
func TestClearingTheFleetNameRestoresTheOlderRule(t *testing.T) {
	c := nameConfig("")
	c.setFleetServerName("lab.dsse.invalid")
	c.active.Store(&activeEndpoint{serverName: "region-b.example"})
	if got := c.activeServerName(); got != "lab.dsse.invalid" {
		t.Fatalf("setup: got %q", got)
	}

	c.setFleetServerName("")
	if got := c.activeServerName(); got != "region-b.example" {
		t.Fatalf("after the list stopped stating a name the device sent %q; it must fall back to the region's "+
			"own name %q", got, "region-b.example")
	}
}

// The report the fold is gated on has to describe what the device WOULD send, including the install-time name —
// otherwise a fleet configured entirely at install time reads as "sends nothing" and the gate never opens.
func TestTheReportedNameIncludesTheInstallStatedOne(t *testing.T) {
	c := nameConfig("lab.dsse.invalid")
	sent, recovery := c.activeServerName(), c.currentRecoverySNI()
	if sent != "lab.dsse.invalid" {
		t.Fatalf("transport_server_name_sent would be %q", sent)
	}
	// ★ And the pairing itself: this side cannot report an empty transport name beside a non-empty recovery
	// one, because the transport name falls back to the host and the recovery name has no fallback at all.
	// Measured against the live box on 2026-08-22 when the Edge reported seeing exactly that combination.
	if sent == "" && recovery != "" {
		t.Fatal("an empty transport name beside a populated recovery name is not a state this agent can be in")
	}
}

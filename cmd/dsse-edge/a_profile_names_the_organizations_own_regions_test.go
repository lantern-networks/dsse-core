package main

import (
	"strings"
	"testing"
)

// ★★★ THE PROFILE IGNORED THE ORGANIZATION'S OWN REGIONS (2026-08-29, found by issuing one for an
// organization whose home region is "tokyo" and reading it: transport_url pointed at osaka).
//
// regionEndpointCatalog.allowedRegionEndpoints already answers this correctly — it emits ONLY the regions an
// organization may occupy and puts its home region first — and both profile routes called it with (nil, "").
//
// Two consequences, and the second is the serious one:
//
//   - every device's FIRST contact went to whichever region sorted first. That is the one moment the home
//     region is all there is to go on: no Edge has answered yet, so no signed region list governs.
//   - an organization pinned to ONE region was offered the other. Residency is declared on the tenant row and
//     shown on the screen, and the artefact its devices and connectors actually take ignored it.
func TestAProfileOffersTheOrganizationsOwnRegionsHomeFirst(t *testing.T) {
	catalog, err := parseRegionEndpoints("osaka=https://agents.osaka.example;tokyo=https://agents.tokyo.example")
	if err != nil {
		t.Fatal(err)
	}
	// The deployment's catalogue sorts osaka before tokyo, which is what made the defect invisible for an
	// organization whose home is osaka and obvious for one whose home is tokyo.
	tenants := map[string]struct {
		allowed []string
		home    string
	}{
		"tenant_tokyohome": {allowed: []string{"osaka", "tokyo"}, home: "tokyo"},
		"tenant_pinned":    {allowed: []string{"tokyo"}, home: "tokyo"},
	}
	regions := func(id string) []regionEndpoint {
		row, ok := tenants[id]
		if !ok {
			return catalog.allowedRegionEndpoints(nil, "")
		}
		return catalog.allowedRegionEndpoints(row.allowed, row.home)
	}

	// ★ HOME FIRST. The first entry is what agentProfilePrimaryURL turns into transport_url.
	got := agentProfileEndpoints("", "tenant_tokyohome", regions)
	if len(got) != 2 || !strings.HasPrefix(got[0], "tokyo=") {
		t.Errorf("an organization whose home region is tokyo is sent to %v first — its devices cross regions on "+
			"first contact, which is the one moment the home region is all there is to go on", got)
	}
	if url := agentProfilePrimaryURL(got); url != "https://agents.tokyo.example" {
		t.Errorf("transport_url is %q", url)
	}

	// ★★ AND A PINNED ORGANIZATION IS NEVER OFFERED THE OTHER REGION. This is residency, not preference: the
	// catalogue's own contract says an out-of-boundary region is NEVER emitted.
	pinned := agentProfileEndpoints("", "tenant_pinned", regions)
	for _, e := range pinned {
		if strings.HasPrefix(e, "osaka=") {
			t.Errorf("an organization allowed only in tokyo was handed %q — residency is declared on the tenant "+
				"row and the profile its devices take must not widen it", e)
		}
	}
	if len(pinned) != 1 {
		t.Errorf("a pinned organization was offered %d door(s): %v", len(pinned), pinned)
	}

	// The control: an organization this node has no row for still gets the deployment's list, which is what
	// every organization got before this. Narrowing to nothing would take a fleet off the network.
	if unknown := agentProfileEndpoints("", "tenant_unknown", regions); len(unknown) != 2 {
		t.Errorf("an unknown organization was handed %v — a node with no row for a tenant must not narrow its "+
			"doors to nothing", unknown)
	}
}

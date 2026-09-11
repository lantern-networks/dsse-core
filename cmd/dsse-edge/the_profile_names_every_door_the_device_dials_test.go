package main

import (
	"strings"
	"testing"
)

// ★★★ THE PROFILE NAMED THE TRANSPORT DOOR AND NOT THE ENROLMENT ONE (2026-08-29, measured on a Mac that
// could not enrol).
//
// On a folded transport port the enrolment path is selected BY the name in the ClientHello —
// organizationEnrolmentName, "enrol." in front of the organization's own name — and the profile stated only
// the transport name. A device holding nothing therefore dialled the TRANSPORT listener for its very first
// request, which is not the listener that issues identities.
//
// The names are derived from the same server name the certificate carries, by the same function the Edge
// selects with, so a name can never be offered that the node does not serve — which this deployment has
// already paid for twice, on the recovery name and on the enrolment name.
func TestTheProfileNamesEveryDoorTheDeviceDials(t *testing.T) {
	source := readSourceFile(t, "admin_agent_profile_routes.go")
	for _, want := range []struct{ code, why string }{
		{"organization.TransportServerName = ", "the door its steered traffic goes through"},
		{"organization.EnrolmentServerName = organizationEnrolmentName(", "the door that issues its first certificate"},
		{"organization.RenewalRecoveryServerName = organizationRecoveryName(", "the door it comes back through when its certificate has expired"},
	} {
		if !strings.Contains(source, want.code) {
			t.Errorf("the profile does not name %s — a device holding nothing dials the wrong listener and "+
				"the failure arrives as a bare TLS error", want.why)
		}
	}

	// ★ DERIVED, NOT SPELLED. A literal "enrol."+name here would be a second implementation of the rule the
	// Edge selects by, and the two would drift into a name that is offered and not served.
	if strings.Contains(source, `"enrol." + `) {
		t.Error("the enrolment name is spelled out rather than derived from the function the Edge selects with")
	}
}

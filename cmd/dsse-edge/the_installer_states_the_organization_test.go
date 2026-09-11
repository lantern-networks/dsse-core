package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ A DEVICE THAT HOLDS NOTHING CANNOT LEARN ITS ORGANIZATION FROM THE BUNDLE (2026-08-22).
//
// The bundle arrives after enrolment, and enrolment is what needs the name: on the folded transport port the
// enrolment path is selected by SNI, and only enrol.<organization> opens it. Measured — every other name,
// including the deployment's own resolvable one, is refused at the handshake, and an IP literal sends no SNI
// at all. So the installer states it.
func TestTheAgentConfigStatesTheOrganization(t *testing.T) {
	// No organization to speak of: the field is absent rather than empty.
	if got := agentConfigOrganization(""); got != nil {
		t.Fatalf("a config with no organization grew the field anyway: %#v", got)
	}

	// An organization with no transport name of its own is still NAMED — knowing whose device this is matters
	// for enrolment either way, and a missing name is not a reason to withhold the id.
	got := agentConfigOrganization("tenant_no_transport_name")
	if got == nil || got["tenant_id"] != "tenant_no_transport_name" {
		t.Fatalf("the organization id was withheld: %#v", got)
	}
	if _, present := got["transport_server_name"]; present {
		t.Fatalf("a name this deployment cannot serve was offered: %#v", got)
	}
	if _, present := got["enrolment_server_name"]; present {
		t.Fatalf("an enrolment name was offered with no transport name behind it: %#v", got)
	}

	// Case is normalised the way every other organization comparison in this tree does it.
	if got := agentConfigOrganization("  Tenant_Mixed_Case  "); got["tenant_id"] != "tenant_mixed_case" {
		t.Fatalf("the organization id was not normalised: %#v", got)
	}
}

// And the publisher puts it in the file, not merely in a helper — the shape this repo keeps finding.
func TestTheAgentConfigPublisherEmitsTheOrganization(t *testing.T) {
	b, err := os.ReadFile("network_extension_snapshot_publisher.go")
	if err != nil {
		t.Fatalf("read the publisher: %v", err)
	}
	raw := string(b)
	if !strings.Contains(raw, `config["organization"] = org`) {
		t.Fatal("the published agent config does not state the organization, so a device installed from it " +
			"cannot reach the folded enrolment path — it does not know the name to present")
	}
	// ★ AND THE NAME IS ONLY OFFERED WHEN A CERTIFICATE CARRIES IT. the enrolment fold has paid for the opposite twice.
	if !strings.Contains(raw, "transportTenantCertificates.For(enrol)") {
		t.Fatal("the enrolment name is offered without checking that a certificate this node serves carries " +
			"it — a device dialling a name nothing answers to reads as the Edge being down")
	}
}

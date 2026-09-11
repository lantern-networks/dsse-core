package main

import (
	"crypto/tls"
	"strings"
	"testing"
)

// ★★★ THE INSTALL BUNDLE SAID "EMBED THESE IN THE AGENT INSTALLER FOR THIS ORGANIZATION" AND DID NOT CARRY
// THE ONE THING THAT REACHES IT (2026-08-22, measured).
//
// An installer built from that answer got the organization's transport CA and its trust bundle and NO NAME.
// The device then dials the Edge by ADDRESS, is served the DEPLOYMENT-WIDE certificate, and refuses it —
// because the only anchor it was given is its own organization's. Permanent from the moment the shared anchor
// leaves that organization's bundle, which is the last step of roadmap D.
//
// It is also what held the enrolment fold's data port open: the port stays "until every agent has been given the name",
// and the product's own install path was not giving it.
func TestTheInstallBundleNamesWhatAnInstallerMustSend(t *testing.T) {
	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })

	// An organization this node serves under its own name — through the same resolver the agent
	// configuration uses, because a second one here would be a second opinion that drifts.
	restoreAuthority := agentConfigTransportAuthority
	agentConfigTransportAuthority = newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	t.Cleanup(func() { agentConfigTransportAuthority = restoreAuthority })
	if _, err := agentConfigTransportAuthority.EnsureCA("tenant_lab", "lab.dsse.invalid"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	// The certificate index FIRST: the enrolment name is stated only when this node actually serves it, which
	// is the rule that stops the bundle naming something a handshake would never produce.
	transportTenantCertificates.put("tenant_lab", []string{"lab.dsse.invalid", "enrol.lab.dsse.invalid"},
		&tls.Certificate{}, "anchor")
	org := agentConfigOrganization("tenant_lab")
	name, _ := org["transport_server_name"].(string)
	if name == "" {
		t.Fatal("the fixture serves no name, so this test would measure nothing")
	}
	if org["enrolment_server_name"] != "enrol.lab.dsse.invalid" {
		t.Fatalf("the bundle would state the wrong enrolment name: %v", org["enrolment_server_name"])
	}
	transportTenantCertificates.put("tenant_lab", []string{"lab.dsse.invalid", "enrol.lab.dsse.invalid"},
		&tls.Certificate{}, "anchor")
	if got := organizationEnrolmentName(name); got != "enrol.lab.dsse.invalid" {
		t.Fatalf("the enrolment name an installer must send is wrong: %q", got)
	}
	// ★ The enrolment name has to be one the certificate actually carries, or every dial from a device
	// holding nothing is a verification failure — the shape the enrolment fold has already paid for twice.
	if _, _, served := transportTenantCertificates.For(organizationEnrolmentName(name)); !served {
		t.Error("the bundle would name an enrolment name this node does not serve")
	}

	// An organization with no name of its own: nothing to state, and an installer for it is NOT complete —
	// it would produce exactly the device described above.
	nameless := agentConfigOrganization("tenant_nameless")
	if n, _ := nameless["transport_server_name"].(string); n != "" {
		t.Errorf("an organization this node serves no name for must state none, got %q", n)
	}
	if got := organizationEnrolmentName(""); got != "" {
		t.Errorf("no name means no enrolment name, not a prefix on its own: %q", got)
	}
	if strings.HasPrefix(organizationEnrolmentName(""), "enrol.") {
		t.Error("a bare prefix would be offered as a name no certificate carries")
	}
}

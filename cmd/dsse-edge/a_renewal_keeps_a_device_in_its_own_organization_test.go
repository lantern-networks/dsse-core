package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ EVERY RENEWAL MOVED A DEVICE BACK TO THE DEPLOYMENT'S CA (2026-08-22, measured on the lab).
//
// POST /enroll picks the signer per organization. POST /enroll/renew took ONE signer at registration and used
// it for every device, whoever they belonged to — and it stamped the NODE's organization into the subject. So
// a device enrolled under its organization's authority was moved back on its first renewal, and a device
// enrolled before its organization had one could never leave. Measured: every device in this lab presented a
// certificate from "Lantern DSSE Device Issuing CA" months after its organization had its own, and no number
// of renewals would ever have changed that. It is the last thing between this deployment and per-tenant
// device identity.
//
// The organization comes from the LEDGER — the control plane's answer, keyed by the identity the verified
// certificate proved. Never from the request, never from the node's own configuration.
func TestARenewalIsSignedUnderTheDevicesOwnOrganization(t *testing.T) {
	restore := tenantDeviceIdentity
	tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{},
		rotation: map[string]deviceAuthorityFingerprints{}}
	t.Cleanup(func() { tenantDeviceIdentity = restore })

	ledger := enrolledinventory.NewLedger()
	ledger.ReplaceAll([]enrolledinventory.Entry{
		{Identity: "mac-dev-1", Enabled: true, TenantID: "tenant_reference_lab"},
		{Identity: "loner-1", Enabled: true, TenantID: "tenant_no_authority"},
		{Identity: "unknown-1", Enabled: true},
	}, "")

	if got := renewTenantOf(ledger, "mac-dev-1"); got != "tenant_reference_lab" {
		t.Fatalf("the ledger is the authority on which organization a device belongs to, got %q", got)
	}
	if got := renewTenantOf(ledger, "MAC-DEV-1"); got != "tenant_reference_lab" {
		t.Errorf("identity matching must normalise the way every other lookup does, got %q", got)
	}
	if got := renewTenantOf(ledger, "unknown-1"); got != "" {
		t.Errorf("an entry with no organization must answer nothing, not a guess: %q", got)
	}
	if got := renewTenantOf(nil, "mac-dev-1"); got != "" {
		t.Errorf("no ledger means no answer, not a default: %q", got)
	}

	// ★ An organization this node holds no authority for falls back to the node's signer — the behaviour a
	// single-tenant deployment has always had — rather than refusing a renewal, which would strand the device.
	if signerFor("tenant_no_authority") != nil {
		t.Fatal("this test's node holds no authority for that organization; the fixture is wrong")
	}
	if signerFor("tenant_reference_lab") != nil {
		t.Fatal("nothing installed yet — the assertion below would pass for the wrong reason")
	}

}

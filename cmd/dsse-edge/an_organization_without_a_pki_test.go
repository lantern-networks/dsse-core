package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// ★★★ AN ORGANIZATION THAT DOES NOT BRING A PKI HAD NO ROUTE TO AN INTERCEPTION AUTHORITY (2026-08-30).
//
// The control plane is where an organization's interception authority belongs — every Edge takes the same one
// from there, so the organization's devices can be told one fingerprint. But the endpoint only IMPORTED: it
// is written for a customer who signs an issuing CA under their own root. An organization without a CA team —
// the ordinary onboarding case, and every lab — could not use it, and the only route in the product that
// MINTED a root was the per-Edge one, which is per-Edge by construction. A region ended up with one root per
// Edge process, all different, and which one signed a device's traffic depended on which the door picked.
func TestAMintedAuthorityPassesTheImportItGoesThrough(t *testing.T) {
	rootPEM, issuingPEM, keyPEM, err := mintTenantInterceptionAuthority(
		"tenant_zkn2u436c5g53gfwzdcbddrfqy", "Sakura Foods", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	authority := &tenantInterceptionAuthority{issuers: map[string]*storedTenantInterceptionIssuer{},
		now: time.Now}
	if _, err := authority.Import("tenant_zkn2u436c5g53gfwzdcbddrfqy", rootPEM, issuingPEM, keyPEM); err != nil {
		t.Fatalf("the material this mints does not pass the check every imported authority must pass: %v", err)
	}
}

// ★ The issuing CA must permit a CA beneath it. The control plane mints a short-lived per-Edge tier under it
// so the long-lived key never reaches a node; pathLenConstraint:0 makes every chain that tier signs invalid —
// openssl says "path length constraint exceeded" and Chrome accepts it, which is how one reached a device and
// was found by git failing rather than by a browser.
func TestTheMintedIssuingAuthorityHasRoomForThePerEdgeTier(t *testing.T) {
	_, issuingPEM, _, err := mintTenantInterceptionAuthority("tenant_x", "Aoi Manufacturing", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issuingPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA {
		t.Fatal("the issuing certificate is not a CA")
	}
	if cert.MaxPathLenZero {
		t.Fatal("the issuing authority is pathLenConstraint:0, so the per-Edge tier beneath it produces chains " +
			"openssl refuses and browsers accept")
	}
	if cert.MaxPathLen < 1 {
		t.Fatalf("the issuing authority leaves no room for the per-Edge tier (MaxPathLen=%d)", cert.MaxPathLen)
	}
}

// ★ Roots an operator cannot tell apart on a device is a defect this deployment already reports on. A fleet
// of organizations whose roots all read the same name is exactly that.
func TestAMintedRootNamesItsOrganization(t *testing.T) {
	rootPEM, _, _, err := mintTenantInterceptionAuthority("tenant_zkn2u436c5g53gfwzdcbddrfqy", "Sakura Foods", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(rootPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cert.Subject.CommonName, "Sakura Foods") {
		t.Fatalf("the root does not name the organization an operator will read it as: %q", cert.Subject.CommonName)
	}
	// Display names are not unique; the id is. Both, so a duplicate name is still separable.
	if len(cert.Subject.OrganizationalUnit) == 0 ||
		!strings.Contains(strings.Join(cert.Subject.OrganizationalUnit, ","), "tenant_zkn2u") {
		t.Fatalf("the root does not carry the organization's id: %v", cert.Subject)
	}
	if !cert.IsCA || cert.MaxPathLen < 2 {
		t.Fatalf("the root leaves no room for an issuing CA and the per-Edge tier under it (MaxPathLen=%d)",
			cert.MaxPathLen)
	}
}

// ★★★ AND WHEN AN ORGANIZATION HAS BOTH, THE DEPLOYMENT'S ANSWER WINS (2026-08-30, measured an hour after the
// control-plane authority existed):
//
//	osaka announced f1c7fdf6…   (the deployment's authority for Sakura Foods)
//	tokyo announced efa1ac6d…   (a root left over on that node)
//
// The same organization, two answers, one door apart. A device is told one fingerprint and may be served by
// any Edge, so the node-local root is what a deployment has BEFORE it has an authority and must stop being
// the answer the moment it does.
func TestTheDeploymentsAuthorityOutranksARootLeftOnANode(t *testing.T) {
	body := readFileForTest(t, "trust_bundle_per_tenant.go")
	if !strings.Contains(body, "tenantHasCentralInterceptionAuthority(config, tenant)") {
		t.Fatal("a root minted on this node is still announced even when the deployment holds this " +
			"organization's authority, so two Edges answer differently about the same organization")
	}
	// And the local root must still be the answer when there is no authority — that is the state every
	// deployment is in before one is created, and removing it would announce nothing at all.
	i := strings.Index(body, "func tenantHasCentralInterceptionAuthority")
	if i < 0 {
		t.Fatal("the precedence has no named rule")
	}
	if !strings.Contains(body[i:], "ListOfflineTenantIntermediates()") {
		t.Fatal("the rule does not read the deployment-held authority")
	}
}

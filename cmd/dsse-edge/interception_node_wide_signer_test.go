package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★ THE DEPLOYMENT-WIDE ANSWER NAMED A SIGNER AND NEVER SAID WHETHER IT SIGNS (2026-08-19).
//
// GET /admin/interception-intermediate leads with intermediate_cn and root_cn. Measured on the reference lab
// it answered root_cn "Lantern DSSE MSSP Root CA v2" while signing_counts_since_start, in the same body, read
// {own_offline_root: 11} — every leaf signed by an organization's OWN authority and none by the one named.
// An operator reading the headline concludes the deployment intercepts under the provider's root, which is
// part of how two regions came to sign the same organization differently without it looking urgent.
//
// So the answer now names the organizations that signer would still sign for. Empty means it signs for
// nobody, which is the fact that makes it retirable and the one the screen could not previously give.
func TestTheDeploymentWideAnswerSaysWhoTheNodeWideSignerStillSignsFor(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	config := serverConfig{
		Evaluator:              testEvaluator(), // node tenant = tenant_lab_001, which has NO issuer of its own
		EnrolledLedger:         enrolledinventory.NewLedger(),
		NetworkExtensionLabTLS: interception,
		TenantIDForTrust:       "tenant_lab_001",
		AdminAuth:              newAdminAuthStore(),
	}

	// The node's own organization has no issuer here, so the node-wide signer still signs for it — and says so.
	signsFor := tenantsWithoutTheirOwnInterceptionIssuer(config)
	if len(signsFor) != 1 || signsFor[0] != "tenant_lab_001" {
		t.Fatalf("the node-wide signer signs for tenant_lab_001 and the answer says %v", signsFor)
	}

	// Give that organization its own issuer too: now the node-wide signer signs for nobody, which is what
	// makes it retirable. A check that only ever produced a non-empty list would never show that.
	labRoot, labInter, labKey := offlineTenantBundleForTest(t, "Lab", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_lab_001", labRoot, labInter, labKey); err != nil {
		t.Fatalf("load lab issuer: %v", err)
	}
	if got := tenantsWithoutTheirOwnInterceptionIssuer(config); len(got) != 0 {
		t.Fatalf("every organization has an authority of its own and the node-wide signer is still reported as "+
			"signing for %v — an operator cannot tell it is retirable", got)
	}

}

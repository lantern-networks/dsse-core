package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ EVERY ORGANIZATION WAS AUTHORED ON THE CONTROL PLANE AND INSPECTED UNDER ONE SHARED ROOT (2026-08-27,
// measured on the Edge that does the signing, after walking a customer's whole PKI through the Console).
//
// The Console said what an operator wants to hear:
//
//	In use: CN=Kaede Logistics Interception Root,O=Kaede Logistics
//
// The Edge that terminates that organization's TLS said the opposite, and it is the one that is right:
//
//	per_tenant: []   per_tenant_issuers: []
//	signing_scope: {configured: "shared", effective: "shared_root_direct", per_tenant_signing: false,
//	                note: "one root for every tenant; provisioned per-tenant roots are not used to sign"}
//
// An Edge fetches each organization's transport certificate and interception material from the control plane
// only when it is told to. The installer never told it, so every deployment this program has ever produced
// authors per-organization PKI that nothing enforces: the customer's root is registered, listed, handed to
// their devices — and every leaf is minted by the deployment's one shared CA anyway.
//
// ★ AND THE CHECK BESIDE IT PASSED. verifyAnOrganizationCanHaveItsOwnTree asks the CONTROL PLANE whether it
// has somewhere to KEEP an authority, which it did. Authoring and enforcing are different nodes, and only the
// enforcing one can answer this.
func TestEveryEdgeAssemblesItsOrganizationsFromTheControlPlane(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	edge := string(body)
	if !strings.Contains(edge, "-tenant-transport-material-from-cp") {
		t.Error("an Edge is not told to fetch its organizations' material from the control plane — so every " +
			"organization's traffic is signed by the deployment's ONE shared interception root no matter what " +
			"the Console was told, and per-organization PKI is authored and never enforced")
	}
	// ★★ AND THE FETCH RIDES ON THE AUDIT-INGEST CHANNEL, so naming the flag without those is the same as not
	// naming it — the node logs "NOT fetched" once at start-up and serves shared material forever.
	for _, needed := range []string{"-audit-ingest-url=", "-audit-ingest-token=", "-audit-ingest-ca="} {
		if !strings.Contains(edge, needed) {
			t.Errorf("the material fetch is enabled and %s is not set — the node will log NOT fetched and go on "+
				"signing every organization under the shared root", needed)
		}
	}
}

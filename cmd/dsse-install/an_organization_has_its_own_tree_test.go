package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ A GENERATED DEPLOYMENT HAD NOWHERE TO KEEP AN ORGANIZATION'S OWN PKI (2026-08-27, found by creating an
// organization in the Console and trying to give it one).
//
// The canonical is that every organization has its own tree — device identity, transport, interception — so
// that no single key can impersonate two of them. The control plane has a durable store for each, and each
// one says plainly what an empty value costs:
//
//	-tenant-transport-authority-store    "Empty = this node issues no per-organization transport material,
//	                                     and Edges cannot assemble themselves"
//	-tenant-interception-authority-store "Empty = this node hands Edges no interception material"
//
// The installer named none of them. So the Console offered "Register this tenant's device CA" and "Load this
// tenant's interception CA" — with a time-boxed elevation the customer can see — and the second answered
//
//	interception is not enabled on this node, so it cannot say what this organization's traffic is
//	inspected under
//
// Every organization fell back to the deployment's ONE shared interception root. The Edge said so
// (configured=shared, per_tenant_issuers=0) and nothing else did.
func TestEveryOrganizationHasSomewhereToKeepItsOwnTree(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(script)

	for _, store := range []struct{ flag, costOfEmpty string }{
		{"-tenant-model-store", "an organization created in the Console is gone on the next restart"},
		{"-tenant-device-authority-store", "no organization can say which device CA admits its devices"},
		{"-tenant-transport-authority-store", "Edges cannot assemble themselves for an organization"},
		{"-tenant-interception-authority-store", "this node hands Edges no interception material, so every organization shares one root"},
	} {
		if !strings.Contains(body, store.flag+"=") {
			t.Errorf("the control plane is started without %s — %s", store.flag, store.costOfEmpty)
		}
	}

	// ★ AND NOT WITH AN EMPTY VALUE, which is the same as absent and reads as configured. Each of these
	// selects a BACKEND; -state-dir cannot default them, and a path is not an answer.
	for _, bad := range []string{
		`-tenant-model-store="" `, `-tenant-device-authority-store="" `,
		`-tenant-transport-authority-store="" `, `-tenant-interception-authority-store="" `,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("%s is named and empty, which is the same as absent", strings.TrimSpace(bad))
		}
	}

	// ★★ THE CONTROL: an EDGE must not be given them. Holding organizations' authorities is what a control
	// plane does; serving their traffic is what an Edge does, and the node that does both is the co-location
	// this deployment shape exists to end.
	edge, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []string{"-tenant-device-authority-store", "-tenant-transport-authority-store",
		"-tenant-interception-authority-store"} {
		if strings.Contains(string(edge), store+"=") {
			t.Errorf("an Edge is given %s — it serves organizations' traffic, it does not hold their authorities", store)
		}
	}
}

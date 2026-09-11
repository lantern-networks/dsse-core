//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// ★★★ THE FIX THAT PROTECTED ONLY THE DEVICES THAT DID NOT NEED IT (2026-08-30, the macOS session's finding,
// reproduced here because this box was repaired by hand for exactly this).
//
// Recording the tenant on the adopted pointer makes a stranger's distribution detectable — for distributions
// adopted after the field existed. Every pointer in the field today predates it, so the check answered "cannot
// tell" for the entire fleet it was written to protect. The evidence was already on disk: the name the
// distribution tells this device to present. A name that is not the one this deployment serves is proof, not
// suspicion.
func TestAnAdoptedDistributionThatNamesAnotherDeploymentIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Some Other Deployment Transport CA (test)")
	// A pointer as they exist in the field: a serial, a name, and NO tenant.
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 3, TransportCAPEM: string(ca.pem),
		TransportServerName: "44paeq.dsse.invalid"}, "", "44paeq.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if p, ok := readAdoptedPointer(dir); !ok || strings.TrimSpace(p.TenantID) != "" {
		t.Fatalf("the fixture must have no tenant, got %+v", p)
	}

	discarded, note := discardForeignAdoptedAnchors(dir, "tenant_sakura", "c2neh.hikari.lab")
	if !discarded {
		t.Fatalf("a distribution naming another deployment survived: %q", note)
	}
	for _, want := range []string{"44paeq.dsse.invalid", "c2neh.hikari.lab", "somebody else"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note does not carry %q: %s", want, note)
		}
	}
	// Moved, not deleted: the pointer is the evidence of what this device was carrying and why it could not
	// reach its own deployment.
	if _, err := os.Stat(filepath.Join(dir, adoptedPointerFile)); !os.IsNotExist(err) {
		t.Fatal("the pointer is still in force")
	}
	kept := 0
	for _, e := range mustDir(t, dir) {
		if strings.Contains(e, ".foreign-") {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("expected the pointer and the anchors kept aside, found %d", kept)
	}
	// And the floor no longer gates this organization's distribution.
	if got := trustSerialFloorForName(dir, "tenant_sakura", "c2neh.hikari.lab"); got != 0 {
		t.Fatalf("floor = %d after the discard", got)
	}
}

// ★ A RENAME WITHIN ONE ORGANIZATION IS NOT A STRANGER. Discarding there resets the replay floor to zero and
// lets a withdrawn CA come back, which is the failure the floor exists to prevent.
func TestARenameInsideOneOrganizationIsNotDiscarded(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Sakura Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 9, TenantID: "tenant_sakura", TransportCAPEM: string(ca.pem),
		TransportServerName: "old-name.hikari.lab"}, "", "old-name.hikari.lab"); err != nil {
		t.Fatal(err)
	}
	discarded, note := discardForeignAdoptedAnchors(dir, "tenant_sakura", "new-name.hikari.lab")
	if discarded {
		t.Fatalf("a rename inside one organization was treated as a stranger: %s", note)
	}
	if got := trustSerialFloorForName(dir, "tenant_sakura", "new-name.hikari.lab"); got != 9 {
		t.Fatalf("floor = %d — a rename must not reset the replay guard", got)
	}
}

// The tenant decides when both sides have one, so a stranger is caught even when the names happen to agree.
func TestTheTenantStillDecidesWhenBothSidesHaveOne(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Other Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 4, TenantID: "tenant_default", TransportCAPEM: string(ca.pem),
		TransportServerName: "same.hikari.lab"}, "", "same.hikari.lab"); err != nil {
		t.Fatal(err)
	}
	if discarded, _ := discardForeignAdoptedAnchors(dir, "tenant_sakura", "same.hikari.lab"); !discarded {
		t.Fatal("a different organization survived because the names matched")
	}
}

// Nothing to compare is still nothing to act on: no name on either side leaves the floor standing, and says so.
func TestWithNoNameAndNoTenantTheFloorStands(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Legacy Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 7, TransportCAPEM: string(ca.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	if discarded, _ := discardForeignAdoptedAnchors(dir, "tenant_sakura", "c2neh.hikari.lab"); discarded {
		t.Fatal("a pointer with nothing to compare was discarded on a suspicion")
	}
	if got := trustSerialFloorForName(dir, "tenant_sakura", "c2neh.hikari.lab"); got != 7 {
		t.Fatalf("floor = %d", got)
	}
}

func mustDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

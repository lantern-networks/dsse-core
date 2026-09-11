package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★ A CUSTOMER COULD READ ANOTHER CUSTOMER'S DEVICES (2026-08-15). GET /admin/device-runtime returned this
// node's whole presence map — OS, logged-in users, posture — with no tenant filter at all.
//
// The sighting is on the sibling route: on the reference lab, an ordinary `admin` of tenant_reference_lab with
// no cross-tenant rights read `nw-laptop-001` — tenant_northwind's device — out of /admin/device-certificates,
// and after the fix that same call returns only its own three while the device is still there for the tenant
// that owns it. This route's own rows have not been seen leaking, because presence is written only on the (T)
// mux CONNECT path and no second-tenant device has completed one here yet. Same absent filter, same fix, and
// this test is what stands in for the sighting.
//
// It stayed invisible for exactly the reason this review exists: with one tenant, an unscoped read and a
// correctly scoped one return the same thing.
func TestDeviceRuntimeShowsOnlyTheCallersOwnTenant(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("mac-dev-1", "tenant_reference_lab", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("nw-laptop-001", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	present := map[string]deviceRuntimeView{
		"mac-dev-1":     {OS: "macOS"},
		"nw-laptop-001": {OS: "windows"},
	}

	own, withheld := scopeDeviceRuntimeToTenant(present, ledger, "tenant_reference_lab")
	if _, leaked := own["nw-laptop-001"]; leaked {
		t.Fatal("another tenant's device is visible — its OS, users and posture with it")
	}
	if _, ok := own["mac-dev-1"]; !ok {
		t.Fatal("the caller lost its OWN device")
	}
	if withheld != 0 {
		t.Fatalf("withheld = %d; both devices are attributable", withheld)
	}

	// And from the other side.
	other, _ := scopeDeviceRuntimeToTenant(present, ledger, "tenant_northwind")
	if len(other) != 1 {
		t.Fatalf("the second tenant sees %d device(s), want only its own", len(other))
	}
	if _, ok := other["nw-laptop-001"]; !ok {
		t.Fatal("the second tenant cannot see its own device")
	}
}

// A device the ledger cannot place is withheld and COUNTED. Showing it would hand it to a tenant that may not
// own it; dropping it silently would teach an operator that the fleet is smaller than it is.
func TestAnUnattributableDeviceIsWithheldAndCounted(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("known", "tenant_a", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	present := map[string]deviceRuntimeView{"known": {}, "stranger": {}}

	out, withheld := scopeDeviceRuntimeToTenant(present, ledger, "tenant_a")
	if len(out) != 1 || withheld != 1 {
		t.Fatalf("devices=%d withheld=%d, want 1 and 1", len(out), withheld)
	}
}

// A SCOPED caller with no ledger to scope with sees NOTHING: no device can be attributed, and returning the
// whole map when the filter cannot run is how the defect existed in the first place.
func TestAScopedCallerWithNoLedgerSeesNothing(t *testing.T) {
	present := map[string]deviceRuntimeView{"a": {}, "b": {}}
	if out, withheld := scopeDeviceRuntimeToTenant(present, nil, "tenant_a"); len(out) != 0 || withheld != 2 {
		t.Fatalf("no ledger: devices=%d withheld=%d, want 0 and 2", len(out), withheld)
	}
}

// ★ AND THE FIX MUST NOT BLANK THE SCREEN IT WAS PROTECTING. An UNSCOPED caller — a deployment with no tenant
// model, where adminTenantIDFromRequest resolves nothing — owns the whole node, and this was the first shape
// of the fix: it withheld every device from exactly those admins, turning a leak into an empty fleet view.
//
// The rule is not new and is not this screen's to invent: deviceGroupVisibleToTenant settled it for the
// enrolled-device screens (2026-08-12). An empty CALLER tenant is a fact about the deployment; an empty
// OBJECT tenant is "belongs to nobody". Answering it differently here would give the boundary one answer per
// screen, which is the defect this whole review keeps finding.
func TestAnUnscopedCallerStillSeesTheWholeNode(t *testing.T) {
	present := map[string]deviceRuntimeView{"a": {OS: "macOS"}, "b": {OS: "windows"}}
	out, withheld := scopeDeviceRuntimeToTenant(present, enrolledinventory.NewLedger(), "")
	if len(out) != 2 || withheld != 0 {
		t.Fatalf("unscoped caller: devices=%d withheld=%d, want 2 and 0 — the only admin of this deployment", len(out), withheld)
	}
}

// A device enrolled with NO tenant of its own is withheld from a scoped caller and counted, exactly like one
// the ledger has never heard of: both mean nobody can say whose it is, and "belongs to nobody" must not be
// read as "belongs to everybody".
func TestADeviceEnrolledWithoutATenantIsNotEverybodys(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := ledger.Enroll("orphan", "", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("owned", "tenant_a", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	out, withheld := scopeDeviceRuntimeToTenant(map[string]deviceRuntimeView{"orphan": {}, "owned": {}}, ledger, "tenant_a")
	if _, leaked := out["orphan"]; leaked {
		t.Fatal("a device belonging to nobody was shown to a tenant that may not own it")
	}
	if len(out) != 1 || withheld != 1 {
		t.Fatalf("devices=%d withheld=%d, want 1 and 1", len(out), withheld)
	}
}

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func withdrawalGateFixture(t *testing.T, tenant string, devices map[string]string) serverConfig {
	t.Helper()
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	observed := newObservedExclusionStore(64)
	for identity, pin := range devices {
		if _, err := ledger.Enroll(identity, tenant, "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", identity, err)
		}
		entry := observedExclusionEntry{TenantID: tenant, DeviceIdentity: identity, ReportedAt: time.Now()}
		// "" means the device has not said, which the gate must read as unknown rather than as "not pinned".
		entry.InterceptionRootPinSHA256 = pin
		observed.Record(entry)
	}
	return serverConfig{EnrolledLedger: ledger, ObservedExclusions: observed}
}

// ★ THE WITHDRAWAL IS THE FLAG DAY, DONE BY HAND (2026-08-16). A replacement keeps the outgoing root announced
// so devices pinned to it keep working. Stopping that announcement while devices are still pinned to it makes
// every one of them mismatch at once and, with the pin armed, stand aside together — which is exactly the
// event the overlap was built to remove, re-created by an operator who could not see who had moved.
func TestWithdrawalIsRefusedWhileADeviceIsStillPinnedToThatRoot(t *testing.T) {
	config := withdrawalGateFixture(t, "tenant_northwind", map[string]string{
		"nw-moved":  "bbbb",
		"nw-behind": "aaaa",
	})

	verdict := interceptionRootWithdrawalGate(config, nil, "tenant_northwind", "aaaa")

	if verdict.Allowed {
		t.Fatal("the withdrawal was allowed while a device was still pinned to that root")
	}
	if len(verdict.StillPinned) != 1 || verdict.StillPinned[0] != "nw-behind" {
		t.Fatalf("still pinned = %v; the refusal has to NAME them or an operator goes hunting", verdict.StillPinned)
	}
	if !strings.Contains(verdict.Text, "tenant-install-bundle") {
		t.Fatalf("the refusal does not say how to move the device: %s", verdict.Text)
	}
}

// ★ SILENCE BLOCKS. A device that has not reported a pin is UNKNOWN, never "has moved" — and the machines in
// trouble are disproportionately the quiet ones. The same rule the transport-anchor withdrawal already
// follows; collapsing the two would let a fleet look ready precisely because it had stopped reporting.
func TestADeviceThatHasNotSaidBlocksTheWithdrawal(t *testing.T) {
	config := withdrawalGateFixture(t, "tenant_northwind", map[string]string{
		"nw-moved":  "bbbb",
		"nw-silent": "",
	})

	verdict := interceptionRootWithdrawalGate(config, nil, "tenant_northwind", "aaaa")

	if verdict.Allowed {
		t.Fatal("a device that has said nothing was treated as having moved")
	}
	if len(verdict.Silent) != 1 || verdict.Silent[0] != "nw-silent" {
		t.Fatalf("silent = %v", verdict.Silent)
	}
}

// And it opens when every device has genuinely moved — a gate that never opens is a gate operators route
// around, and the whole overlap depends on being able to close it.
func TestWithdrawalIsAllowedOnceEveryDeviceReportsADifferentPin(t *testing.T) {
	config := withdrawalGateFixture(t, "tenant_northwind", map[string]string{
		"nw-one": "bbbb",
		"nw-two": "bbbb",
	})

	verdict := interceptionRootWithdrawalGate(config, nil, "tenant_northwind", "aaaa")

	if !verdict.Allowed {
		t.Fatalf("refused although nobody is pinned to the outgoing root: %s", verdict.Text)
	}
}

// ★ AN ORGANIZATION WITH NO DEVICES IS ALLOWED. There is nobody to strand, and a gate that cannot be satisfied
// on an empty fleet blocks the very first rotation of every new customer — the state every organization is in
// on the day it is created.
func TestAnOrganizationWithNoDevicesMayWithdraw(t *testing.T) {
	config := withdrawalGateFixture(t, "tenant_northwind", map[string]string{})

	verdict := interceptionRootWithdrawalGate(config, nil, "tenant_northwind", "aaaa")

	if !verdict.Allowed {
		t.Fatalf("an organization with no enrolled device could not withdraw: %s", verdict.Text)
	}
}

// The devices of ANOTHER organization are not this decision's business — counting them would make one
// customer's rotation depend on another customer's fleet.
func TestOnlyThisOrganizationsDevicesAreCounted(t *testing.T) {
	config := withdrawalGateFixture(t, "tenant_northwind", map[string]string{"nw-one": "bbbb"})
	stamp := time.Now().UTC().Format(time.RFC3339)
	if _, err := config.EnrolledLedger.Enroll("lab-behind", "tenant_reference_lab", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	config.ObservedExclusions.Record(observedExclusionEntry{
		TenantID: "tenant_reference_lab", DeviceIdentity: "lab-behind",
		InterceptionRootPinSHA256: "aaaa", ReportedAt: time.Now(),
	})

	verdict := interceptionRootWithdrawalGate(config, nil, "tenant_northwind", "aaaa")

	if !verdict.Allowed {
		t.Fatalf("another organization's device blocked this one's rotation: %s", verdict.Text)
	}
}

// ★ TWO AUTHORITIES WITH ONE NAME (2026-08-16). A trust store shows an operator the NAME, so two certificates
// carrying the same subject are one string twice on the machine they have to clean up — and this product has
// already had an outage from exactly that, then heard it again from the Windows machine the day it was fixed.
// Newly generated per-tenant roots name their organization now; this reports the ones already in the field and
// the ones a customer supplies, which this Edge cannot rename.
func TestRootsSharingACommonNameAreReported(t *testing.T) {
	collisions := interceptionRootsIndistinguishableByName(map[string]string{
		"aaaa": "Lantern DSSE Interception Root",
		"bbbb": "Lantern DSSE Interception Root",
		"cccc": "Northwind Traders Interception Root",
	})

	if len(collisions) != 1 {
		t.Fatalf("reported %d collisions, want exactly the one pair: %v", len(collisions), collisions)
	}
	pair := collisions["Lantern DSSE Interception Root"]
	if len(pair) != 2 || pair[0] != "aaaa" || pair[1] != "bbbb" {
		t.Fatalf("the colliding fingerprints are not named: %v", pair)
	}
	// A name held by exactly one certificate is not a collision — reporting it would bury the real ones.
	if _, wrong := collisions["Northwind Traders Interception Root"]; wrong {
		t.Fatal("a uniquely named root was reported as indistinguishable")
	}
}

// An unnamed certificate is not a collision with every other unnamed one: empty is "no common name", not a
// name they share.
func TestUnnamedRootsAreNotTreatedAsSharingAName(t *testing.T) {
	if got := interceptionRootsIndistinguishableByName(map[string]string{"aaaa": "", "bbbb": "  "}); len(got) != 0 {
		t.Fatalf("unnamed certificates were reported as sharing a name: %v", got)
	}
}

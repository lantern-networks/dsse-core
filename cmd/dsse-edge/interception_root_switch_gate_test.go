package main

import (
	"strings"
	"testing"
	"time"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
)

// The interception root is the one certificate whose replacement breaks EVERY site on a device rather than
// one tunnel, and until now POST /admin/interception-intermediate would switch it with nothing checking who
// held the new root. The gate is decided on what devices REPORTED: silence blocks, because a device that has
// not spoken is unknown rather than fine, and an operator may account for one by name.
func TestInterceptionRootSwitchGateNeedsEveryDeviceToHoldTheNewRoot(t *testing.T) {
	newRoot, newRootPEM, _ := mintTestCA(t, "Incoming Interception Root")
	const tenant = "t-interception-switch"

	ledger := enrolledinventory.NewLedger()
	ledger.SeedFromStatic(map[string]struct{}{"dev-a": {}, "dev-b": {}}, "t0")
	observed := newObservedExclusionStore(8)
	config := serverConfig{
		EnrolledLedger:     ledger,
		ObservedExclusions: observed,
		TenantIDForTrust:   tenant,
		// Distributed but not yet signing under — exactly the state a staged switch is in.
		InterceptionPendingRootPEM: newRootPEM,
	}
	report := func(device string, roots ...string) {
		observed.Record(observedExclusionEntry{TenantID: tenant, DeviceIdentity: device,
			ReportedAt: time.Now(), PinnedInterceptionRootSHA256: roots})
	}

	// Nobody has reported: both devices are named, and the switch is refused.
	ok, verdict := interceptionRootSwitchGate(config, newRootPEM)
	if ok {
		t.Fatal("switching to a root no device has reported holding must be refused")
	}
	if verdict.Code != "root_not_held_by" || len(verdict.Params) != 2 {
		t.Fatalf("refusal must name every device that has not reported, got %s %v", verdict.Code, verdict.Params)
	}

	// One device holds it; the other is still silent, which is not consent.
	report("dev-a", certFingerprint(newRoot))
	if ok, verdict := interceptionRootSwitchGate(config, newRootPEM); ok {
		t.Fatal("a partially-distributed root must not open the gate")
	} else if len(verdict.Params) != 1 || verdict.Params[0] != "dev-b" {
		t.Fatalf("refusal must name only the outstanding device, got %v", verdict.Params)
	}

	// A device that reported OTHER roots but not this one is a refusal too — it spoke, and said no.
	report("dev-b", strings.Repeat("11", 32))
	if ok, _ := interceptionRootSwitchGate(config, newRootPEM); ok {
		t.Fatal("a device reporting other roots but not this one must still block")
	}

	// Both hold it: the switch is allowed.
	report("dev-b", certFingerprint(newRoot))
	if ok, verdict := interceptionRootSwitchGate(config, newRootPEM); !ok {
		t.Fatalf("with every device holding the root the switch must proceed: %s", verdict.Text)
	}
}

// The vouch escape hatch, on the same terms as the transport-anchor gate: something with no trust store to
// report from (a connector) can be accounted for by name, or the gate could never open and would stop being
// a safeguard.
func TestInterceptionRootSwitchGateAcceptsAnOperatorVouch(t *testing.T) {
	newRoot, newRootPEM, _ := mintTestCA(t, "Vouched Interception Root")
	const tenant = "t-interception-vouch"

	ledger := enrolledinventory.NewLedger()
	ledger.SeedFromStatic(map[string]struct{}{"dev-a": {}, "conn-1": {}}, "t0")
	observed := newObservedExclusionStore(8)
	observed.Record(observedExclusionEntry{TenantID: tenant, DeviceIdentity: "dev-a",
		ReportedAt: time.Now(), PinnedInterceptionRootSHA256: []string{certFingerprint(newRoot)}})
	config := serverConfig{EnrolledLedger: ledger, ObservedExclusions: observed,
		TenantIDForTrust: tenant, InterceptionPendingRootPEM: newRootPEM}

	if ok, _ := interceptionRootSwitchGate(config, newRootPEM); ok {
		t.Fatal("the connector has not reported; the gate must hold before the vouch")
	}
	prev := transportAnchorAcks
	transportAnchorAcks = newTransportAnchorAcknowledgements("")
	defer func() { transportAnchorAcks = prev }()
	if err := transportAnchorAcks.Acknowledge(certFingerprint(newRoot), "conn-1",
		"connector has no interception trust store", "tester", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, verdict := interceptionRootSwitchGate(config, newRootPEM); !ok {
		t.Fatalf("an acknowledged identity must count: %s", verdict.Text)
	}
}

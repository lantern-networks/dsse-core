package main

import (
	"path/filepath"
	"testing"
	"time"
)

// A gate that cannot open is not a safeguard.
//
// Adoption is measured from what devices report, which is right for anything running the steering agent and
// impossible for anything that is not. A connector is enrolled because it needs an identity, verifies the Edge
// against a CA file rather than reporting, and so can never appear ready — leaving the withdrawal gate shut
// forever and teaching an operator to work around it.
func TestAnOperatorsAssertionCanOpenTheGate(t *testing.T) {
	before := transportCAReadiness{
		SHA256: "abc", Ready: []string{"mac-dev-1", "win-dev-1"},
		NotReady: []string{}, Silent: []string{"conn-lab-1"}, NeverReportedAnything: []string{"conn-lab-1"},
		ReadyPct: 66, SafeToCut: false,
	}
	after := applyAnchorAcknowledgements(before, map[string]bool{"conn-lab-1": true}, enrolledForTest(before))

	if !after.SafeToCut {
		t.Fatal("with every identity either reported or vouched for, the withdrawal decision must be reachable")
	}
	if after.ReadyPct != 100 {
		t.Fatalf("ReadyPct = %d, want 100", after.ReadyPct)
	}
	// The distinction has to survive. Ready means the device said so; an assertion is somebody's word, and a
	// screen that merged them would answer "is this safe" while destroying "how do we know".
	if len(after.Ready) != 2 {
		t.Fatalf("an acknowledged identity must NOT be moved into Ready: %v", after.Ready)
	}
	for _, id := range after.Silent {
		if id == "conn-lab-1" {
			t.Fatal("an acknowledged identity should no longer be counted as silent")
		}
	}
}

// Acknowledging one identity must not excuse the others. The gate is all-or-nothing because the stragglers are
// precisely the devices that cannot recover on their own.
func TestAcknowledgingOneIdentityDoesNotExcuseTheRest(t *testing.T) {
	before := transportCAReadiness{
		SHA256: "abc", Ready: []string{"mac-dev-1"},
		NotReady: []string{"win-dev-1"}, Silent: []string{"conn-lab-1"},
		SafeToCut: false,
	}
	after := applyAnchorAcknowledgements(before, map[string]bool{"conn-lab-1": true}, enrolledForTest(before))
	if after.SafeToCut {
		t.Fatal("a device that reported NOT holding the anchor still blocks the withdrawal")
	}
	if len(after.NotReady) != 1 {
		t.Fatalf("NotReady = %v, want win-dev-1 left alone", after.NotReady)
	}
}

// The assertion is a claim about a deployment, not an observation of one, so it must name who made it —
// otherwise it cannot be revisited when it turns out to be wrong.
func TestAnAssertionMustNameWhoMadeIt(t *testing.T) {
	acks := newTransportAnchorAcknowledgements(filepath.Join(t.TempDir(), "acks.json"))
	if err := acks.Acknowledge("abc", "conn-lab-1", "CA file updated by hand", "", time.Now()); err == nil {
		t.Fatal("an unattributed assertion must be refused")
	}
	if err := acks.Acknowledge("abc", "conn-lab-1", "CA file updated by hand", "alice@example.com", time.Now()); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	got := acks.For("abc")
	if len(got) != 1 || got[0].AcknowledgedBy != "alice@example.com" || got[0].Reason == "" {
		t.Fatalf("the record must keep who and why: %+v", got)
	}
}

// Durable, or a restart silently re-closes a gate the operator opened and gives them no way to see why.
func TestAssertionsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acks.json")
	if err := newTransportAnchorAcknowledgements(path).
		Acknowledge("abc", "conn-lab-1", "CA file updated", "alice@example.com", time.Now()); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if got := newTransportAnchorAcknowledgements(path).For("abc"); len(got) != 1 {
		t.Fatalf("the assertion did not survive a restart: %+v", got)
	}
	// Withdrawing must survive too, or a retracted claim comes back from the dead.
	acks := newTransportAnchorAcknowledgements(path)
	if err := acks.Withdraw("abc", "conn-lab-1"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if got := newTransportAnchorAcknowledgements(path).For("abc"); len(got) != 0 {
		t.Fatalf("a withdrawn assertion returned after restart: %+v", got)
	}
}

// enrolledForTest is the enrolled set a readiness was measured over — every identity it mentions.
func enrolledForTest(r transportCAReadiness) []string {
	out := []string{}
	out = append(out, r.Ready...)
	out = append(out, r.NotReady...)
	out = append(out, r.Silent...)
	return out
}

// R4: an acknowledgement for an identity that is not enrolled must not move the measurement. Vouching is
// evidence ABOUT a device; a name nobody has heard of is evidence about nothing.
func TestAnAcknowledgementForNobodyDoesNotOpenTheGate(t *testing.T) {
	empty := transportCAReadiness{}
	after := applyAnchorAcknowledgements(empty, map[string]bool{"nobody-at-all": true}, nil)
	if after.SafeToCut || after.ReadyPct != 0 {
		t.Fatalf("an ack for an unknown identity must not open the gate: %+v", after)
	}

	// And with a real fleet, only the enrolled name counts.
	r := transportCAReadiness{Ready: []string{"a"}, Silent: []string{"b"}}
	known := []string{"a", "b"}
	padded := applyAnchorAcknowledgements(r, map[string]bool{"b": true, "ghost-1": true, "ghost-2": true}, known)
	if !padded.SafeToCut {
		t.Fatalf("vouching for the one silent enrolled device should open it: %+v", padded)
	}
	if padded.ReadyPct != 100 {
		t.Fatalf("two enrolled devices, both accounted for, is 100%%: %+v", padded)
	}
}

// R10①: a report has a shelf life. A device that said it held the CA six months ago, and has not been
// heard from since, is silence — not evidence that opens the withdrawal gate.
func TestAStaleReportIsSilenceNotReadiness(t *testing.T) {
	s := newObservedExclusionStore(64)
	fresh := observedExclusionEntry{TenantID: "t", DeviceIdentity: "fresh-1",
		PinnedTransportCASHA256: []string{"aa"}, ReportedAt: time.Now()}
	stale := observedExclusionEntry{TenantID: "t", DeviceIdentity: "stale-1",
		PinnedTransportCASHA256: []string{"aa"}, ReportedAt: time.Now().Add(-90 * 24 * time.Hour)}
	s.Record(fresh)
	s.Record(stale)

	r := s.TransportCAReadiness("t", "aa", []string{"fresh-1", "stale-1"})
	if len(r.Ready) != 1 || r.Ready[0] != "fresh-1" {
		t.Fatalf("only a current report counts as ready: %+v", r)
	}
	if len(r.Silent) != 1 || r.Silent[0] != "stale-1" {
		t.Fatalf("a stale report is silence: %+v", r)
	}
	if r.SafeToCut {
		t.Fatal("a gate must not open on a report nobody has refreshed")
	}
}

// 2026-08-01: fingerprints say what a device HOLDS; only the serial says whether it is holding the set the
// Edge is distributing now. A device reporting an older distribution is verifying against something that has
// since been replaced, and must not open a withdrawal gate.
func TestADeviceOnAnOlderDistributionIsNotReady(t *testing.T) {
	s := newObservedExclusionStore(64)
	current := observedExclusionEntry{TenantID: "t", DeviceIdentity: "current-1",
		PinnedTransportCASHA256: []string{"aa"}, AdoptedTrustSerial: 3, ReportedAt: time.Now()}
	behind := observedExclusionEntry{TenantID: "t", DeviceIdentity: "behind-1",
		PinnedTransportCASHA256: []string{"aa"}, AdoptedTrustSerial: 2, ReportedAt: time.Now()}
	s.Record(current)
	s.Record(behind)

	r := s.TransportCAReadinessAtSerial("t", "aa", []string{"current-1", "behind-1"}, 3)
	if len(r.Ready) != 1 || r.Ready[0] != "current-1" {
		t.Fatalf("only a device on the current distribution is ready: %+v", r)
	}
	if len(r.NotReady) != 1 || r.NotReady[0] != "behind-1" {
		t.Fatalf("a device on an older distribution is not ready: %+v", r)
	}
	if r.SafeToCut {
		t.Fatal("a gate must not open while a device verifies against a superseded set")
	}

	// An agent that does not report a serial yet is judged on fingerprints alone, as before — the new rule
	// must not turn every existing fleet silent the day it ships.
	s2 := newObservedExclusionStore(8)
	s2.Record(observedExclusionEntry{TenantID: "t", DeviceIdentity: "quiet-1",
		PinnedTransportCASHA256: []string{"aa"}, ReportedAt: time.Now()})
	if r2 := s2.TransportCAReadinessAtSerial("t", "aa", []string{"quiet-1"}, 3); !r2.SafeToCut {
		t.Fatalf("a device that does not report a serial keeps its previous meaning: %+v", r2)
	}
}

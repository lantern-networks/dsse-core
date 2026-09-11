package main

import (
	"strings"
	"testing"
	"time"
)

// ★★★ THE PORT MAY ONLY CLOSE ON AN ANSWER (the fold's fourth step/5).
//
// The dedicated recovery listener serves devices whose certificate expired while they were switched off —
// which is to say the devices least likely to have reported anything lately. Every way of reading silence as
// agreement strands exactly those machines, and they cannot complain, because the path they would complain
// over is the one that was closed. Both directions asserted.
func TestTheRecoveryPortClosesOnlyWhenEveryDeviceHasSaidItHoldsTheName(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	name := "recovery.dsse.invalid"

	// ★ A device counts only when it reports BOTH the name it holds and where it would actually dial. Holding
	// the name was the old rule, and win-dev-1 held it while resolving to the port that had just been closed.
	all := []observedExclusionEntry{
		{DeviceIdentity: "mac-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: name,
			RenewalRecoveryTarget: "203.0.113.10:18543|" + name},
		{DeviceIdentity: "win-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: "RECOVERY.DSSE.INVALID",
			RenewalRecoveryTarget: "203.0.113.10:18543|RECOVERY.DSSE.INVALID"},
	}
	ready := measureRecoveryNameReadiness(all, name, []string{"mac-dev-1", "win-dev-1"}, now)
	if !ready.MayCloseTheDedicatedPort() {
		t.Fatalf("every device said it holds the name and the port was still held open: %s", ready.Line())
	}

	// ★ THE CASE THE OLD RULE MISSED: the name is reported and the device resolves somewhere else — the
	// dedicated port it is about to lose. Not silence: a device heading for the wrong door is a device that
	// will fail, and it must be named rather than counted.
	elsewhere := []observedExclusionEntry{
		{DeviceIdentity: "mac-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: name,
			RenewalRecoveryTarget: "203.0.113.10:18543|" + name},
		{DeviceIdentity: "win-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: name,
			RenewalRecoveryTarget: "203.0.113.10:18545"},
	}
	wrongDoor := measureRecoveryNameReadiness(elsewhere, name, []string{"mac-dev-1", "win-dev-1"}, now)
	if wrongDoor.MayCloseTheDedicatedPort() {
		t.Fatal("a device that reports the name and would dial the port about to be closed was counted as " +
			"ready — that is exactly how the port was closed on win-dev-1")
	}
	if len(wrongDoor.DoesNotHold) != 1 || wrongDoor.DoesNotHold[0] != "win-dev-1" {
		t.Fatalf("the device heading for the wrong door was not named: %+v", wrongDoor)
	}

	// A device that reports the name and NOT where it resolves has not shown it can get here.
	noTarget := []observedExclusionEntry{
		{DeviceIdentity: "mac-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: name},
	}
	if measureRecoveryNameReadiness(noTarget, name, []string{"mac-dev-1"}, now).MayCloseTheDedicatedPort() {
		t.Fatal("holding the name was accepted as reaching it, which is the defect this rule replaces")
	}

	// Reported recently, and said nothing about the name — an agent too old to carry the field is here, and it
	// is precisely the agent that will need the dedicated port.
	quiet := append([]observedExclusionEntry{}, all...)
	quiet[1].RenewalRecoverySNISent = ""
	got := measureRecoveryNameReadiness(quiet, name, []string{"mac-dev-1", "win-dev-1"}, now)
	if got.MayCloseTheDedicatedPort() {
		t.Fatal("a device that said nothing about the name was counted as holding it — closing the port on " +
			"that silence strands it with no way back")
	}
	if len(got.Silent) != 1 || got.Silent[0] != "win-dev-1" {
		t.Fatalf("the silent device was not named: %+v", got)
	}

	// Never reported at all: silent AND named as never having said anything, because the two are different
	// problems for an operator.
	never := measureRecoveryNameReadiness(all, name, []string{"mac-dev-1", "win-dev-1", "conn_lab_001"}, now)
	if never.MayCloseTheDedicatedPort() {
		t.Fatal("an enrolled device that has never reported was passed over")
	}
	if len(never.NeverReportedAnything) != 1 || never.NeverReportedAnything[0] != "conn_lab_001" {
		t.Fatalf("a device that never reported anything was not distinguished: %+v", never)
	}

	// A report with a shelf life: six months ago says nothing about a machine since re-imaged.
	stale := []observedExclusionEntry{
		{DeviceIdentity: "mac-dev-1", ReportedAt: now.Add(-transportCAReportShelfLife - time.Hour),
			RenewalRecoverySNISent: name},
	}
	if measureRecoveryNameReadiness(stale, name, []string{"mac-dev-1"}, now).MayCloseTheDedicatedPort() {
		t.Fatal("a stale claim opened the gate")
	}

	// A device holding a DIFFERENT name is not silence — it is a device that will dial somewhere else.
	other := []observedExclusionEntry{
		{DeviceIdentity: "mac-dev-1", ReportedAt: fresh, RenewalRecoverySNISent: "old.dsse.invalid"},
	}
	wrong := measureRecoveryNameReadiness(other, name, []string{"mac-dev-1"}, now)
	if wrong.MayCloseTheDedicatedPort() || len(wrong.DoesNotHold) != 1 {
		t.Fatalf("a device holding another name was not reported as such: %+v", wrong)
	}

	// ★ A service identity is removed from the denominator — and NAMED. It enrols with a token and never
	// dials POST /enroll/renew, so counting it would hold the port open forever on a component that would never
	// use it. Dropping it silently would be the opposite mistake, so the line has to carry it.
	kept, excluded := excludeIdentitiesThatNeverDialRecovery(
		[]string{"mac-dev-1", "conn_lab_001", "win-dev-1"}, map[string]bool{"conn_lab_001": true})
	if len(kept) != 2 || len(excluded) != 1 || excluded[0] != "conn_lab_001" {
		t.Fatalf("the connector was not separated out by name: kept=%v excluded=%v", kept, excluded)
	}
	withConnector := measureRecoveryNameReadiness(all, name, kept, now)
	withConnector.NotAgents = excluded
	if !withConnector.MayCloseTheDedicatedPort() {
		t.Fatalf("two agents holding the name could not close the port because a connector was counted: %s",
			withConnector.Line())
	}
	if !strings.Contains(withConnector.Line(), "conn_lab_001") {
		t.Fatalf("the excluded identity was dropped from the verdict instead of being named: %s", withConnector.Line())
	}
	// A device that is NOT in the registry stays in the denominator, whatever it is called.
	if k, _ := excludeIdentitiesThatNeverDialRecovery([]string{"conn-looks-like-one"}, map[string]bool{}); len(k) != 1 {
		t.Fatal("an identity was excluded on the strength of its name rather than the registry")
	}

	// No name announced at all, and a deployment with no devices: neither may close the port.
	if measureRecoveryNameReadiness(all, "", []string{"mac-dev-1"}, now).MayCloseTheDedicatedPort() {
		t.Fatal("the port closed while no name was announced")
	}
	if measureRecoveryNameReadiness(nil, name, nil, now).MayCloseTheDedicatedPort() {
		t.Fatal("a deployment with no devices at all read as ready")
	}
}

package main

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"
)

func opIntent(sha string) *pkiOperationIntent {
	return &pkiOperationIntent{Kind: "transport_trust_rotation", TargetSHA256: sha,
		StartedAt: time.Now().UTC().Format(time.RFC3339)}
}

func stageByKey(t *testing.T, v pkiOperationView, key string) pkiOperationStage {
	t.Helper()
	for _, st := range v.Stages {
		if st.Key == key {
			return st
		}
	}
	t.Fatalf("no stage %q in %+v", key, v.Stages)
	return pkiOperationStage{}
}

// The property the whole design rests on: stages are COMPUTED from what is measurably true, never stored.
// The same intent produces different stages as the deployment changes underneath it — including changes
// somebody made outside the wizard, which is what a remembered stage gets wrong.
func TestPKIOperationStagesAreComputedFromFacts(t *testing.T) {
	oldCert := parseAllCerts(testCertPEM(t, "old-trust"))[0]
	newCert := parseAllCerts(testCertPEM(t, "new-trust"))[0]
	target := certFingerprint(newCert)

	// Nothing distributed yet: stage 1 is the next thing to do.
	v := buildPKIOperationView(opIntent(target), pkiOperationFacts{Distributed: []*x509.Certificate{oldCert}})
	if v.NextStage != "distribute" || stageByKey(t, v, "distribute").Done {
		t.Fatalf("with the target undistributed, distribute is next: %+v", v)
	}

	// Distributed, but not yet trusted everywhere: the gate's own words carry through.
	v = buildPKIOperationView(opIntent(target), pkiOperationFacts{
		Distributed:        []*x509.Certificate{oldCert, newCert},
		TargetCoverageNote: "not yet trusted by: mac-dev-1",
	})
	if !stageByKey(t, v, "distribute").Done || v.NextStage != "adopt" {
		t.Fatalf("distributed but unadopted should sit at adopt: %+v", v)
	}
	if stageByKey(t, v, "adopt").Blocked != "not yet trusted by: mac-dev-1" {
		t.Fatalf("the blocker must be the gate's reason: %+v", stageByKey(t, v, "adopt"))
	}
	// Switching before adoption is exactly what strands a device, so it is refused with that stated.
	if stageByKey(t, v, "switch").Blocked == "" {
		t.Fatal("switch must be blocked while adoption is incomplete")
	}

	// Trusted everywhere, and the Edge presents a chain the target verifies, but a device has not
	// re-handshaked onto it: applied is not adopted (the 2026-07-31 lesson), so the switch is not done.
	adoption := &serverCertAdoptionReport{OnCurrent: []string{"win-dev-1"}, OnPrevious: []string{"mac-dev-1"}}
	v = buildPKIOperationView(opIntent(target), pkiOperationFacts{
		Distributed: []*x509.Certificate{oldCert, newCert}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{newCert}, ServedAdoption: adoption,
	})
	if stageByKey(t, v, "switch").Done || v.NextStage != "switch" {
		t.Fatalf("a switch nobody has re-handshaked through is not done: %+v", v)
	}

	// Everyone re-handshaked, but the old certificate is still distributed: retire is what remains.
	adoption = &serverCertAdoptionReport{OnCurrent: []string{"mac-dev-1", "win-dev-1"}}
	v = buildPKIOperationView(opIntent(target), pkiOperationFacts{
		Distributed: []*x509.Certificate{oldCert, newCert}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{newCert}, ServedAdoption: adoption,
	})
	if !stageByKey(t, v, "switch").Done || v.NextStage != "retire" {
		t.Fatalf("with the fleet on it, retire is next: %+v", v)
	}

	// Only the target left: complete, with no stage ever having been written down.
	v = buildPKIOperationView(opIntent(target), pkiOperationFacts{
		Distributed: []*x509.Certificate{newCert}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{newCert}, ServedAdoption: adoption,
	})
	if !v.Complete || v.NextStage != "" {
		t.Fatalf("everything measured done means complete: %+v", v)
	}
}

// No operation in flight is the quiet default — not an empty progress display.
func TestPKIOperationViewIsQuietWhenNothingIsInFlight(t *testing.T) {
	v := buildPKIOperationView(nil, pkiOperationFacts{})
	if v.InFlight || len(v.Stages) != 0 || v.Complete {
		t.Fatalf("with no intent there is nothing to show: %+v", v)
	}
}

// The intent is durable and is ALL that is durable: reopening the store finds the operation, and nothing
// about stages is written down (they are recomputed from live facts every time it is read).
func TestPKIOperationIntentSurvivesReopen(t *testing.T) {
	path := t.TempDir() + "/pki_operation.json"
	store, err := openPKIOperationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Current() != nil {
		t.Fatal("a fresh store has nothing in flight")
	}
	if err := store.Start(*opIntent("abc123")); err != nil {
		t.Fatal(err)
	}
	if err := store.Start(*opIntent("def456")); err == nil {
		t.Fatal("a second operation must be refused rather than silently replacing the first")
	}

	reopened, err := openPKIOperationStore(path) // the restart
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Current()
	if got == nil || got.TargetSHA256 != "abc123" {
		t.Fatalf("the intent must survive a restart, got %+v", got)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "stage") {
		t.Fatalf("no stage may be persisted — stages are computed: %s", raw)
	}

	if err := reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("clearing removes the record rather than leaving an empty one behind")
	}
}

// R1: the review's probe — two enrolled devices, no sightings at all (an Edge restart empties them) —
// used to compute the switch as DONE and the whole operation as complete, telling the operator to
// withdraw the old certificate with no evidence any device can verify the new one.
func TestSwitchIsNotDoneWhenNoDeviceHasBeenSeenOnIt(t *testing.T) {
	target := parseAllCerts(testCertPEM(t, "new-trust"))[0]
	empty := buildServerCertAdoption(target, map[string]serverCertSighting{}, []string{"mac-dev-1", "win-dev-1"})
	if empty.Complete {
		t.Fatal("precondition: the adoption report itself must not call this complete")
	}
	v := buildPKIOperationView(opIntent(certFingerprint(target)), pkiOperationFacts{
		Distributed: []*x509.Certificate{target}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{target}, ServedAdoption: &empty,
	})
	st := stageByKey(t, v, "switch")
	if st.Done {
		t.Fatalf("a switch no device has handshaked through is not done: %+v", st)
	}
	if !strings.Contains(st.Blocked, "mac-dev-1") || !strings.Contains(st.Blocked, "win-dev-1") {
		t.Fatalf("the devices not yet seen must be named: %q", st.Blocked)
	}
	if v.Complete {
		t.Fatal("the operation cannot be complete while the switch is not")
	}
	// And the two views computed from the same facts must agree.
	if empty.Complete != st.Done {
		t.Fatal("the adoption report and the switch stage must not contradict each other")
	}
}

// A device with no sighting is as blocking as one still on the previous certificate — both mean "not
// seen on it".
func TestSwitchNamesBothKindsOfMissingDevice(t *testing.T) {
	target := parseAllCerts(testCertPEM(t, "new-trust"))[0]
	report := serverCertAdoptionReport{
		OnCurrent: []string{"win-dev-1"}, OnPrevious: []string{"mac-dev-1"}, NotSeen: []string{"conn-lab-1"},
	}
	st := stageByKey(t, buildPKIOperationView(opIntent(certFingerprint(target)), pkiOperationFacts{
		Distributed: []*x509.Certificate{target}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{target}, ServedAdoption: &report,
	}), "switch")
	if st.Done || !strings.Contains(st.Blocked, "mac-dev-1") || !strings.Contains(st.Blocked, "conn-lab-1") {
		t.Fatalf("both the stale and the unseen device must block and be named: %+v", st)
	}
}

// Telemetry absent is not telemetry saying yes.
func TestSwitchCannotBeConfirmedWithoutAdoptionMeasurement(t *testing.T) {
	target := parseAllCerts(testCertPEM(t, "new-trust"))[0]
	st := stageByKey(t, buildPKIOperationView(opIntent(certFingerprint(target)), pkiOperationFacts{
		Distributed: []*x509.Certificate{target}, TargetCovered: true,
		PresentedChain: []*x509.Certificate{target}, ServedAdoption: nil,
	}), "switch")
	if st.Done || st.Blocked == "" {
		t.Fatalf("with no measurement the switch is unconfirmed, not done: %+v", st)
	}
}

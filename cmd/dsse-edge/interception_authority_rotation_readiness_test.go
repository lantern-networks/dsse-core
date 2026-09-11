package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

const (
	icaOld = "1111111111111111111111111111111111111111111111111111111111111111"
	icaNew = "2222222222222222222222222222222222222222222222222222222222222222"
)

// ★★★ PROMOTING BEFORE EVERY DEVICE HOLDS THE ROOT TAKES EVERY HTTPS SITE AWAY (2026-08-22).
//
// This is the transport shape, not the device-identity one: the Edge presents and the device verifies, so the
// dangerous half is the PROMOTION. It is the eighteen minutes of 2026-08-19, with both sides healthy.
func TestPromotingAnInterceptionAuthorityWaitsForEveryDevice(t *testing.T) {
	enrolled := []string{"mac-dev-1", "win-dev-1"}

	// Nobody has adopted it.
	r := measureInterceptionAuthorityRotation("tenant_reference_lab", icaOld, icaNew, enrolled,
		map[string][]string{"mac-dev-1": {icaOld}, "win-dev-1": {icaOld}})
	if r.MayPromote {
		t.Fatal("promotion was allowed while no device held the incoming root")
	}
	if len(r.DoesNotHold) != 2 {
		t.Fatalf("the devices that do not hold it were not named: %+v", r)
	}

	// One has. A device holding BOTH is ready — that is what adoption looks like mid-rotation.
	r = measureInterceptionAuthorityRotation("tenant_reference_lab", icaOld, icaNew, enrolled,
		map[string][]string{"mac-dev-1": {icaOld, icaNew}, "win-dev-1": {icaOld}})
	if r.MayPromote {
		t.Fatal("promotion was allowed with one device still without the incoming root")
	}
	if len(r.Holds) != 1 || r.Holds[0] != "mac-dev-1" {
		t.Fatalf("a device holding both roots was not counted as ready: %+v", r)
	}
	if !strings.Contains(r.Note, "take every HTTPS site away") {
		t.Fatalf("the note does not say what promoting now would do: %q", r.Note)
	}

	// ★★ SILENCE IS NOT READINESS. The machine that was switched off during the rotation is the one this
	// whole shape exists for, and an empty "does not hold" list must not read as "everybody adopted".
	r = measureInterceptionAuthorityRotation("tenant_reference_lab", icaOld, icaNew, enrolled, map[string][]string{})
	if r.MayPromote {
		t.Fatal("promotion was allowed when NO device had reported at all — absence of evidence read as readiness")
	}
	if len(r.NeverReported) != 2 || !strings.Contains(r.Note, "absence of evidence") {
		t.Fatalf("unreported devices were not counted against the promotion: %+v", r)
	}
	// A device that reported an EMPTY list has still not said it holds it.
	r = measureInterceptionAuthorityRotation("tenant_reference_lab", icaOld, icaNew, enrolled,
		map[string][]string{"mac-dev-1": {icaNew}, "win-dev-1": {}})
	if r.MayPromote {
		t.Fatalf("a device reporting no roots at all was treated as ready: %+v", r)
	}

	// ★ THE CONTROL, and it is the whole test: when everybody HAS adopted, the promotion must be allowed —
	// otherwise this is a gate that never opens and no rotation can ever finish.
	r = measureInterceptionAuthorityRotation("tenant_reference_lab", icaOld, icaNew, enrolled,
		map[string][]string{"mac-dev-1": {icaOld, icaNew}, "win-dev-1": {icaNew}})
	if !r.MayPromote {
		t.Fatalf("every device had adopted and the promotion was still refused: %+v", r)
	}
	// Nothing staged is not "ready" either.
	if idle := measureInterceptionAuthorityRotation("t", icaOld, "", enrolled, nil); idle.Rotating || idle.MayPromote {
		t.Fatalf("an organization with nothing staged reported a rotation: %+v", idle)
	}
	// Fingerprints compare case-insensitively, the way every other comparison in this tree does.
	if up := measureInterceptionAuthorityRotation("t", icaOld, strings.ToUpper(icaNew), enrolled,
		map[string][]string{"mac-dev-1": {icaNew}, "win-dev-1": {icaNew}}); !up.MayPromote {
		t.Fatal("a case difference in the fingerprints was read as a different root")
	}
}

// ★★★ AND HANDING OVER A REPLACEMENT MUST NOT SWITCH ANYTHING (2026-08-22).
func TestAReplacementInterceptionAuthorityIsStagedNotSwitched(t *testing.T) {
	now := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	a := newTenantInterceptionAuthority(nil, nil, func() time.Time { return now })
	rootACert, rootAKey := interceptionTestCA(t, "Probe Root A", nil, nil, now)
	issuingACert, issuingAKey := interceptionTestCA(t, "Probe Issuing A", rootACert, rootAKey, now)
	rootA, issuingA, keyA := certPEMForTest(rootACert), certPEMForTest(issuingACert), ecKeyPEMForTest(t, issuingAKey)
	rootBCert, rootBKey := interceptionTestCA(t, "Probe Root B", nil, nil, now)
	issuingBCert, issuingBKey := interceptionTestCA(t, "Probe Issuing B", rootBCert, rootBKey, now)
	rootB, issuingB, keyB := certPEMForTest(rootBCert), certPEMForTest(issuingBCert), ecKeyPEMForTest(t, issuingBKey)

	// The FIRST authority is not a replacement: nothing is signing, no device trusts anything, it takes effect.
	if _, err := a.Import("tenant_probe", rootA, issuingA, keyA); err != nil {
		t.Fatalf("import the first authority: %v", err)
	}
	if a.IsStaged("tenant_probe") {
		t.Fatal("the first authority was staged, so this organization can never start intercepting")
	}
	before, err := a.IssueFor("tenant_probe", "edge-1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if strings.TrimSpace(before.IncomingRootPEM) != "" {
		t.Fatal("material carried an incoming root with no rotation in flight")
	}

	// A REPLACEMENT is staged.
	if _, err := a.Import("tenant_probe", rootB, issuingB, keyB); err != nil {
		t.Fatalf("stage the replacement: %v", err)
	}
	if !a.IsStaged("tenant_probe") {
		t.Fatal("a replacement was not staged — every device without the new root would lose HTTPS at once")
	}
	mid, err := a.IssueFor("tenant_probe", "edge-1", time.Hour)
	if err != nil {
		t.Fatalf("issue mid-rotation: %v", err)
	}
	if !strings.Contains(mid.RootPEM, strings.TrimSpace(rootA)) {
		t.Fatal("mid-rotation the Edge is no longer signing under the authority in force")
	}
	if !strings.Contains(mid.IncomingRootPEM, strings.TrimSpace(rootB)) {
		t.Fatal("the staged root does not travel to the Edge, so no device is ever asked to adopt it")
	}
	// One at a time.
	if _, err := a.Import("tenant_probe", rootB, issuingB, keyB); err == nil {
		t.Fatal("a second replacement was staged while one was already in flight")
	}

	// ★ THE WAY BACK. A staged authority that turns out to be wrong must be removable without promoting it.
	if _, err := a.WithdrawIncoming("tenant_probe"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if a.IsStaged("tenant_probe") {
		t.Fatal("the staged authority survived a withdrawal")
	}
	after, _ := a.IssueFor("tenant_probe", "edge-1", time.Hour)
	if !strings.Contains(after.RootPEM, strings.TrimSpace(rootA)) {
		t.Fatal("withdrawing the staged authority moved the organization off the one it was signing under")
	}

	// And promoting makes the staged one the only one.
	if _, err := a.Import("tenant_probe", rootB, issuingB, keyB); err != nil {
		t.Fatalf("stage again: %v", err)
	}
	if _, err := a.Promote("tenant_probe"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	promoted, _ := a.IssueFor("tenant_probe", "edge-1", time.Hour)
	if !strings.Contains(promoted.RootPEM, strings.TrimSpace(rootB)) {
		t.Fatal("after the promotion the Edge is not signing under the authority that was staged")
	}
	if strings.TrimSpace(promoted.IncomingRootPEM) != "" {
		t.Fatal("something is still staged after the promotion")
	}
	if _, err := a.Promote("tenant_probe"); err == nil {
		t.Fatal("promoting with nothing staged was accepted")
	}
}

// ★★★ A WITHDRAWAL THAT WRITES ONLY THE BOOKKEEPING (2026-08-22, measured on the lab).
//
// Withdrawing a staged authority on the control plane stops the material carrying its root — and told the
// Edges nothing, so they went on announcing it. Every device would have kept being asked to adopt a root that
// existed nowhere, and the readiness measurement would have kept reporting a rotation nobody could finish or
// cancel: may_promote false for ever, on a rotation that had already been called off.
func TestWithdrawingAStagedAuthorityStopsTheEdgeAnnouncingIt(t *testing.T) {
	raw := interceptionSourceForTest(t, "main.go")
	if !strings.Contains(raw, "interception.WithdrawIncomingTenantRoot(mat.TenantID)") {
		t.Fatal("material that no longer carries an incoming root does not retract the announcement, so every " +
			"device goes on being asked to adopt a root that exists nowhere")
	}
	// ★ AND IT IS THE ELSE OF THE ANNOUNCE, not a separate pass: a node must not withdraw the root it was
	// just told to announce.
	announce := strings.Index(raw, "AnnounceTenantInterceptionRoot(mat.TenantID")
	withdraw := strings.Index(raw, "interception.WithdrawIncomingTenantRoot(mat.TenantID)")
	if announce < 0 || withdraw < 0 || withdraw < announce {
		t.Fatal("the withdrawal does not sit on the other branch of the announcement")
	}
}

func interceptionSourceForTest(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// ★★★ AN IDENTITY WITH NO TRUST STORE HELD THE PROMOTION SHUT (2026-08-22, measured — both devices held the
// incoming root and conn_lab_001 did not, because a connector has no browser and no interception trust store
// to hold one in). Third gate in one day with the same shape: the transport-name retirement and the
// authority promotion were the other two.
func TestAPromotionIsNotHeldShutBySomethingWithNoTrustStore(t *testing.T) {
	enrolled := []string{"mac-dev-1", "win-dev-1", "conn_lab_001"}
	held := map[string][]string{"mac-dev-1": {"aa"}, "win-dev-1": {"aa"}}

	shut := measureInterceptionAuthorityRotation("t", "bb", "aa", enrolled, held)
	if shut.MayPromote {
		t.Fatal("without the exclusion the connector never reported and the gate must stay shut — otherwise " +
			"this test proves nothing about the exclusion below")
	}

	notAgents := map[string]bool{"conn_lab_001": true}
	open := measureInterceptionAuthorityRotationExcluding("t", "bb", "aa", enrolled, held, notAgents)
	if !open.MayPromote {
		t.Fatalf("every device that has a trust store holds the incoming root; the promotion must be "+
			"allowed: %+v", open)
	}
	if len(open.NotAgents) != 1 || open.NotAgents[0] != "conn_lab_001" {
		t.Errorf("the excluded identity must be NAMED in the answer, got %v", open.NotAgents)
	}

	// ★ Self-cancelling: the day it reports a root, it is counted like anything else.
	speaks := map[string][]string{"mac-dev-1": {"aa"}, "win-dev-1": {"aa"}, "conn_lab_001": {"bb"}}
	counted := measureInterceptionAuthorityRotationExcluding("t", "bb", "aa", enrolled, speaks, notAgents)
	if counted.MayPromote {
		t.Error("an identity that reports holding the OLD root only must hold the promotion shut, whatever " +
			"kind it is — the exclusion is about having no trust store, not about being a connector")
	}
	if len(counted.NotAgents) != 0 {
		t.Errorf("an identity that reported a root is no longer excluded, got %v", counted.NotAgents)
	}

	// ★ And excluding must not open a gate a real device is holding shut.
	missing := map[string][]string{"mac-dev-1": {"aa"}}
	still := measureInterceptionAuthorityRotationExcluding("t", "bb", "aa", enrolled, missing, notAgents)
	if still.MayPromote {
		t.Error("a device that does not hold the incoming root must keep the promotion shut")
	}
}

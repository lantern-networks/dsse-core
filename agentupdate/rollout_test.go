package agentupdate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePlan(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "update-plan.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// planFile writes a plan as the bare JSON an unpinned device accepts.
//
// ★ These properties are deliberately tested WITHOUT a signature, because the signature is exactly what does
// not help: it says who wrote a plan and nothing about when, or about which release it describes. A correctly
// signed replay and a correctly signed current plan are the same document to a verifier.
func planFile(t *testing.T, p RolloutPlan) string {
	t.Helper()
	p.SchemaVersion = RolloutPlanSchema
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return writePlan(t, string(b))
}

const barePlan = `{"schema_version":"dsse.agent-update-plan.v1","frozen":false,"window":{"local_start":"01:00","local_end":"03:00","require_idle_minutes":0,"require_unattended":true,"require_ac_power":true,"deadline_days":7}}`

// ★ An Edge with no agent-policy signer serves the plan as a BARE JSON object, and that deployment must not be
// a fleet that freezes itself. Found by probing: before this, a device with no pin froze on the unsigned form,
// so the default lab setup would have halted every machine the moment a plan appeared.
//
// The pin decides. A device with no pin has already opted out of verification — refusing the unsigned FORM
// while accepting unverified CONTENT would be a distinction with no security in it and a halted lab behind it.
func TestAnUnsignedPlanIsAcceptedOnlyByADeviceThatPinsNothing(t *testing.T) {
	path := writePlan(t, barePlan)

	r, err := LoadRollout(path, nil, time.Now(), RolloutExpectation{})
	if err != nil {
		t.Fatalf("a device with no pin refused an unsigned plan: %v", err)
	}
	if r.Frozen {
		t.Fatal("an unsigned plan froze a device that pins nothing; the lab default would halt the fleet")
	}
	if r.Plan.Window == nil || r.Plan.Window.LocalStart != "01:00" {
		t.Fatalf("the plan did not survive: %+v", r.Plan)
	}
	if !strings.Contains(r.Source, "UNSIGNED") {
		t.Fatalf("source = %q; a device accepting an unsigned plan must say so every time", r.Source)
	}
}

// ★ And the other half, which is what makes the first half safe: a device that DID pin a key asked for
// tamper-evidence, so an unsigned document is precisely the substitution it asked to be protected from.
func TestAPinnedDeviceFreezesOnAnUnsignedPlan(t *testing.T) {
	path := writePlan(t, barePlan)

	r, err := LoadRollout(path, []string{strings.Repeat("ab", 32)}, time.Now(), RolloutExpectation{})
	if !errors.Is(err, ErrPlanUnverifiable) {
		t.Fatalf("err = %v, want ErrPlanUnverifiable", err)
	}
	if !r.Frozen {
		t.Fatal("a pinned device accepted an unsigned plan")
	}
	if !strings.Contains(r.FrozenReason, "pins a") {
		t.Fatalf("the reason must say why this device refused where another would not: %q", r.FrozenReason)
	}
}

// Garbage is garbage on either path: an unpinned device must not accept something that is neither an envelope
// nor a plan.
func TestAnUnpinnedDeviceStillFreezesOnRubbish(t *testing.T) {
	path := writePlan(t, `{"nonsense":true}`)
	r, err := LoadRollout(path, nil, time.Now(), RolloutExpectation{})
	if !errors.Is(err, ErrPlanUnverifiable) {
		t.Fatalf("err = %v, want ErrPlanUnverifiable", err)
	}
	if !r.Frozen {
		t.Fatal("an unpinned device accepted a document that is not a plan")
	}
}

// ★ THE FINDING THIS EXISTS FOR (2026-08-11, from a review). The manifest and the plan are couriered
// independently and each keeps its last copy when a fetch fails, so "new manifest, old plan" happens in normal
// operation. Applied blindly, a wave that opened for the PREVIOUS release authorises the immediate install of
// the new one — on every device, without anyone deciding it.
func TestAPlanCannotOpenAWaveForAReleaseItWasNotComputedFor(t *testing.T) {
	plan := RolloutPlan{
		SchemaVersion: RolloutPlanSchema,
		EligibleSince: "2026-01-01T00:00:00Z", // long since open
		TargetVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	path := planFile(t, plan)

	// The release this device is actually being offered is a different one.
	r, err := LoadRollout(path, nil, time.Now(),
		RolloutExpectation{Version: "0.3.0", MaxAge: DefaultPlanMaxAge})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.EligibleSince.IsZero() {
		t.Fatalf("an old wave authorised a release it was never computed for: %s", r.EligibleSince)
	}
	if !strings.Contains(r.WaveWithheld, "0.2.0") || !strings.Contains(r.WaveWithheld, "0.3.0") {
		t.Errorf("the reason must name both releases, got %q", r.WaveWithheld)
	}

	// And the same plan for the SAME release still works: this must withhold waves, not break them.
	r, err = LoadRollout(path, nil, time.Now(),
		RolloutExpectation{Version: "0.2.0", MaxAge: DefaultPlanMaxAge})
	if err != nil || r.EligibleSince.IsZero() {
		t.Fatalf("a plan for the offered release must still open its wave: %+v (%v)", r, err)
	}
}

// ★ A CORRECTLY SIGNED PLAN FROM BEFORE A HALT MUST NOT LIFT IT. The signature says who wrote it and nothing
// about when, so replaying the last plan from before a release was withdrawn is otherwise indistinguishable
// from the current one — and it is the single most useful document an attacker could resend.
func TestAnOlderPlanThanOneAlreadyAcceptedFreezesTheDevice(t *testing.T) {
	accepted := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	replayed := RolloutPlan{
		SchemaVersion: RolloutPlanSchema,
		Frozen:        false, // the whole point of the replay
		EligibleSince: "2026-01-01T00:00:00Z",
		TargetVersion: "0.2.0",
		GeneratedAt:   accepted.Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	path := planFile(t, replayed)

	r, err := LoadRollout(path, nil, accepted.Add(time.Minute),
		RolloutExpectation{Version: "0.2.0", NotBefore: accepted, MaxAge: DefaultPlanMaxAge})
	// ★ AND IT IS REPORTED AS UNVERIFIABLE (2026-08-13, twenty-ninth review). This test used to require err ==
	// nil, which pinned the one freeze branch that did not return ErrPlanUnverifiable — so a REPLAY, the only
	// freeze that means somebody handed this device a document on purpose, was indistinguishable from a halt
	// an operator authored.
	if !errors.Is(err, ErrPlanUnverifiable) {
		t.Fatalf("a replayed plan must be reported as unverifiable, got %v", err)
	}
	if !r.Frozen {
		t.Fatal("an unfrozen plan older than one already accepted must FREEZE, not be applied")
	}
	if !strings.Contains(r.FrozenReason, "OLDER") {
		t.Errorf("the reason must say what was wrong with it, got %q", r.FrozenReason)
	}
}

// A plan nobody has refreshed for a day may still stop this device and may no longer start it: the fleet may
// have withdrawn the release in the meantime and this device would be the last to know.
func TestAStalePlanKeepsItsHaltAndLosesItsWave(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	plan := RolloutPlan{
		SchemaVersion: RolloutPlanSchema,
		Frozen:        true,
		FrozenReason:  "halted two days ago",
		EligibleSince: "2026-01-01T00:00:00Z",
		TargetVersion: "0.2.0",
		GeneratedAt:   old.UTC().Format(time.RFC3339),
	}
	path := planFile(t, plan)

	r, err := LoadRollout(path, nil, time.Now(),
		RolloutExpectation{Version: "0.2.0", MaxAge: DefaultPlanMaxAge})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.Frozen {
		t.Fatal("a stale plan must keep its halt — obeying an old stop is always safe")
	}
	if !r.EligibleSince.IsZero() {
		t.Fatal("a stale plan must not still be opening waves")
	}
}

// The ratchet only moves forward, and a journal that cannot say where it is accepts the next plan rather than
// refusing every one of them.
func TestThePlanFloorIsARatchet(t *testing.T) {
	j := NewJournal()
	if j.AcceptedPlanFloor().IsZero() != true {
		t.Fatal("a fresh journal has no floor")
	}
	first := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
	if !j.AcceptPlanFloor(first) {
		t.Fatal("the first plan must set the floor")
	}
	if j.AcceptPlanFloor(first.Add(-time.Hour)) {
		t.Fatal("an older plan must not lower the floor")
	}
	if !j.AcceptPlanFloor(first.Add(time.Hour)) {
		t.Fatal("a newer plan must raise it")
	}
	if got := j.AcceptedPlanFloor(); !got.Equal(first.Add(time.Hour)) {
		t.Fatalf("floor = %s, want %s", got, first.Add(time.Hour))
	}
}

// ★ MY OWN BUG, found by reading a live device's status against the clock while adding the ratchet. The floor
// is "the newest plan accepted", so accepting one dated next year sets a floor no legitimate plan can clear:
// every later plan reads as a replay and the device freezes for good. A control-plane clock set wrong would do
// that to an entire fleet, and the message would accuse the fleet of being attacked.
func TestAPlanFromTheFutureDoesNotMoveTheRatchet(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	plan := RolloutPlan{
		Frozen:        true,
		FrozenReason:  "halted",
		EligibleSince: "2026-01-01T00:00:00Z",
		TargetVersion: "0.2.0",
		GeneratedAt:   now.Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	r, err := LoadRollout(planFile(t, plan), nil, now, RolloutExpectation{Version: "0.2.0", MaxAge: DefaultPlanMaxAge})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.Frozen {
		t.Error("a future-dated plan must still be able to halt this device")
	}
	if !r.EligibleSince.IsZero() {
		t.Error("a plan whose age cannot be established must not open a wave")
	}
	if !r.PlanGeneratedAt.IsZero() {
		t.Fatal("a future-dated plan must NOT raise the ratchet — that is the permanent-freeze bug")
	}
	if !strings.Contains(r.WaveWithheld, "FUTURE") || !strings.Contains(r.WaveWithheld, "clock") {
		t.Errorf("the reason must send someone to the clock, got %q", r.WaveWithheld)
	}

	// Ordinary skew between two machines is not "the future".
	plan.GeneratedAt = now.Add(2 * time.Minute).UTC().Format(time.RFC3339)
	r, err = LoadRollout(planFile(t, plan), nil, now, RolloutExpectation{Version: "0.2.0", MaxAge: DefaultPlanMaxAge})
	if err != nil || r.PlanGeneratedAt.IsZero() {
		t.Fatalf("a plan two minutes ahead is clock skew, not a future plan: %+v (%v)", r, err)
	}
}

// ★ A VALIDLY SIGNED PLAN FOR SOMEBODY ELSE (second review). The Edge signs one plan per device and each names
// its addressee, so a plan issued for a device in an earlier wave can be dropped onto a later one to authorise
// it early. The signature does not help: it is a real plan, for another machine.
func TestAPlanAddressedToAnotherDeviceCannotOpenThisOnesWave(t *testing.T) {
	plan := RolloutPlan{
		EligibleSince:  "2026-01-01T00:00:00Z",
		TargetVersion:  "0.2.0",
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		DeviceIdentity: "mac-pilot-1",
		TenantID:       "tenant-a",
	}
	path := planFile(t, plan)
	exp := RolloutExpectation{Version: "0.2.0", MaxAge: DefaultPlanMaxAge,
		DeviceIdentity: "mac-lab-9", TenantID: "tenant-a"}

	r, err := LoadRollout(path, nil, time.Now(), exp)
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.EligibleSince.IsZero() {
		t.Fatal("another device's plan opened this device's wave")
	}
	if !strings.Contains(r.WaveWithheld, "mac-pilot-1") || !strings.Contains(r.WaveWithheld, "mac-lab-9") {
		t.Errorf("the reason must name both devices, got %q", r.WaveWithheld)
	}

	// Its own plan still works.
	exp.DeviceIdentity = "mac-pilot-1"
	if r, _ = LoadRollout(path, nil, time.Now(), exp); r.EligibleSince.IsZero() {
		t.Fatal("a device's own plan must still open its wave")
	}

	// ★ And a device that cannot know its own identity says so rather than quietly passing.
	exp.DeviceIdentity = ""
	r, _ = LoadRollout(path, nil, time.Now(), exp)
	if !strings.Contains(r.Source, "could not confirm the plan is addressed to it") {
		t.Errorf("an unrunnable check must be visible, got %q", r.Source)
	}
}

// The tenant is the coarser half of the same binding.
func TestAPlanFromAnotherTenantCannotOpenAWave(t *testing.T) {
	plan := RolloutPlan{EligibleSince: "2026-01-01T00:00:00Z", TargetVersion: "0.2.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), TenantID: "tenant-a"}
	r, err := LoadRollout(planFile(t, plan), nil, time.Now(), RolloutExpectation{
		Version: "0.2.0", MaxAge: DefaultPlanMaxAge, TenantID: "tenant-b"})
	if err != nil {
		t.Fatalf("LoadRollout: %v", err)
	}
	if !r.EligibleSince.IsZero() || !strings.Contains(r.WaveWithheld, "tenant-a") {
		t.Fatalf("a plan from another tenant opened a wave: %+v", r)
	}
}

// ★ ONE MISDELIVERED PLAN WAS A PERMANENT FREEZE (2026-08-13, twenty-ninth review). The replay floor is a
// one-way ratchet, and it moved for any plan that parsed — including one addressed to another device. A
// correctly signed, newer plan meant for somebody else raised this device's floor above its own plan, and
// every legitimate plan afterwards tripped the replay guard.
func TestAPlanForAnotherDeviceDoesNotMoveTheReplayFloor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	generated := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	plan := RolloutPlan{SchemaVersion: RolloutPlanSchema, DeviceIdentity: "someone-else",
		GeneratedAt: generated.Format(time.RFC3339)}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadRollout(path, nil, generated, RolloutExpectation{DeviceIdentity: "win-dev-1"})
	if err != nil {
		t.Fatal(err)
	}

	if got.WaveWithheld == "" {
		t.Fatal("a plan for another device opened this one's wave")
	}
	if !got.PlanGeneratedAt.IsZero() {
		t.Fatalf("the floor moved to %s for a plan this device may not act on: its own plan is now older than "+
			"the ratchet and freezes for ever", got.PlanGeneratedAt)
	}
}

// The device's OWN plan still moves the floor, or the replay defence stops existing.
func TestThisDevicesOwnPlanStillMovesTheFloor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	generated := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	plan := RolloutPlan{SchemaVersion: RolloutPlanSchema, DeviceIdentity: "win-dev-1",
		GeneratedAt: generated.Format(time.RFC3339)}
	raw, _ := json.Marshal(plan)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadRollout(path, nil, generated, RolloutExpectation{DeviceIdentity: "win-dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanGeneratedAt.IsZero() {
		t.Fatal("this device's own plan did not move the floor, so a replayed older plan would be accepted")
	}
}

// ★★ ANOTHER DEVICE'S OLD PLAN IS NOT A REPLAY OF THIS DEVICE'S HISTORY (2026-08-13, thirtieth review #18).
// The twenty-ninth review established that a plan addressed elsewhere must not move this device's replay
// floor, and put that check BELOW the replay branch — which therefore still fired first. A single misdelivered
// file froze the machine, and since the same round it does so with ErrPlanUnverifiable, which says "you were
// attacked" about somebody's routing mistake.
func TestAnOldPlanForAnotherDeviceDoesNotFreezeThisOne(t *testing.T) {
	now := time.Now().UTC()
	plan := RolloutPlan{
		SchemaVersion:  RolloutPlanSchema,
		DeviceIdentity: "some-other-mac",
		TargetVersion:  "0.2.9",
		GeneratedAt:    now.Add(-48 * time.Hour).Format(time.RFC3339),
	}
	exp := RolloutExpectation{
		DeviceIdentity: "this-mac",
		Version:        "0.2.9",
		NotBefore:      now.Add(-time.Hour), // this device has accepted something much newer
	}

	out, err := decideRollout(plan, "plan.json", now, exp, "test")
	if err != nil {
		t.Fatalf("a plan for another device was treated as unverifiable: %v", err)
	}
	if out.Frozen {
		t.Fatal("another device's misdelivered plan froze this one — one wrong file is a denial of service")
	}
	if out.WaveWithheld == "" {
		t.Fatal("it must still refuse to OPEN this device's wave; only the freeze was wrong")
	}
	if !out.PlanGeneratedAt.IsZero() {
		t.Fatal("a plan addressed elsewhere moved this device's replay floor")
	}
}

// And a genuine replay — the same device, an older document — must still be refused, loudly and as an attack.
func TestAReplayOfThisDevicesOwnPlanIsStillRefused(t *testing.T) {
	now := time.Now().UTC()
	plan := RolloutPlan{
		SchemaVersion:  RolloutPlanSchema,
		DeviceIdentity: "this-mac",
		TargetVersion:  "0.2.9",
		GeneratedAt:    now.Add(-48 * time.Hour).Format(time.RFC3339),
	}
	exp := RolloutExpectation{DeviceIdentity: "this-mac", Version: "0.2.9", NotBefore: now.Add(-time.Hour)}

	out, err := decideRollout(plan, "plan.json", now, exp, "test")
	if !errors.Is(err, ErrPlanUnverifiable) {
		t.Fatalf("a replay must be distinguishable from an authored halt: err=%v", err)
	}
	if !out.Frozen {
		t.Fatal("a replay must freeze")
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func writeControl(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rollout.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ★ An absent file is NOT a freeze. A deployment that never configured waves must not be halted by the absence
// of a document nobody told it to write — that would make this feature's arrival a fleet-wide outage.
func TestNoRolloutControlFileMeansNoWavesAndNoFreeze(t *testing.T) {
	rc, err := loadRolloutControl(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("an absent control file must not be an error: %v", err)
	}
	if rc.Frozen {
		t.Fatal("an absent control file froze the fleet")
	}
	if len(rc.Waves.Waves) != 0 {
		t.Fatal("waves appeared from nowhere")
	}
}

// ★ And a BROKEN file IS a freeze. The operator editing this file is plausibly halting a bad release at that
// very moment; a JSON typo must not be the thing that lets the release keep going.
func TestABrokenRolloutControlFileFreezesRatherThanFailingOpen(t *testing.T) {
	rc, err := loadRolloutControl(writeControl(t, `{"frozen": tru`))
	if err == nil {
		t.Fatal("a malformed control file was accepted")
	}
	if !rc.Frozen {
		t.Fatal("a malformed control file did not freeze; the halt is least reliable exactly when it is in use")
	}
	if !strings.Contains(rc.FrozenReason, "unreadable") {
		t.Fatalf("the device must be told why it is held, got %q", rc.FrozenReason)
	}
}

// A schedule that cannot mean what its author intended is the same case: held, and said.
func TestAnInvalidWaveScheduleFreezes(t *testing.T) {
	rc, err := loadRolloutControl(writeControl(t, `{"waves":{"waves":[{"group":"pilot","delay_days":-1}]}}`))
	if err == nil {
		t.Fatal("a negative delay was accepted")
	}
	if !rc.Frozen {
		t.Fatal("an invalid schedule did not freeze")
	}
}

// A field nobody implemented is refused rather than ignored, for the same reason the manifest refuses one: an
// ignored field is a setting an operator believes is in effect and is not. On THIS file that setting could be
// the freeze.
func TestAnUnknownRolloutControlFieldIsRefused(t *testing.T) {
	rc, err := loadRolloutControl(writeControl(t, `{"frozen":false,"halt":true}`))
	if err == nil {
		t.Fatal("an unrecognised field was ignored")
	}
	if !rc.Frozen {
		t.Fatal("a file whose freeze may have been misspelled must hold the fleet, not release it")
	}
}

func TestAFreezeIsCarriedWithItsReason(t *testing.T) {
	rc, err := loadRolloutControl(writeControl(t, `{"frozen":true,"frozen_reason":"0.2.0 bricked the pilot ring"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !rc.Frozen || rc.FrozenReason == "" {
		t.Fatalf("got %+v", rc)
	}
}

// The wave start is what only the control plane can compute, and the endpoint's whole reason for being
// device-identified. Checked here at the layer that does the arithmetic.
func TestTheWaveStartIsTheReleaseTimePlusTheGroupsDelay(t *testing.T) {
	rc, err := loadRolloutControl(writeControl(t,
		`{"waves":{"waves":[{"group":"pilot","delay_days":0,"priority":10},{"group":"finance","delay_days":5}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	released := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

	// A pilot machine that is also in finance starts on day 0: priority is the admin saying which membership
	// speaks for the device, and without it the ring that exists to catch bad builds early never runs early.
	start, a := rc.Waves.WaveStart([]string{"finance", "pilot"}, released)
	if !start.Equal(released) {
		t.Fatalf("pilot start = %s, want %s (%s)", start, released, a.Reason)
	}
	if !strings.Contains(a.Reason, "pilot") || !strings.Contains(a.Reason, "finance") {
		t.Fatalf("the reason must name the winner AND what it outranked, got %q", a.Reason)
	}

	// A device in no scheduled group takes the SLOWEST wave, not the fastest: an admin who adds a group and
	// forgets to schedule it must not have created a same-day fleet-wide rollout by omission.
	late, _ := rc.Waves.WaveStart([]string{"unlisted"}, released)
	if !late.Equal(released.AddDate(0, 0, 5)) {
		t.Fatalf("unscheduled group start = %s, want day 5", late)
	}
}

// With nothing published there is no release instant, so there is no wave — and the field must be OMITTED
// rather than zeroed. A device reading eligible_since=0001-01-01 would treat its wave as long since open.
func TestNoPublishedReleaseMeansNoWaveStartAtAll(t *testing.T) {
	var s agentrollout.WaveSchedule
	start, _ := s.WaveStart([]string{"pilot"}, time.Time{})
	if !start.IsZero() {
		t.Fatalf("a zero release time produced a wave start of %s", start)
	}
}

// ★ The document the Edge signs must be the one the device can decode, field for field. They are in different
// modules and a mismatch is silent in the worst way: a field the Edge sets and the device drops is a control an
// operator believes is in effect, and on this document that could be the freeze.
func TestTheSignedPlanRoundTripsThroughTheDevicesOwnDecoder(t *testing.T) {
	sent := agentupdate.RolloutPlan{
		SchemaVersion: agentupdate.RolloutPlanSchema,
		TenantID:      "tenant_lab",
		Frozen:        true,
		FrozenReason:  "0.2.0 bricked the pilot ring",
		EligibleSince: "2026-08-15T02:00:00Z",
		WaveReason:    "group \"finance\", day 5",
		TargetVersion: "0.2.0",
		Window:        &agentupdate.PlanWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true, DeadlineDays: 14},
	}
	b, err := json.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := agentupdate.DecodeRolloutPlan(b)
	if err != nil {
		t.Fatalf("the device could not decode what this edge would sign: %v", err)
	}
	if got.Frozen != sent.Frozen || got.FrozenReason != sent.FrozenReason {
		t.Fatalf("the freeze did not survive: %+v", got)
	}
	if got.EligibleSince != sent.EligibleSince || got.Window == nil || got.Window.LocalStart != "02:00" {
		t.Fatalf("plan did not round trip: %+v", got)
	}
	if _, terr := got.EligibleSinceTime(); terr != nil {
		t.Fatalf("the wave start this edge wrote is not parseable by the device: %v", terr)
	}
}

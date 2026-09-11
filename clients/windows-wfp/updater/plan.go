package main

// plan.go — the local, unsigned half of an update: WHEN this device may act.
//
// The manifest says WHAT and is immutable per release; this says WHEN and changes independently. Putting a
// time window inside the manifest would mean re-signing a release to move a maintenance slot.
//
// WHERE THE MANIFEST COMES FROM is deliberately not here any more: updateplatform.FileManifestSource owns it,
// and its reasoning — the signature is the trust boundary, not the channel — is the same conclusion this file
// reached independently before the two were merged.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// Plan is the local, unsigned half: WHEN this device may update.
//
// Unsigned deliberately, and the reasoning should be checked rather than assumed. The plan cannot authorise an
// installation — only a signed manifest names a version, and only its digest names the bytes. The worst a
// hostile plan achieves is making an ALREADY AUTHORISED update happen sooner than the operator intended, and
// writing it requires the administrator rights that would let someone run the installer directly. Signing it
// would protect against nothing that is not already lost.
//
// It is separate from the manifest because the manifest is immutable per release: putting a time window inside
// it would mean re-signing a release to move a maintenance slot.
type Plan struct {
	LocalStart         string `json:"local_start"`
	LocalEnd           string `json:"local_end"`
	RequireIdleMinutes int    `json:"require_idle_minutes"`
	RequireUnattended  bool   `json:"require_unattended"`
	RequireACPower     bool   `json:"require_ac_power"`
	DeadlineDays       int    `json:"deadline_days"`
	MaxAttempts        int    `json:"max_attempts"`
}

// DefaultPlan is what a device uses when no plan has been delivered.
//
// The defaults are the cautious end of every axis except one. A night window, unattended required, AC
// required — and a DEADLINE, because the alternative is a device that waits forever while a console shows it
// as managed. A machine nobody ever locks, or one that lives on battery, would otherwise sit on an old build
// indefinitely and look configured while doing it.
//
// RequireIdleMinutes is deliberately 0 in the default: on Windows it is currently unsatisfiable (LastInputTime
// is zero for the console session, measured on win-dev-1), so a non-zero default would ship a fleet that can
// only ever update at its deadline. RequireUnattended asks the same operator question in the form this
// platform can actually answer.
func DefaultPlan() Plan {
	return Plan{
		LocalStart:        "02:00",
		LocalEnd:          "04:00",
		RequireUnattended: true,
		RequireACPower:    true,
		DeadlineDays:      14,
		MaxAttempts:       agentupdate.DefaultMaxAttempts,
	}
}

// LoadPlan reads a plan file. A missing file yields the default, which is how an un-provisioned device behaves
// sensibly rather than not at all. A CORRUPT file is an error: falling back to the default there would
// silently substitute a window nobody wrote for one somebody did.
func LoadPlan(path string) (Plan, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultPlan(), nil
	}
	if err != nil {
		return Plan{}, err
	}
	p := DefaultPlan()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Plan{}, fmt.Errorf("plan %s is unreadable (%w); refusing to substitute the default window for one an "+
			"operator wrote", path, err)
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = agentupdate.DefaultMaxAttempts
	}
	return p, nil
}

// Window converts the plan into what the gate consumes.
func (p Plan) Window() agentupdate.MaintenanceWindow {
	return agentupdate.MaintenanceWindow{
		LocalStart:         p.LocalStart,
		LocalEnd:           p.LocalEnd,
		RequireIdleMinutes: p.RequireIdleMinutes,
		RequireUnattended:  p.RequireUnattended,
		RequireACPower:     p.RequireACPower,
		DeadlineDays:       p.DeadlineDays,
	}
}

// Rollout, LoadRollout and the freeze rule moved to agentupdate — see agentupdate.LoadRollout.
//
// Both platforms need them identically, and the decision inside (what an UNVERIFIABLE plan means) must not be
// answered twice: a second answer is a platform where damaging the plan lifts the halt. Plan stays here
// because it is this endpoint's LOCAL file — the fallback window, and MaxAttempts, which the fleet plan does
// not carry.

// Apply folds the rollout's window over the local plan. Fields the rollout does not carry keep the local
// value: a plan that only sets `frozen` must not silently rewrite the device's schedule to midnight-to-midnight.
func (p Plan) Apply(r agentupdate.Rollout) Plan {
	w := r.Plan.Window
	if w == nil {
		return p
	}
	// ★ THE RULE ITSELF LIVES IN agentupdate (2026-08-13, thirtieth review #22). It was written out here and in
	// the other platform's file, in the same words, after the twenty-ninth review found that a plan carrying
	// nothing but a window zeroed the safety gates. Two copies of a rule are two places for the next one to
	// land, and this lane's history is rules that shipped on one OS.
	merged := agentupdate.RaiseWindow(p.Window(), *w)
	out := p
	out.LocalStart = merged.LocalStart
	out.LocalEnd = merged.LocalEnd
	out.RequireIdleMinutes = merged.RequireIdleMinutes
	out.RequireUnattended = merged.RequireUnattended
	out.RequireACPower = merged.RequireACPower
	out.DeadlineDays = merged.DeadlineDays
	return out
}

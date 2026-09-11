package agentupdate

// plan.go — the rollout plan document: WHEN a device may install, as opposed to WHAT.
//
// It lives here, beside the manifest, because both ends of the wire have to agree on it byte for byte and they
// are in different modules: the Edge mints and signs it, the device verifies and applies it. Two hand-written
// structs would drift, and the failure would be silent in the worst possible way — a field the Edge sets and
// the device ignores is a control an operator believes is in effect and is not, and one of these fields is the
// FREEZE.
//
// WHY IT IS NOT PART OF THE MANIFEST. The manifest is immutable per release and signed by a key no Edge holds.
// This changes independently of any release — a maintenance window moves, a rollout halts — and re-signing a
// release to move a time slot would be absurd. They are also under DIFFERENT KEYS on purpose: an Edge may
// decide when a fleet updates and must never be able to decide what it runs.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RolloutPlanSchema names the payload. The device checks it before anything else, because one signing key
// legitimately signs several documents on this surface — a steering posture accepted as a rollout plan would
// be an unfrozen fleet with no field saying so.
const RolloutPlanSchema = "dsse.agent-update-plan.v1"

// RolloutPlanEnvelopeType is the plan's own ENVELOPE type.
//
// ★ It has one for the same reason the manifest does, and it did not at first — the plan was signed under the
// steer-policy type because it reuses that signer. The payload's schema_version would still have caught a
// substitution (DecodeRolloutPlan refuses a schema it does not know), so nothing was exploitable; but that
// leaves the type check doing no work on a document whose whole purpose is to carry a FREEZE, and it makes the
// envelope indistinguishable from an exclusion policy signed by the same key. One signing key legitimately
// signs several documents on this surface, and the type is the field that says which — so it should say it
// rather than being a coincidence of which struct happened to decode.
const RolloutPlanEnvelopeType = "dsse_agent_update_plan.v1"

// RolloutPlan is the signed statement of when this device may act.
type RolloutPlan struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id,omitempty"`
	DeviceIdentity string `json:"device_identity,omitempty"`

	// Frozen halts this device. The WITHDRAWAL mechanism: a release found bad after it shipped is stopped by
	// setting this, because un-publishing its manifest cannot reach a device that already holds one.
	Frozen bool `json:"frozen"`
	// FrozenReason travels with it so "waiting: the rollout is frozen" is not the whole sentence. Without it an
	// operator goes looking for a fault, and this is a decision.
	FrozenReason string `json:"frozen_reason,omitempty"`

	// EligibleSince is this device's wave start, RFC3339. Only the control plane can compute it — the release
	// time, the device's group memberships and the wave schedule are needed together.
	//
	// EMPTY means no schedule, which is deliberately not the same as the zero time: a device reading
	// "0001-01-01" would treat its wave as long since open.
	EligibleSince string `json:"eligible_since,omitempty"`
	// WaveReason explains the assignment. "Why is this machine still on the old build" is the question this
	// feature generates, and "day 5" without "because it is in finance, which outranks its membership in pilot"
	// sends an admin to the wrong place.
	WaveReason string `json:"wave_reason,omitempty"`
	// TargetVersion is what the wave was computed against, so a device can tell a stale plan from a current one.
	TargetVersion string `json:"target_version,omitempty"`

	// Window is the tenant's maintenance window. A nil window means the device keeps its own default rather
	// than being handed an empty one — a plan that only sets `frozen` must not silently rewrite everyone's
	// schedule to midnight-to-midnight.
	Window *PlanWindow `json:"window,omitempty"`

	GeneratedAt string `json:"generated_at,omitempty"`
}

// PlanWindow is the operator's answer to "when may this run", in DEVICE-local wall clock.
type PlanWindow struct {
	LocalStart         string `json:"local_start"`
	LocalEnd           string `json:"local_end"`
	RequireIdleMinutes int    `json:"require_idle_minutes"`
	RequireUnattended  bool   `json:"require_unattended"`
	RequireACPower     bool   `json:"require_ac_power"`
	DeadlineDays       int    `json:"deadline_days"`
}

// DecodeRolloutPlan reads a plan payload strictly.
//
// Unknown fields are REFUSED, the same rule the manifest follows and for a sharper reason here: an ignored
// field is a setting the operator believes is in effect, and on this document that could be the halt. A device
// that silently drops `frozen` because it arrived under a name this build does not know would keep installing
// a release somebody stopped.
func DecodeRolloutPlan(payload []byte) (RolloutPlan, error) {
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	var p RolloutPlan
	if err := dec.Decode(&p); err != nil {
		return RolloutPlan{}, fmt.Errorf("rollout plan is malformed: %w", err)
	}
	if dec.More() {
		return RolloutPlan{}, fmt.Errorf("rollout plan has trailing content")
	}
	if p.SchemaVersion != RolloutPlanSchema {
		return RolloutPlan{}, fmt.Errorf("rollout plan schema %q, want %q", p.SchemaVersion, RolloutPlanSchema)
	}
	if _, err := p.EligibleSinceTime(); err != nil {
		return RolloutPlan{}, err
	}
	return p, nil
}

// EligibleSinceTime parses the wave start. An unparseable value is an ERROR rather than "no schedule":
// treating it as absent would turn a control-plane bug into every device quietly ignoring its wave, which is
// the same fleet-wide same-day rollout the waves exist to prevent.
func (p RolloutPlan) EligibleSinceTime() (time.Time, error) {
	if strings.TrimSpace(p.EligibleSince) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, p.EligibleSince)
	if err != nil {
		return time.Time{}, fmt.Errorf("rollout plan eligible_since %q is not RFC3339: %w", p.EligibleSince, err)
	}
	return t, nil
}

// RaiseWindow folds a fleet plan's window over a device's local one: times are taken when the plan states
// them, and the SAFETY GATES are raised, never lowered.
//
// ★★ ONE IMPLEMENTATION, BECAUSE THE RULE WAS PATCHED INTO BOTH AGENTS BY HAND (2026-08-13, thirtieth review
// #22). The twenty-ninth review found that a plan carrying nothing but a window — the ordinary shape — zeroed
// RequireIdleMinutes, RequireUnattended and RequireACPower, so an install ran while somebody was typing, on
// battery. The fix was written twice, in the same words, in two files. The review's point about that is the
// operative one: the NEXT window rule ships on one platform unless the rule itself lives somewhere both import.
//
// The absence of a field in a document is not an instruction to remove a protection the device already had. A
// plan that genuinely wants a WEAKER gate has to say so, and there is deliberately no way to say it: the
// device's local defaults are the floor.
func RaiseWindow(local MaintenanceWindow, plan PlanWindow) MaintenanceWindow {
	out := local
	// Times are a schedule, not a protection: an operator moving the window is moving it, and a plan that does
	// not state one leaves the device's own.
	if strings.TrimSpace(plan.LocalStart) != "" {
		out.LocalStart = plan.LocalStart
	}
	if strings.TrimSpace(plan.LocalEnd) != "" {
		out.LocalEnd = plan.LocalEnd
	}
	if plan.RequireIdleMinutes > out.RequireIdleMinutes {
		out.RequireIdleMinutes = plan.RequireIdleMinutes
	}
	if plan.RequireUnattended {
		out.RequireUnattended = true
	}
	if plan.RequireACPower {
		out.RequireACPower = true
	}
	// A deadline is how long the gates may hold an update back. Raising it is not a safety decision the device
	// should refuse, and 0 means the plan does not state one.
	if plan.DeadlineDays > 0 {
		out.DeadlineDays = plan.DeadlineDays
	}
	return out
}

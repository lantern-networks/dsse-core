package agentupdate

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// gate.go — when may a verified update actually run?
//
// This is the `armed` stage of the state machine: the manifest has been verified and the artifact's digest
// checked, and what remains is the operator's answer to "not during the working day". The requirement is
// plain — update at night, when the machine is idle — and every awkward part of it comes from the fact that
// waiting is not free: a device that waits forever is a device that never gets the fix.
//
// Two rules shape everything below.
//
// The window is evaluated in the DEVICE's local time, not the tenant's. Once a fleet crosses a timezone, a
// UTC window is somebody's midday. Only the device knows what midnight means for its user.
//
// Every wait has a deadline. A laptop closed at 03:00 never enters its window; a machine in constant use
// never goes idle; a desktop whose power state cannot be read never confirms AC. Each of those is a device
// that silently stays on an old build while the console shows a configured maintenance window — which reads
// as "managed" and is not. So every reason to wait is also counted, reported, and eventually overridden.

// MaintenanceWindow is the operator's answer to "when may this run", carried in the rollout plan rather than
// in the signed manifest: the manifest says WHAT to install and is immutable per release, while this says
// WHEN and changes independently. Re-signing a release to move a time slot would be absurd.
type MaintenanceWindow struct {
	// LocalStart / LocalEnd are device-local wall clock, "HH:MM". Equal values mean "no window" (always
	// eligible). A start later than the end wraps past midnight, which is the common case for a night window.
	LocalStart string
	LocalEnd   string
	// RequireIdleMinutes is how long since the last user input before the device counts as idle. 0 = do not
	// require idleness.
	RequireIdleMinutes int
	// RequireUnattended blocks the update while a person is at the machine — locked, disconnected, or nobody
	// logged on all count as unattended.
	//
	// It is a SEPARATE knob rather than something RequireIdleMinutes infers, because the two ask different
	// questions and, on Windows, only one of them is answerable. Measured on win-dev-1: a session's lock state
	// reads reliably from session 0, and LastInputTime comes back zero for the console session — so a window
	// written in minutes is unsatisfiable on a box that can say perfectly well whether anyone is at it. Folding
	// "unattended" into the minutes field would also make that number stop being a number: an operator who
	// wrote 30 would have no way to express "any lock will do".
	//
	// The honest limit, stated because it decides whether this is the right setting for a deployment: a
	// MANUAL lock may be five seconds old, so unattended does NOT imply idle-for-N. An auto-lock does imply
	// it, and nothing distinguishes the two after the fact. Operators who need the duration should set both.
	RequireUnattended bool
	// RequireACPower blocks an update while running on battery: losing power mid-install is how a machine ends
	// up neither on the old version nor the new one.
	RequireACPower bool
	// DeadlineDays bounds the waiting. After this long eligible-but-waiting, the update proceeds regardless of
	// window, idleness and power. 0 disables the deadline — which means a device CAN wait forever, so it is
	// not the default anyone should choose.
	DeadlineDays int
}

// DeviceConditions is what the device can observe about itself right now. Each signal is accompanied by
// whether it could be read at all, because "cannot tell" must not collapse into either answer — an idle check
// that silently reads as "idle" whenever it breaks would authorise updates during the working day.
type DeviceConditions struct {
	// LocalNow is the device's own wall clock, in its own location.
	LocalNow time.Time
	// IdleFor is time since the last user input; IdleKnown is false when it could not be determined.
	IdleFor   time.Duration
	IdleKnown bool
	// InUse is whether a person is at this machine, as a PREDICATE rather than a duration. InUseKnown is false
	// when it could not be determined.
	//
	// It exists because on Windows the duration is the part that cannot be measured and the predicate is the
	// part that can. Measured on win-dev-1: the terminal-services API reports a session's lock state reliably
	// from session 0, and reports LastInputTime as zero for the console session — so IdleKnown is false on a
	// box whose lock state is perfectly readable. Any gate written only in terms of IdleFor is therefore
	// unsatisfiable there, while the thing an operator meant by it is sitting right next to the number.
	//
	// The two are NOT redundant and neither implies the other. A locked session is not in use but says nothing
	// about for how long; an unlocked session idle for thirty minutes may be someone reading or presenting.
	//
	// It is consumed by RequireUnattended and by NOTHING ELSE. In particular it must never be allowed to
	// satisfy RequireIdleMinutes: that would loosen a check somebody deliberately turned on, as a side effect
	// of the platform learning to observe more. Two questions, two knobs, and an operator who wants both sets
	// both.
	//
	// ★ WHAT THIS FIELD MEANS, as opposed to how one platform answers it. A platform must set InUseKnown only
	// when it can speak for EVERY interactive session on the device, and InUse when it can see that a person
	// could be interrupted by an install right now. A session it cannot read is exactly the one that might have
	// someone at it, so partial knowledge is unknown, not "nobody". Windows answers from the terminal-services
	// session table (lock state, disconnected sessions, nobody logged on); macOS has the same question and a
	// different mechanism, and the rule above is what has to match — the correction learned on RunningVersion,
	// where the spec described a mechanism and the second platform then had none.
	//
	// Unknown is never permission. The guess being refused here is "nobody is here", which is the one that
	// restarts a machine under someone's hands.
	InUse      bool
	InUseKnown bool
	// OnACPower / PowerKnown, same three-state treatment.
	OnACPower  bool
	PowerKnown bool
	// EligibleSince is when this update first became applicable to this device. The deadline is measured from
	// here, so it counts the whole time the device has been waiting rather than restarting each tick.
	EligibleSince time.Time
	// Frozen is the incident halt from the rollout plan.
	Frozen bool
	// PlanHold is a non-empty reason why this device's plan may not AUTHORISE an install, even though it is
	// not a halt somebody ordered.
	//
	// ★ IT IS A SEPARATE FIELD BECAUSE ZEROING A WAVE START DOES NOT HOLD ANYTHING (2026-08-11, from a review
	// of the fix that was supposed to). A plan that cannot authorise this release had its EligibleSince cleared
	// — and Run replaces a zero wave start with the attempt's own start time, precisely so a device with no
	// schedule is not stuck forever. So the "withheld" wave became a log line and the install proceeded at the
	// next maintenance window. A refusal that is not a value the gate reads is a refusal that does not happen.
	PlanHold string
}

// Wait reasons, reported so an operator can see WHY a device is still on the old build. A device that has
// been waiting for a week on "asleep" and one waiting on "busy" need different responses.
const (
	WaitFrozen = "frozen"
	// WaitPlanHold is a device whose plan cannot authorise the release it is being offered — a different
	// release, a stale plan, one with no generation time, or one from the future.
	WaitPlanHold     = "plan_cannot_authorise"
	WaitOutOfWindow  = "out_of_window"
	WaitBusy         = "busy"
	WaitIdleUnknown  = "idle_unknown"
	WaitOnBattery    = "on_battery"
	WaitPowerUnknown = "power_unknown"
	// Distinct from WaitBusy/WaitIdleUnknown on purpose: those mean "the idle CLOCK says no", these mean "a
	// person is there". A fleet waiting on in_use and one waiting on idle_unknown need opposite responses —
	// the first is working as intended, the second is a device that cannot measure itself.
	WaitInUse        = "in_use"
	WaitInUseUnknown = "in_use_unknown"
	// WaitNotYetInWave is a device whose group's rollout wave has not started. It is not a problem and must
	// not read as one: a fleet sitting on this is a staggered rollout working exactly as designed, whereas a
	// fleet sitting on out_of_window or in_use may be one that will never update.
	WaitNotYetInWave = "not_yet_in_wave"
)

// GateDecision is the answer, plus enough context to report it.
type GateDecision struct {
	Proceed bool
	// WaitReason is one of the Wait* constants when Proceed is false, and empty otherwise.
	WaitReason string
	// ForcedByDeadline is true when the update is proceeding DESPITE a condition that would otherwise hold it.
	// It is surfaced separately because "we updated your machine mid-afternoon" needs to be explainable.
	ForcedByDeadline bool
	// Detail is the human sentence for the log/report.
	Detail string
}

// EvaluateGate decides whether a verified update may execute now.
//
// Order is deliberate. Freeze is checked first and is never overridden: an incident halt that only takes
// effect at the next maintenance window is not a halt. The deadline is checked second, so a device that has
// waited too long stops accumulating reasons and simply proceeds. Everything after that is the ordinary
// "is it a good moment" test.
func EvaluateGate(w MaintenanceWindow, c DeviceConditions) GateDecision {
	// Ordered BEFORE the freeze so the more specific reason wins: "this plan cannot authorise the release you
	// are being offered" sends someone to the courier, and "frozen" sends them to the control plane.
	if h := strings.TrimSpace(c.PlanHold); h != "" {
		return GateDecision{WaitReason: WaitPlanHold, Detail: h}
	}
	if c.Frozen {
		// Deliberately above the deadline check: freeze outranks everything, including a device that has been
		// waiting a month. The operator halting a rollout means it stops now.
		return GateDecision{WaitReason: WaitFrozen, Detail: "rollout is frozen; no device moves until the freeze is lifted"}
	}

	// A device has not become eligible yet: its group's wave has not started.
	//
	// Checked HERE, above the deadline, and returning immediately. The deadline arithmetic would already
	// decline to fire (it measures from EligibleSince, so the elapsed time is negative before it), but that is
	// a coincidence of the formula rather than a rule, and this is not a property to leave resting on one. A
	// staggered rollout whose later waves could be pulled forward by any mechanism is not staggered — the
	// point of the second wave is that somebody gets to look at the first one before it starts.
	if !c.EligibleSince.IsZero() && c.LocalNow.Before(c.EligibleSince) {
		return GateDecision{
			WaitReason: WaitNotYetInWave,
			Detail: fmt.Sprintf("this device's rollout wave starts %s (device-local %s); %s remain",
				c.EligibleSince.Format("2006-01-02 15:04"), c.LocalNow.Format("2006-01-02 15:04"),
				c.EligibleSince.Sub(c.LocalNow).Round(time.Minute)),
		}
	}

	held, reason, detail := windowHolds(w, c)
	if !held {
		return GateDecision{Proceed: true, Detail: detail}
	}

	if past, waited := deadlinePassed(w, c); past {
		return GateDecision{
			Proceed:          true,
			ForcedByDeadline: true,
			Detail: fmt.Sprintf("proceeding despite %s: this device has been eligible and waiting for %s, past the %d-day deadline. "+
				"Waiting longer would mean never updating it", reason, waited.Round(time.Hour), w.DeadlineDays),
		}
	}
	return GateDecision{WaitReason: reason, Detail: detail}
}

// windowHolds reports whether some condition is holding the update back, and why. Returns held=false when
// everything is satisfied.
func windowHolds(w MaintenanceWindow, c DeviceConditions) (held bool, reason, detail string) {
	if in, err := inLocalWindow(w.LocalStart, w.LocalEnd, c.LocalNow); err != nil {
		// A malformed window must NOT read as "always allowed". An operator who typed the time wrongly gets a
		// device that waits and says so, not one that updates at noon.
		return true, WaitOutOfWindow, fmt.Sprintf("maintenance window is unusable (%v); holding until it is corrected", err)
	} else if !in {
		return true, WaitOutOfWindow, fmt.Sprintf("outside the maintenance window %s-%s (device-local %s %s)",
			w.LocalStart, w.LocalEnd, c.LocalNow.Format("15:04"), c.LocalNow.Format("MST"))
	}

	if w.RequireIdleMinutes > 0 {
		need := time.Duration(w.RequireIdleMinutes) * time.Minute
		switch {
		case !c.IdleKnown:
			// Unknown is NOT idle. An idle check that fails open updates machines while someone is typing on
			// them — and on Windows a session-0 service reading GetLastInputInfo gets exactly that answer
			// forever, which is why this is spelled out rather than assumed.
			return true, WaitIdleUnknown, "cannot determine how long this device has been idle; not updating a device that may be in use"
		case c.IdleFor < need:
			return true, WaitBusy, fmt.Sprintf("in use: idle for %s, need %s", c.IdleFor.Round(time.Second), need)
		}
	}

	if w.RequireUnattended {
		switch {
		case !c.InUseKnown:
			// Same rule as idle and power: unknown is not permission. The guess this refuses to make is
			// "nobody is here", which is the one that restarts a machine under someone's hands.
			return true, WaitInUseUnknown, "cannot determine whether anyone is using this device; not updating a device that may be in use"
		case c.InUse:
			return true, WaitInUse, "someone is using this device (an interactive session is unlocked and connected)"
		}
	}

	if w.RequireACPower {
		switch {
		case !c.PowerKnown:
			return true, WaitPowerUnknown, "cannot determine whether this device is on mains power; not risking an install that loses power part-way"
		case !c.OnACPower:
			return true, WaitOnBattery, "running on battery"
		}
	}

	return false, "", fmt.Sprintf("inside the maintenance window %s-%s (device-local %s %s) and all conditions met",
		w.LocalStart, w.LocalEnd, c.LocalNow.Format("15:04"), c.LocalNow.Format("MST"))
}

// deadlinePassed reports whether this device has waited long enough that the window stops applying.
func deadlinePassed(w MaintenanceWindow, c DeviceConditions) (bool, time.Duration) {
	if w.DeadlineDays <= 0 || c.EligibleSince.IsZero() {
		return false, 0
	}
	waited := c.LocalNow.Sub(c.EligibleSince)
	return waited >= time.Duration(w.DeadlineDays)*24*time.Hour, waited
}

// inLocalWindow reports whether now's wall-clock time falls inside [start, end).
//
// Equal start and end means "no window" — always inside. A start after the end wraps past midnight, which is
// what a night window looks like and would otherwise be an empty set.
func inLocalWindow(start, end string, now time.Time) (bool, error) {
	s, err := parseHHMM(start)
	if err != nil {
		return false, fmt.Errorf("start %q: %w", start, err)
	}
	e, err := parseHHMM(end)
	if err != nil {
		return false, fmt.Errorf("end %q: %w", end, err)
	}
	cur := now.Hour()*60 + now.Minute()
	switch {
	case s == e:
		return true, nil // no window configured
	case s < e:
		return cur >= s && cur < e, nil
	default:
		return cur >= s || cur < e, nil // wraps midnight
	}
}

func parseHHMM(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("empty")
	}
	h, m, ok := strings.Cut(v, ":")
	if !ok {
		return 0, fmt.Errorf("want HH:MM")
	}
	hh, herr := strconv.Atoi(h)
	mm, merr := strconv.Atoi(m)
	if herr != nil || merr != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("want HH:MM in 00:00..23:59")
	}
	return hh*60 + mm, nil
}

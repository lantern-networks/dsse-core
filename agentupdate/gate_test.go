package agentupdate

import (
	"strings"
	"testing"
	"time"
)

func nightWindow() MaintenanceWindow {
	return MaintenanceWindow{LocalStart: "02:00", LocalEnd: "05:00", RequireIdleMinutes: 15, RequireACPower: true, DeadlineDays: 7}
}

// at builds device conditions at a device-local wall-clock time, idle and on mains, eligible since "ago".
func at(hhmm string, ago time.Duration) DeviceConditions {
	t, err := time.Parse("15:04", hhmm)
	if err != nil {
		panic(err)
	}
	now := time.Date(2026, 8, 9, t.Hour(), t.Minute(), 0, 0, time.UTC)
	return DeviceConditions{
		LocalNow: now, IdleFor: time.Hour, IdleKnown: true,
		OnACPower: true, PowerKnown: true, EligibleSince: now.Add(-ago),
	}
}

func TestProceedsAtNightWhenIdleAndOnMains(t *testing.T) {
	d := EvaluateGate(nightWindow(), at("03:00", time.Hour))
	if !d.Proceed {
		t.Fatalf("should proceed: %s", d.Detail)
	}
	if d.ForcedByDeadline {
		t.Fatal("this is the normal path, not a deadline override")
	}
}

func TestHoldsDuringTheWorkingDay(t *testing.T) {
	d := EvaluateGate(nightWindow(), at("14:00", time.Hour))
	if d.Proceed {
		t.Fatal("must not update in the afternoon")
	}
	if d.WaitReason != WaitOutOfWindow {
		t.Fatalf("reason = %q, want %q", d.WaitReason, WaitOutOfWindow)
	}
	// The report has to carry the device-local time, so a timezone or clock problem is visible rather than
	// looking like the window being ignored.
	if !strings.Contains(d.Detail, "14:00") {
		t.Fatalf("detail must state the device-local time, got %q", d.Detail)
	}
}

// A night window normally crosses midnight. Treating start>end as an empty set would make the most common
// configuration never fire.
func TestAWindowThatCrossesMidnightWorks(t *testing.T) {
	w := nightWindow()
	w.LocalStart, w.LocalEnd = "22:00", "05:00"
	for _, in := range []string{"22:00", "23:30", "00:10", "04:59"} {
		if d := EvaluateGate(w, at(in, time.Hour)); !d.Proceed {
			t.Errorf("%s should be inside 22:00-05:00: %s", in, d.Detail)
		}
	}
	for _, out := range []string{"05:00", "12:00", "21:59"} {
		if d := EvaluateGate(w, at(out, time.Hour)); d.Proceed {
			t.Errorf("%s should be outside 22:00-05:00", out)
		}
	}
}

func TestEqualStartAndEndMeansNoWindow(t *testing.T) {
	w := nightWindow()
	w.LocalStart, w.LocalEnd = "00:00", "00:00"
	if d := EvaluateGate(w, at("14:00", time.Hour)); !d.Proceed {
		t.Fatalf("an unconfigured window must not block: %s", d.Detail)
	}
}

// ★ Unknown is not idle, and unknown is not on-mains. An idle check that fails open updates machines while
// someone is using them — and on Windows a session-0 service reading GetLastInputInfo gets "idle" forever.
func TestUnknownConditionsHoldRatherThanPass(t *testing.T) {
	base := at("03:00", time.Hour)

	noIdle := base
	noIdle.IdleKnown = false
	d := EvaluateGate(nightWindow(), noIdle)
	if d.Proceed {
		t.Fatal("an unreadable idle time must not authorise an update")
	}
	if d.WaitReason != WaitIdleUnknown {
		t.Fatalf("reason = %q, want %q", d.WaitReason, WaitIdleUnknown)
	}

	noPower := base
	noPower.PowerKnown = false
	if d := EvaluateGate(nightWindow(), noPower); d.Proceed || d.WaitReason != WaitPowerUnknown {
		t.Fatalf("an unreadable power state must hold: proceed=%v reason=%q", d.Proceed, d.WaitReason)
	}
}

func TestBusyAndBatteryHoldWithDistinctReasons(t *testing.T) {
	busy := at("03:00", time.Hour)
	busy.IdleFor = time.Minute
	if d := EvaluateGate(nightWindow(), busy); d.Proceed || d.WaitReason != WaitBusy {
		t.Fatalf("in-use device: proceed=%v reason=%q", d.Proceed, d.WaitReason)
	}

	batt := at("03:00", time.Hour)
	batt.OnACPower = false
	if d := EvaluateGate(nightWindow(), batt); d.Proceed || d.WaitReason != WaitOnBattery {
		t.Fatalf("battery device: proceed=%v reason=%q", d.Proceed, d.WaitReason)
	}
}

// ★ The reason a laptop closed at 03:00 does not stay on an old build forever. Every wait reason is
// overridable by the deadline, or a device that never meets a condition never updates while the console shows
// a configured window — which reads as managed and is not.
func TestTheDeadlineOverridesEveryWaitReason(t *testing.T) {
	long := 8 * 24 * time.Hour // past the 7-day deadline
	for name, mut := range map[string]func(*DeviceConditions){
		"out of window": func(c *DeviceConditions) { *c = at("14:00", long) },
		"busy":          func(c *DeviceConditions) { c.IdleFor = 0 },
		"idle unknown":  func(c *DeviceConditions) { c.IdleKnown = false },
		"on battery":    func(c *DeviceConditions) { c.OnACPower = false },
		"power unknown": func(c *DeviceConditions) { c.PowerKnown = false },
	} {
		c := at("03:00", long)
		mut(&c)
		d := EvaluateGate(nightWindow(), c)
		if !d.Proceed {
			t.Errorf("%s: should be forced past the deadline (%s)", name, d.Detail)
			continue
		}
		if !d.ForcedByDeadline {
			t.Errorf("%s: proceeded but did not mark it as a deadline override — an unexpected mid-day update must be explainable", name)
		}
	}
}

func TestDeadlineZeroMeansWaitForever(t *testing.T) {
	w := nightWindow()
	w.DeadlineDays = 0
	if d := EvaluateGate(w, at("14:00", 365*24*time.Hour)); d.Proceed {
		t.Fatal("with no deadline configured the device waits, however long that is")
	}
}

// ★ Freeze is an incident halt. One that only takes effect at the next maintenance window is not a halt, and
// it must outrank even a device that has waited past its deadline.
func TestFreezeOutranksEverythingIncludingTheDeadline(t *testing.T) {
	c := at("03:00", 365*24*time.Hour) // deep past the deadline, perfect conditions
	c.Frozen = true
	d := EvaluateGate(nightWindow(), c)
	if d.Proceed {
		t.Fatal("a frozen rollout must not move, deadline or not")
	}
	if d.WaitReason != WaitFrozen {
		t.Fatalf("reason = %q, want %q", d.WaitReason, WaitFrozen)
	}
}

// A window an operator typed wrongly must hold, not silently become "always". The failure of a time field is
// not a licence to update at noon.
func TestAMalformedWindowHoldsInsteadOfAllowingEverything(t *testing.T) {
	for _, bad := range []MaintenanceWindow{
		{LocalStart: "2am", LocalEnd: "05:00", DeadlineDays: 7},
		{LocalStart: "02:00", LocalEnd: "25:00", DeadlineDays: 7},
		{LocalStart: "02:00", LocalEnd: "", DeadlineDays: 7},
		{LocalStart: "0200", LocalEnd: "0500", DeadlineDays: 7},
	} {
		d := EvaluateGate(bad, at("14:00", time.Hour))
		if d.Proceed {
			t.Errorf("malformed window %+v allowed an update", bad)
		}
		if !strings.Contains(d.Detail, "unusable") {
			t.Errorf("malformed window must say so, got %q", d.Detail)
		}
	}
}

// TestNightWindowPlusUnattended is the operation this knob was added for: a 02:00-04:00 device-local window,
// and the machine may only be updated if nobody is at it.
//
// The four rows are the whole decision surface, and each one is a different operational story rather than a
// permutation for its own sake.
func TestNightWindowPlusUnattended(t *testing.T) {
	w := MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true}
	at := func(hhmm string) time.Time {
		ts, err := time.ParseInLocation("15:04", hhmm, time.UTC)
		if err != nil {
			t.Fatalf("bad test time %q: %v", hhmm, err)
		}
		return ts
	}

	cases := []struct {
		name       string
		now        string
		inUse      bool
		inUseKnown bool
		proceed    bool
		reason     string
	}{
		// The intended path: it is 03:00 and the screen is locked.
		{"night, locked", "03:00", false, true, true, ""},
		// Locked at noon is still noon. The window is what stops an update from landing in the middle of the
		// working day just because someone stepped out for lunch.
		{"midday, locked", "12:00", false, true, false, WaitOutOfWindow},
		// 03:00 but somebody is actually working — a night shift, or a long-running job with the screen
		// unlocked. The window alone would have updated this machine underneath them.
		{"night, in use", "03:00", true, true, false, WaitInUse},
		// The device cannot tell. Not permission: this must read the same as "someone is there".
		{"night, unknown", "03:00", false, false, false, WaitInUseUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateGate(w, DeviceConditions{
				LocalNow:   at(tc.now),
				InUse:      tc.inUse,
				InUseKnown: tc.inUseKnown,
			})
			if got.Proceed != tc.proceed {
				t.Fatalf("Proceed = %v, want %v (%s)", got.Proceed, tc.proceed, got.Detail)
			}
			if got.WaitReason != tc.reason {
				t.Fatalf("WaitReason = %q, want %q (%s)", got.WaitReason, tc.reason, got.Detail)
			}
		})
	}
}

// TestUnattendedIsIndependentOfIdle pins the separation that motivated a second knob.
//
// A Windows box reports InUse reliably and IdleKnown=false, so a plan that only knew about minutes could
// never update it. RequireUnattended alone must proceed there — and must NOT start ignoring an idle
// requirement that was also asked for.
func TestUnattendedIsIndependentOfIdle(t *testing.T) {
	now := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	unattendedNoIdleReading := DeviceConditions{LocalNow: now, InUseKnown: true, InUse: false, IdleKnown: false}

	got := EvaluateGate(MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true}, unattendedNoIdleReading)
	if !got.Proceed {
		t.Fatalf("unattended-only plan held a box that cannot measure idle: %s (%s)", got.WaitReason, got.Detail)
	}

	// Both asked for: the unmeasurable one still holds, because the operator asked for a duration and this
	// device cannot supply one.
	both := MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true, RequireIdleMinutes: 30}
	got = EvaluateGate(both, unattendedNoIdleReading)
	if got.Proceed {
		t.Fatal("a plan requiring 30 idle minutes proceeded on a device whose idle time is unknown")
	}
	if got.WaitReason != WaitIdleUnknown {
		t.Fatalf("WaitReason = %q, want %q", got.WaitReason, WaitIdleUnknown)
	}
}

// TestDeadlineOverridesInUse: the deadline is what stops "always in use" from meaning "never updated". A
// machine nobody ever locks would otherwise sit on an old build forever, and the report has to say that is
// what happened.
func TestDeadlineOverridesInUse(t *testing.T) {
	w := MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true, DeadlineDays: 7}
	got := EvaluateGate(w, DeviceConditions{
		LocalNow:      time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC),
		InUse:         true,
		InUseKnown:    true,
		EligibleSince: time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
	})
	if !got.Proceed || !got.ForcedByDeadline {
		t.Fatalf("Proceed=%v ForcedByDeadline=%v, want both true (%s)", got.Proceed, got.ForcedByDeadline, got.Detail)
	}
	if !strings.Contains(got.Detail, WaitInUse) {
		t.Fatalf("forced-by-deadline detail does not name what was overridden: %q", got.Detail)
	}
}

// TestWaveHoldCannotBeJumpedByTheDeadline is the property that makes a stagger a stagger.
//
// The deadline exists so a device that keeps missing its window still eventually updates. It must not be able
// to start a wave early: the entire point of the second wave is that somebody gets to look at the first one
// before it begins. The arithmetic already declines to fire before EligibleSince (the elapsed time is
// negative), but that is a coincidence of the formula, and this asserts the rule instead of the coincidence.
func TestWaveHoldCannotBeJumpedByTheDeadline(t *testing.T) {
	now := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	// A deadline of 1 day, and a wave that does not start for another 3.
	w := MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", DeadlineDays: 1}
	got := EvaluateGate(w, DeviceConditions{
		LocalNow:      now,
		EligibleSince: now.AddDate(0, 0, 3),
	})
	if got.Proceed {
		t.Fatalf("a device updated before its wave started (forced=%v): %s", got.ForcedByDeadline, got.Detail)
	}
	if got.WaitReason != WaitNotYetInWave {
		t.Fatalf("WaitReason = %q, want %q", got.WaitReason, WaitNotYetInWave)
	}
	// The sentence has to say when, because "why is this machine still on the old build" is the question a
	// stagger generates and "not yet" without a date sends someone looking for a fault.
	if !strings.Contains(got.Detail, "2026-08-12") {
		t.Fatalf("detail does not say when the wave starts: %q", got.Detail)
	}
}

// TestWaveStartedThenNormalRulesApply: once the wave opens, the device is subject to exactly the same window
// and conditions as any other — the stagger shifts WHEN the rules start applying, it does not replace them.
func TestWaveStartedThenNormalRulesApply(t *testing.T) {
	waveStarted := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	w := MaintenanceWindow{LocalStart: "02:00", LocalEnd: "04:00", RequireUnattended: true}

	// Inside the wave and inside the window, unattended: proceeds.
	got := EvaluateGate(w, DeviceConditions{
		LocalNow:      time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC),
		EligibleSince: waveStarted,
		InUseKnown:    true,
	})
	if !got.Proceed {
		t.Fatalf("held inside its wave and window: %s (%s)", got.WaitReason, got.Detail)
	}

	// Inside the wave, but the working day: still the window that decides.
	got = EvaluateGate(w, DeviceConditions{
		LocalNow:      time.Date(2026, 8, 9, 14, 0, 0, 0, time.UTC),
		EligibleSince: waveStarted,
		InUseKnown:    true,
	})
	if got.Proceed || got.WaitReason != WaitOutOfWindow {
		t.Fatalf("wave start overrode the maintenance window: proceed=%v reason=%q", got.Proceed, got.WaitReason)
	}
}

package agentupdate

import "testing"

// ★★ A PLAN RAISES SAFETY GATES AND NEVER LOWERS THEM (2026-08-13, thirtieth review #22 — the rule hoisted
// here from two hand-kept copies). A plan carrying nothing but a window is the ordinary shape, and copying its
// zeroes over the device's own defaults is how an install ran while somebody was typing, on battery.
func TestAPlanWindowRaisesTheGatesAndNeverLowersThem(t *testing.T) {
	local := MaintenanceWindow{
		LocalStart: "01:00", LocalEnd: "05:00",
		RequireIdleMinutes: 10, RequireUnattended: true, RequireACPower: true, DeadlineDays: 14,
	}

	// The ordinary shape: times only. Every gate must survive.
	got := RaiseWindow(local, PlanWindow{LocalStart: "02:00", LocalEnd: "06:00"})
	if got.RequireIdleMinutes != 10 || !got.RequireUnattended || !got.RequireACPower {
		t.Fatalf("a plan carrying only a window removed the device's protections: %+v", got)
	}
	if got.LocalStart != "02:00" || got.LocalEnd != "06:00" || got.DeadlineDays != 14 {
		t.Fatalf("the schedule did not move, or the deadline was lost: %+v", got)
	}

	// Raising is allowed in every direction that is stricter.
	got = RaiseWindow(local, PlanWindow{RequireIdleMinutes: 30})
	if got.RequireIdleMinutes != 30 {
		t.Fatalf("a stricter idle requirement was ignored: %+v", got)
	}

	// And a device with NO local gates still takes the plan's.
	got = RaiseWindow(MaintenanceWindow{}, PlanWindow{RequireIdleMinutes: 5, RequireUnattended: true, RequireACPower: true})
	if got.RequireIdleMinutes != 5 || !got.RequireUnattended || !got.RequireACPower {
		t.Fatalf("the plan's gates did not reach a device with none of its own: %+v", got)
	}
}

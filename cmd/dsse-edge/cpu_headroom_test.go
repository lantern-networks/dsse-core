package main

import (
	"runtime"
	"strings"
	"testing"
)

// The reservation must actually reserve on a node big enough for it to matter, and must NOT on a small one.
// Both directions, because a rule that only ever says yes is not a rule.
func TestCPUHeadroomReservesOnlyWhereItHelps(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cores          int
		requested      int
		wantProcs      int
		wantReserved   int
		reasonContains string
	}{
		{"four cores, decide for me", 4, -1, 3, 1, "reserving 1 of 4"},
		{"sixteen cores, decide for me", 16, -1, 15, 1, "reserving 1 of 16"},
		{"two cores, decide for me", 2, -1, 2, 0, "too few to reserve from"},
		{"one core, decide for me", 1, -1, 1, 0, "too few to reserve from"},
		{"explicitly off", 8, 0, 8, 0, "explicitly disabled"},
		{"explicitly two", 8, 2, 6, 2, "reserving 2 of 8"},
		{"asked for more than exists", 4, 9, 1, 3, "clamped"},
		{"asked for exactly all", 4, 4, 1, 3, "clamped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procs, reserved, reason := cpuHeadroomPlan(tc.cores, tc.requested)
			if procs != tc.wantProcs || reserved != tc.wantReserved {
				t.Fatalf("cpuHeadroomPlan(%d, %d) = procs %d reserved %d, want procs %d reserved %d (%s)",
					tc.cores, tc.requested, procs, reserved, tc.wantProcs, tc.wantReserved, reason)
			}
			if procs < 1 {
				t.Fatalf("the plan left this process %d cores — a reservation must never reserve the node out of a data plane", procs)
			}
			if !strings.Contains(reason, tc.reasonContains) {
				t.Fatalf("reason = %q, want it to mention %q — an operator reading the log has to be able to tell which rule fired", reason, tc.reasonContains)
			}
		})
	}
}

// It has to take effect, not merely be computed. The startup line an operator reads must describe the
// GOMAXPROCS the process is actually running with.
func TestCPUHeadroomTakesEffect(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)

	line := applyCPUHeadroom(0)
	if got := runtime.GOMAXPROCS(0); got != runtime.NumCPU() {
		t.Fatalf("with the reservation off GOMAXPROCS = %d, want every core (%d)", got, runtime.NumCPU())
	}
	if !strings.Contains(line, "none reserved") {
		t.Fatalf("startup line = %q, want it to say nothing was reserved", line)
	}

	line = applyCPUHeadroom(1)
	want := runtime.NumCPU() - 1
	if want < 1 {
		want = 1
	}
	if got := runtime.GOMAXPROCS(0); got != want {
		t.Fatalf("GOMAXPROCS = %d after reserving one core, want %d — the reservation was computed and not applied", got, want)
	}
	if !strings.Contains(line, "core(s) reserved") {
		t.Fatalf("startup line = %q, want it to name the reservation", line)
	}
	// The line must not overclaim. This mechanism does not give admin requests inside this process a core.
	if !strings.Contains(line, "does not") {
		t.Fatalf("startup line = %q, want it to say what the reservation does NOT do — an operator who reads "+
			"it as an admin-only core will trust something that is not there", line)
	}
}

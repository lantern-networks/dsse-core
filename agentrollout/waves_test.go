package agentrollout

import (
	"strings"
	"testing"
	"time"
)

func intPtr(v int) *int { return &v }

// TestPilotRingBeatsDepartment is the case that decided the design. A machine deliberately placed in a pilot
// ring is almost always ALSO in an ordinary department group, so a slowest-wins rule would make the pilot
// start last — the ring that exists to find bad builds early would never run early, and the feature would be
// useless for its main purpose. Priority is what distinguishes a deliberate pilot from an accidental fast
// membership; the delays alone cannot.
func TestPilotRingBeatsDepartment(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{
		{Group: "pilot", DelayDays: 0, Priority: 100},
		{Group: "finance", DelayDays: 5},
	}}
	a := s.AssignmentFor([]string{"finance", "pilot"})
	if a.DelayDays != 0 || a.Group != "pilot" {
		t.Fatalf("assignment = %+v, want pilot at day 0", a)
	}
	// Membership order must not matter.
	if b := s.AssignmentFor([]string{"pilot", "finance"}); b.DelayDays != a.DelayDays || b.Group != a.Group {
		t.Fatalf("membership order changed the answer: %+v vs %+v", a, b)
	}
	// And the reason must name the losing membership, because "why is this machine updating first" is the
	// question a pilot generates.
	if !strings.Contains(a.Reason, "finance") {
		t.Fatalf("reason does not mention the other membership: %q", a.Reason)
	}
}

// TestTiesGoToTheSlowerWave: between two equally authoritative statements, the conservative one wins. An
// update that happens too late can be chased; one that happened too early has already happened.
func TestTiesGoToTheSlowerWave(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{
		{Group: "a", DelayDays: 1},
		{Group: "b", DelayDays: 4},
	}}
	a := s.AssignmentFor([]string{"a", "b"})
	if a.DelayDays != 4 || a.Group != "b" {
		t.Fatalf("assignment = %+v, want group b at day 4", a)
	}
}

// TestAssignmentIsDeterministic guards a property that is not cosmetic: two control-plane replicas computing
// one device's EligibleSince must agree, or the device's deadline moves depending on which replica answered.
func TestAssignmentIsDeterministic(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{
		{Group: "zeta", DelayDays: 3, Priority: 5},
		{Group: "alpha", DelayDays: 3, Priority: 5},
	}}
	first := s.AssignmentFor([]string{"zeta", "alpha"})
	for i := 0; i < 20; i++ {
		if got := s.AssignmentFor([]string{"alpha", "zeta"}); got.Group != first.Group || got.DelayDays != first.DelayDays {
			t.Fatalf("assignment varied between calls: %+v vs %+v", first, got)
		}
	}
	if first.Group != "alpha" {
		t.Fatalf("fully tied groups resolved to %q; want the lower name for a total order", first.Group)
	}
}

// TestUnscheduledDeviceTakesTheSlowestWave is the fail-late default, and the reason is the failure this whole
// file exists to prevent: an admin who adds a group and forgets to schedule it must not thereby create a
// same-day fleet-wide rollout.
func TestUnscheduledDeviceTakesTheSlowestWave(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{
		{Group: "pilot", DelayDays: 0, Priority: 100},
		{Group: "finance", DelayDays: 5},
	}}
	for _, groups := range [][]string{nil, {}, {"brand-new-group"}, {""}} {
		a := s.AssignmentFor(groups)
		if a.DelayDays != 5 {
			t.Fatalf("groups %v: delay = %d, want 5 (the slowest wave)", groups, a.DelayDays)
		}
		if a.Explicit {
			t.Fatalf("groups %v: reported as explicitly scheduled", groups)
		}
	}

	// An admin who wants a different answer says so.
	s.DefaultDelayDays = intPtr(2)
	if a := s.AssignmentFor([]string{"brand-new-group"}); a.DelayDays != 2 {
		t.Fatalf("configured default ignored: %+v", a)
	}
}

// TestNoScheduleMeansNoStagger: a tenant that has not asked for waves must behave exactly as before this
// existed, not have every device silently pushed to some non-zero day.
func TestNoScheduleMeansNoStagger(t *testing.T) {
	var s WaveSchedule
	a := s.AssignmentFor([]string{"anything"})
	if a.DelayDays != 0 {
		t.Fatalf("empty schedule produced a delay of %d days", a.DelayDays)
	}
	released := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	start, _ := s.WaveStart([]string{"anything"}, released)
	if !start.Equal(released) {
		t.Fatalf("WaveStart = %s, want the release time %s", start, released)
	}
}

// TestWaveStartIsOneDayApart is the operator's stated intent, checked literally.
func TestWaveStartIsOneDayApart(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{
		{Group: "ring0", DelayDays: 0},
		{Group: "ring1", DelayDays: 1},
		{Group: "ring2", DelayDays: 2},
	}}
	released := time.Date(2026, 8, 9, 22, 0, 0, 0, time.UTC)
	for i, g := range []string{"ring0", "ring1", "ring2"} {
		start, _ := s.WaveStart([]string{g}, released)
		want := released.AddDate(0, 0, i)
		if !start.Equal(want) {
			t.Fatalf("%s starts %s, want %s", g, start, want)
		}
	}
}

// TestZeroReleaseTimeDoesNotMeanNow: an absent or unparseable release date must not become a reason to update
// the fleet immediately. The gate reads a zero EligibleSince as "no schedule", so this stays zero.
func TestZeroReleaseTimeDoesNotMeanNow(t *testing.T) {
	s := WaveSchedule{Waves: []RolloutWave{{Group: "ring1", DelayDays: 1}}}
	start, _ := s.WaveStart([]string{"ring1"}, time.Time{})
	if !start.IsZero() {
		t.Fatalf("WaveStart with a zero release = %s, want the zero time", start)
	}
}

func TestValidate(t *testing.T) {
	bad := []struct {
		name string
		s    WaveSchedule
	}{
		{"empty group", WaveSchedule{Waves: []RolloutWave{{Group: "  ", DelayDays: 1}}}},
		{"negative delay", WaveSchedule{Waves: []RolloutWave{{Group: "a", DelayDays: -1}}}},
		// One group, one row. Two rows is an author's mistake, and picking the first would schedule devices by
		// the order rows happened to be written in.
		{"duplicate group", WaveSchedule{Waves: []RolloutWave{{Group: "a"}, {Group: "A"}}}},
		{"negative default", WaveSchedule{Waves: []RolloutWave{{Group: "a"}}, DefaultDelayDays: intPtr(-1)}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.s.Validate(); err == nil {
				t.Fatal("Validate accepted a schedule that cannot mean what its author intended")
			}
		})
	}

	ok := WaveSchedule{Waves: []RolloutWave{
		{Group: "pilot", DelayDays: 0, Priority: 100},
		{Group: "finance", DelayDays: 5},
	}, DefaultDelayDays: intPtr(3)}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate rejected a good schedule: %v", err)
	}
}

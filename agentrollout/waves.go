package agentrollout

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// waves.go — WHEN each device group starts, so a release does not reach the whole fleet at once.
//
// The damage from a bad build is proportional to how many machines took it before anyone noticed, and
// "everybody at 02:00 tonight" maximises that number. Staggering by group turns a fleet-wide outage into a
// first-group outage plus a decision.
//
// HOW THIS CONNECTS TO THE GATE, which is the whole design. A wave produces the device's EligibleSince and
// nothing else changes. The maintenance window, the unattended check, the power check and the deadline all
// already work from that instant, so a group that starts three days later gets its own full night window and
// its own full deadline — it does not inherit a countdown that started while it was still waiting.
//
// WHY THERE IS A PRIORITY. A device may belong to several groups, so several schedules can apply and one has
// to win. Neither obvious rule is acceptable on its own:
//
//   - slowest-wins is safe against accidents but destroys the pilot ring. A machine deliberately placed in
//     "pilot" (day 0) that is also in "finance" (day 5) would start on day 5, so the ring that exists to find
//     bad builds early never runs early. The feature would be unusable for its main purpose.
//   - fastest-wins makes pilots work and makes accidents expensive: one machine added to a fast group updates
//     ahead of the schedule someone designed, which is the event this file exists to prevent.
//
// So the schedule says which group speaks for a device, explicitly. Priority is the admin's statement of
// intent — "pilot outranks department" — and it is the only thing that can distinguish a deliberate pilot from
// an accidental fast membership, because they look identical from the delays alone.
//
// Every tie is broken toward the SLOWER wave, and then by group name so the answer is total. Determinism
// matters beyond tidiness: two control-plane replicas computing a device's EligibleSince must agree, or the
// device's deadline moves depending on which one answered.

// RolloutWave places one device group in the stagger.
type RolloutWave struct {
	Group string `json:"group"`
	// DelayDays is how long after the release this group's devices may begin. 0 is the first wave.
	DelayDays int `json:"delay_days"`
	// Priority decides which group speaks for a device that is in several. Higher wins; 0 is the default, so a
	// schedule that does not care about priority behaves as though the field were not there.
	//
	// It is deliberately NOT derived from the delay. "This device is a pilot" and "this device is in a group
	// that happens to be scheduled early" are different statements, and only one of them should survive
	// someone adding the machine to a second group next month.
	Priority int `json:"priority,omitempty"`
}

// WaveSchedule is the whole stagger for a tenant.
type WaveSchedule struct {
	Waves []RolloutWave `json:"waves"`
	// DefaultDelayDays applies to a device whose groups are all unlisted, and to a device with no groups.
	//
	// When it is nil the fallback is the SLOWEST configured wave, not the fastest. The reason is the failure
	// this whole file exists to prevent: an admin who adds a group and forgets to schedule it would otherwise
	// have created a fleet-wide same-day rollout by omission — the exact event being engineered against. Being
	// late is recoverable and visible; being early is neither.
	DefaultDelayDays *int `json:"default_delay_days,omitempty"`
}

// Validate reports configuration that cannot mean what its author intended.
func (s WaveSchedule) Validate() error {
	seen := make(map[string]bool, len(s.Waves))
	for i, w := range s.Waves {
		g := strings.TrimSpace(w.Group)
		if g == "" {
			return fmt.Errorf("wave %d has an empty group name", i)
		}
		if w.DelayDays < 0 {
			return fmt.Errorf("group %q has a negative delay (%d days)", g, w.DelayDays)
		}
		// A group may appear once in the SCHEDULE even though a device may be in many groups: two rows for one
		// group is an author's mistake, not an ambiguity to pick a winner for. Silently taking the first would
		// schedule devices by the order rows happened to be written in.
		key := strings.ToLower(g)
		if seen[key] {
			return fmt.Errorf("group %q appears more than once in the schedule; give it one row", g)
		}
		seen[key] = true
	}
	if s.DefaultDelayDays != nil && *s.DefaultDelayDays < 0 {
		return fmt.Errorf("default delay is negative (%d days)", *s.DefaultDelayDays)
	}
	return nil
}

// WaveAssignment is a device's place in the stagger, and why.
//
// The reason is carried rather than left to be reconstructed because "why is this machine still on the old
// build" is the question this feature generates, and an answer of "day 5" without "because it is in finance,
// which outranks its membership in pilot" sends an admin looking in the wrong place.
type WaveAssignment struct {
	// Group is the group that decided the answer; empty when nothing matched.
	Group     string
	DelayDays int
	// Explicit is false when no group matched and the fallback was used.
	Explicit bool
	Reason   string
}

// AssignmentFor picks the wave that speaks for a device in the given groups.
//
// Highest priority wins. Ties go to the LONGER delay — between two equally authoritative statements, the
// conservative one is the one that can be undone — and then to the lower group name, so the result never
// depends on the order the caller happened to list memberships in.
func (s WaveSchedule) AssignmentFor(groups []string) WaveAssignment {
	type match struct {
		group    string
		delay    int
		priority int
	}
	var matches []match
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		for _, w := range s.Waves {
			if strings.EqualFold(strings.TrimSpace(w.Group), g) {
				matches = append(matches, match{group: strings.TrimSpace(w.Group), delay: w.DelayDays, priority: w.Priority})
				break
			}
		}
	}

	if len(matches) == 0 {
		days := s.slowest()
		why := fmt.Sprintf("no group of this device is in the rollout schedule, so it takes the slowest wave (day %d)", days)
		if s.DefaultDelayDays != nil {
			days = *s.DefaultDelayDays
			why = fmt.Sprintf("no group of this device is in the rollout schedule, so it takes the configured default (day %d)", days)
		}
		return WaveAssignment{DelayDays: days, Explicit: false, Reason: why}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].priority != matches[j].priority {
			return matches[i].priority > matches[j].priority
		}
		if matches[i].delay != matches[j].delay {
			return matches[i].delay > matches[j].delay
		}
		return matches[i].group < matches[j].group
	})
	win := matches[0]

	reason := fmt.Sprintf("group %q, day %d", win.group, win.delay)
	if len(matches) > 1 {
		others := make([]string, 0, len(matches)-1)
		for _, m := range matches[1:] {
			others = append(others, fmt.Sprintf("%s(day %d, priority %d)", m.group, m.delay, m.priority))
		}
		reason = fmt.Sprintf("group %q (priority %d) decides day %d; also in %s",
			win.group, win.priority, win.delay, strings.Join(others, ", "))
	}
	return WaveAssignment{Group: win.group, DelayDays: win.delay, Explicit: true, Reason: reason}
}

// slowest is the fail-late fallback. With no waves configured at all it is 0, which is the correct
// no-stagger behaviour: a tenant that has not asked for waves gets what it had before this existed.
func (s WaveSchedule) slowest() int {
	max := 0
	for _, w := range s.Waves {
		if w.DelayDays > max {
			max = w.DelayDays
		}
	}
	return max
}

// WaveStart is when a device's groups allow it to begin updating to a release published at releasedAt.
//
// This is the value to put in DeviceConditions.EligibleSince. A zero releasedAt yields a zero time, which the
// gate reads as "no schedule" rather than "start immediately" — an unparseable release date must not become a
// reason to update everything now.
func (s WaveSchedule) WaveStart(groups []string, releasedAt time.Time) (time.Time, WaveAssignment) {
	a := s.AssignmentFor(groups)
	if releasedAt.IsZero() {
		return time.Time{}, a
	}
	return releasedAt.AddDate(0, 0, a.DelayDays), a
}

// Describe renders the schedule in the order the rollout actually happens, for the admin question "who gets
// it when" — not in the order the rows were written.
func (s WaveSchedule) Describe() string {
	if len(s.Waves) == 0 {
		return "no wave schedule: every group starts at release"
	}
	ws := append([]RolloutWave(nil), s.Waves...)
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].DelayDays != ws[j].DelayDays {
			return ws[i].DelayDays < ws[j].DelayDays
		}
		return ws[i].Priority > ws[j].Priority
	})
	var b strings.Builder
	for i, w := range ws {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: day %d", w.Group, w.DelayDays)
		if w.Priority != 0 {
			fmt.Fprintf(&b, " (priority %d)", w.Priority)
		}
	}
	fallback := "the slowest wave"
	if s.DefaultDelayDays != nil {
		fallback = fmt.Sprintf("day %d", *s.DefaultDelayDays)
	}
	return b.String() + " (devices in no scheduled group: " + fallback + ")"
}

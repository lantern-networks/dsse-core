//go:build windows

package main

import (
	"strings"
	"testing"
	"time"
)

// ★ THE POSTURE WAS FETCHED ONCE AND NEVER AGAIN (2026-08-21, raised from the Edge side after they found the
// same shape three times in their own tree). A device whose single start-up fetch failed kept its
// install-time flags for the life of the process and said so exactly once — in a line an operator reads at
// boot and never again. This box did it on 2026-08-20.
//
// The retry reports rather than switches: region failover decides whether the region machinery is built and
// the capture is armed from these values, so flipping them under a running data path would be a worse bug.
// What has to stop is the SILENCE.

func TestALateArrivingPostureThatMatchesEndsQuietly(t *testing.T) {
	p := resolvedPosture{FailOpen: true, RegionFailover: false, TerminalFailOpen: false, Cooldown: 10 * time.Second}
	matched, line := posturePlanAfterRetry(p, p)
	if !matched {
		t.Fatalf("an identical posture should end the retry")
	}
	if !strings.Contains(line, "MATCHES") {
		t.Fatalf("line = %q, want it to say the boot failure cost nothing", line)
	}
}

func TestALateArrivingPostureThatDiffersKeepsSayingSo(t *testing.T) {
	inForce := resolvedPosture{FailOpen: true, RegionFailover: false, TerminalFailOpen: false, Cooldown: 10 * time.Second}
	want := resolvedPosture{FailOpen: true, RegionFailover: true, TerminalFailOpen: false, Cooldown: 30 * time.Second}

	matched, line := posturePlanAfterRetry(inForce, want)
	if matched {
		t.Fatalf("a differing posture must not end the retry — the difference lasts until a restart")
	}
	for _, want := range []string{"DIFFERS", "region_failover=false", "region_failover=true", "RESTART THE AGENT"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line does not carry %q, so an operator cannot act on it:\n%s", want, line)
		}
	}
}

// The cooldown alone differing is still a difference: it is what decides how long a device tolerates an Edge
// outage before tearing steering down, and a device on the wrong one behaves differently in an incident.
func TestACooldownOnlyDifferenceIsStillReported(t *testing.T) {
	inForce := resolvedPosture{FailOpen: true, Cooldown: 10 * time.Second}
	want := resolvedPosture{FailOpen: true, Cooldown: 5 * time.Minute}
	if matched, _ := posturePlanAfterRetry(inForce, want); matched {
		t.Fatalf("a cooldown-only difference was treated as a match")
	}
}

package main

import (
	"os"
	"strings"
	"testing"
)

// The store-level test next door (TestAFlowWithNoUsernameStillCountsAsSteering) passes with the defect
// present: the bug was never in the store, which has always ignored an empty username. It was in the CALLER —
// the mux OPEN handler invoked the store only `if osUser != ""`. A test that cannot fail on the regression it
// names is decoration, so this one reads the call site.
//
// Source inspection is a blunt instrument and used deliberately: the alternative is standing up a steer mux,
// a policy evaluator and a transport identity to observe one function call, and the thing worth protecting is
// exactly one line of control flow.
func TestTheSteeredFlowIsRecordedWhetherOrNotAUserIsKnown(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")

	calls := 0
	for i, ln := range lines {
		if !strings.Contains(ln, "deviceRuntime.recordSteeredFlow(") {
			continue
		}
		calls++
		// Walk back over the comment block to the nearest statement. An `if osUser`/`if user` immediately
		// above, with no closing brace between, is the gate coming back.
		for j := i - 1; j >= 0 && j > i-30; j-- {
			prev := strings.TrimSpace(lines[j])
			if prev == "" || strings.HasPrefix(prev, "//") {
				continue
			}
			if strings.HasPrefix(prev, "if ") && strings.Contains(prev, "sUser") {
				t.Fatalf("main.go:%d — the steered-flow record is gated on knowing the OS user (%q). This is the "+
					"only place a device is credited with carrying traffic: gating it means every agent that "+
					"does not send `u=` reports as never having steered, which is what the macOS NE did.",
					i+1, prev)
			}
			break
		}
	}
	if calls == 0 {
		t.Fatal("no call to deviceRuntime.recordSteeredFlow in main.go — if it moved, move this guard with it; " +
			"a guard that silently stops guarding is worse than none")
	}
}

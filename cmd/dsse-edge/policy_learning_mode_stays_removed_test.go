package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyLearningModeStaysRemoved — carried from the retired reference edge (2026-08-23).
//
// ★★★ WHY IT WAS CARRIED AND NOT DROPPED. The dsse-edge and dsse-cp in the published tree were open-core-era
// leftovers and went with the decision that the product Edge is the published binary. Their tests went with
// the implementations they tested — except this one, which guards an ABSENCE, and an absence is not owned by
// whichever binary happened to be watching it.
//
// /admin/policy-learning-mode was removed because a learning mode that defers default-deny is a deployment
// that decides nothing while every screen says it is protecting. The endpoint exists in neither binary today.
// Losing the guard along with the leftover would have meant that a reintroduction — the exact regression the
// guard was written for — would land silently in the binary that is now the product.
//
// ★ IT READS THE SOURCE RATHER THAN A RUNNING SERVER, because what must not come back is the REGISTRATION.
// A route that is registered and then rejected at runtime is still the mode arriving.
func TestPolicyLearningModeStaysRemoved(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || name == "policy_learning_mode_stays_removed_test.go" {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(".", name))
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		scanned++
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "/admin/policy-learning-mode") {
				continue
			}
			// A mention in prose is the record of why it was removed; a route registration is the mode back.
			if strings.Contains(line, "mux.HandleFunc") || strings.Contains(line, "mux.Handle") {
				t.Errorf("%s registers /admin/policy-learning-mode again:\n    %s\n"+
					"  The mode was removed because a deployment that defers default-deny decides nothing "+
					"while every screen says it is protecting.", name, strings.TrimSpace(line))
			}
		}
	}
	// ★ AND THE SCAN HAS TO HAVE HAPPENED. A guard that read no files reports the same "pass" as one that
	// read all of them, which is how this package's own gates have failed before.
	if scanned < 100 {
		t.Fatalf("only %d source files were scanned; this package has hundreds, so the guard did not run", scanned)
	}
}

package main

import (
	"strings"
	"testing"
)

// ★★★ A STEP THAT RUNS docker compose SAYS WHICH DIRECTORY IT RUNS IN (2026-09-02, found by walking the order
// on a live deployment).
//
// compose finds the deployment by the working directory — the compose file and deployment.env are both read
// from it. Every step for a JOINING machine began `tar xzf … && cd /opt/dsse/<region> && docker compose`, and
// every step for the FOUNDING machine did not: the operator was expected to infer it. On the machine where
// that inference had to be made, the directory was also root-only, so following the order as printed gave
//
//	bash: line 1: cd: /opt/dsse/tokyo-east: Permission denied
//
// — about a step that never mentioned the directory in the first place.
func TestEveryPrintedComposeStepSaysWhereItRuns(t *testing.T) {
	p := planOfThree(t)
	for _, step := range p.InstallOrder("/opt/dsse", "/tmp/plan.json") {
		if !strings.Contains(step.Do, "docker compose") {
			continue
		}
		if strings.Contains(step.Do, "cd /opt/dsse") {
			continue
		}
		t.Errorf("this step runs compose without saying where from, so it works only for a reader who\n"+
			"already inferred the directory:\n  %s\n  (on %s)", step.Do, step.Machine)
	}
}

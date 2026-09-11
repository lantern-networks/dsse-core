package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE STATE THE DEPLOYMENT WAS ACTUALLY IN, AND IT MUST FAIL. Freshly installed, healthy, 20 of 31
// checks green — and the real signed macOS package refuses every install against it.
func TestADeploymentNoEndpointCanJoinFails(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// As shipped: a publisher nobody has filled in yet.
	got := verifyAnEndpointCanBeInstalled(dir)
	if len(got) != 1 || got[0].ok {
		t.Fatalf("a deployment no device can join was reported as ready: %+v", got)
	}
	// It has to name what to set, or an operator is told they have a problem and not what to do.
	if !strings.Contains(got[0].note, "DSSE_AGENT_PUBLISHER") {
		t.Errorf("the finding does not name the value to set: %s", got[0].note)
	}
}

// ★ THE CONTROL: with the publisher filled in, it passes — and says what it did NOT check, because "the
// deployment names a publisher" and "the package is signed by that publisher" are different facts and only
// the first is knowable here.
func TestADeploymentThatNamesItsPublisherPasses(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	appendEnv(t, dir, "DSSE_AGENT_PUBLISHER", "M4U8GSBL6C")
	got := verifyAnEndpointCanBeInstalled(dir)
	if len(got) != 1 || !got[0].ok {
		t.Fatalf("a deployment that names both was reported as a problem: %+v", got)
	}
	if !strings.Contains(got[0].note, "M4U8GSBL6C") || !strings.Contains(got[0].note, "does NOT") {
		t.Errorf("the pass does not say what was measured and what was not: %s", got[0].note)
	}
}

// ★★ AND THE UPDATE-SIGNING KEY IS THE OTHER HALF. A deployment carried without it — or one installed before
// this existed — publishes a configuration refused at the first check, and that must not be silent either.
func TestADeploymentWithNoUpdateSigningKeyFails(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	appendEnv(t, dir, "DSSE_AGENT_PUBLISHER", "M4U8GSBL6C")
	if err := os.Remove(filepath.Join(dir, agentUpdateSigningPublicFile)); err != nil {
		t.Fatal(err)
	}
	got := verifyAnEndpointCanBeInstalled(dir)
	if len(got) != 1 || got[0].ok {
		t.Fatalf("a deployment whose devices could never be patched was reported as ready: %+v", got)
	}
	if !strings.Contains(got[0].note, "patch") {
		t.Errorf("the finding does not say what it costs: %s", got[0].note)
	}
}

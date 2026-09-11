package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ REMOVAL STOPS WHAT RUNS AND COLLECTS NOTHING THAT NAMES THE DEPLOYMENT (2026-09-07, both platforms).
//
// A box whose uninstall could not run came back bound to a deployment destroyed the day before, because the
// material naming it was still on disk. A Mac held a torn-down deployment's material after an uninstall that
// reported success. Deleting it is a decision; leaving it in silence is not.
func TestUninstallSaysWhatItLeavesBehind(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	material := filepath.Join(dir, "DSSE")
	if err := os.MkdirAll(material, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var quiet strings.Builder
	reportWhatUninstallLeaves(&quiet)
	if quiet.Len() != 0 {
		t.Errorf("a machine with nothing left must say nothing, got: %s", quiet.String())
	}

	for _, n := range []string{"install-profile.json", "profile_signing_key.txt"} {
		if err := os.WriteFile(filepath.Join(material, n), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	var said strings.Builder
	reportWhatUninstallLeaves(&said)
	out := said.String()
	if !strings.Contains(out, "install-profile.json") {
		t.Error("the profile is the artefact that says which deployment this machine was; it must be named")
	}
	if !strings.Contains(out, "profile_signing_key.txt") {
		t.Error("the key any future profile is verified against must be named too — leaving it is what lets a " +
			"later act adopt a deployment nobody chose")
	}
	if !strings.Contains(out, material) {
		t.Error("the message must say where, or it is not actionable")
	}
}

//go:build darwin

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/macos/updateplatform"
)

// dry_run_pass_darwin_test.go — a WHOLE PASS under --dry-run, not the guards it is built from.
//
// ★ THE WINDOWS SIDE MADE THIS POINT AND IT LANDS HERE TOO (2026-08-12). Their dry-run test
// only ever watched the journal, so when the fix also stopped the OUTBOX write, nothing asserted it — a build
// that resumed queueing outcomes on a rehearsal would have gone green. Mine had the narrower version of the
// same gap: it tested persist() and queue() rather than a pass that calls them.
//
// So this runs a pass that produces BOTH kinds of write — a completed attempt to reconcile, and a plan floor to
// ratchet — and asserts on what is left ON DISK rather than on what the code returned. The directory being
// empty does not depend on a return value being honest.

type dryRunPlatform struct{ running string }

func (p dryRunPlatform) RunningVersion() (string, error) { return p.running, nil }
func (p dryRunPlatform) Conditions(time.Time) agentupdate.DeviceConditions {
	return agentupdate.DeviceConditions{LocalNow: time.Now(), InUse: false, InUseKnown: true,
		OnACPower: true, PowerKnown: true}
}
func (p dryRunPlatform) CaptureRestoreMaterial(agentupdate.Manifest) ([]string, error) {
	return nil, nil
}
func (p dryRunPlatform) RestoreMaterialFor(string) (string, error) { return "", nil }
func (p dryRunPlatform) DisarmBeforeUpdate() bool                  { return false }
func (p dryRunPlatform) Disarm() error                             { return nil }
func (p dryRunPlatform) Rearm() error                              { return nil }
func (p dryRunPlatform) Execute(agentupdate.Manifest) error        { return nil }
func (p dryRunPlatform) ExecuteRollback(_, _ string) error         { return nil }

// passRig writes a signed manifest and a journal holding an attempt that has ALREADY landed, so the pass has a
// completed attempt to reconcile (an outbox write) and a plan to ratchet (a journal write).
func passRig(t *testing.T, running string) *updater {
	t.Helper()
	dir := t.TempDir()
	// ★ THE REAL PASS REACHES ClearStaged, AND ITS PATH WAS A CONSTANT (2026-08-12, twelfth review). Run this
	// suite as root on a machine with the agent installed and it would delete the staged package of the release
	// that device is actually holding. A test that can damage the device it runs on is not one to leave loaded.
	t.Cleanup(updateplatform.SetDataRootForTest(dir))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	m := agentupdate.Manifest{
		Schema: agentupdate.SchemaVersion, Version: running, Platform: agentupdate.PlatformDarwin,
		Arch: "arm64", Channel: "stable", Delivery: agentupdate.DeliveryDSSE,
		ArtifactKind: agentupdate.ArtifactKindPKG, ArtifactURL: "https://example.test/a.pkg",
		ArtifactSHA256: strings.Repeat("ab", 32), ArtifactSize: 1,
		ReleasedAt: now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:   now.Add(720 * time.Hour).Format(time.RFC3339),
	}
	env, err := agentupdate.Sign(signer, m, now)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	manifestPath := filepath.Join(dir, "update-manifest.json")
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = pub

	journalPath := filepath.Join(dir, "update", "journal.json")
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// The state a completed install leaves: the updater launched the installer and was replaced by it, so the
	// journal is still in `executing` and the pass that finds it is the one that closes it out.
	j := agentupdate.NewJournal()
	j.Begin(running, "0.0.1", now.Add(-time.Minute))
	j.Enter(agentupdate.PhaseExecuting, now.Add(-time.Minute))
	if err := j.Save(journalPath); err != nil {
		t.Fatal(err)
	}
	return &updater{
		manifestPath: manifestPath,
		planPath:     filepath.Join(dir, "update-plan.json"),
		journalPath:  journalPath,
		updateKeys:   []string{signer.PublicKeyHex()},
		platform:     dryRunPlatform{running: running},
	}
}

func TestADryRunPassLeavesNothingBehind(t *testing.T) {
	u := passRig(t, "0.2.9")
	u.dryRun = true
	before, err := os.ReadFile(u.journalPath)
	if err != nil {
		t.Fatal(err)
	}

	u.pass(time.Now().UTC())

	after, err := os.ReadFile(u.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("a rehearsal wrote the journal:\n before %s\n after  %s", before, after)
	}
	// The assertion that does not depend on a return value being honest.
	if entries, _ := os.ReadDir(agentupdate.ReportsDir(u.journalPath)); len(entries) != 0 {
		t.Fatalf("a rehearsal left %d file(s) in the outbox: the extension would send them and the Edge would "+
			"count them", len(entries))
	}
}

// The half that matters more: the same pass WITHOUT the flag must still do both, or this suite would pass
// against a build that simply lost the ability to record anything.
func TestARealPassStillReconcilesAndQueues(t *testing.T) {
	u := passRig(t, "0.2.9")
	before, _ := os.ReadFile(u.journalPath)

	u.pass(time.Now().UTC())

	after, _ := os.ReadFile(u.journalPath)
	if string(after) == string(before) {
		t.Fatalf("a real pass did not record the completed attempt")
	}
	if n := agentupdate.PendingReports(agentupdate.ReportsDir(u.journalPath)); n == 0 {
		t.Fatalf("a real pass queued no outcome for the fleet view")
	}
}

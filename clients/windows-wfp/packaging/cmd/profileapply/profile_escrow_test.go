//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
	"github.com/lantern-networks/dsse-core/installprofile"
)

// The tests mint envelopes with the PRODUCT'S OWN signer, so they exercise the real verification path rather
// than a hand-rolled envelope that would only prove the test and the code agree with each other.
func newIssuer(t *testing.T) (*agentpolicy.Signer, string) {
	t.Helper()
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil || signer == nil {
		t.Fatalf("signer: %v", err)
	}
	return signer, signer.PublicKeyHex()
}

// signEnvelopeWith mints one profile from a given issuer, so a test can mint a SECOND from the same key — the
// re-point case, which is the one where restoring a stale escrow would do real damage.
func signEnvelopeWith(t *testing.T, signer *agentpolicy.Signer, tenant, transport, issuedAt string) []byte {
	t.Helper()
	p := installprofile.InstallProfile{
		Kind:         installprofile.ProfileKind,
		Version:      3,
		TenantID:     tenant,
		TransportURL: transport,
		Posture:      "fail-closed",
		Backend:      "wfp",
		IssuedAt:     issuedAt,
	}
	env, err := signer.Sign(p, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func signEnvelope(t *testing.T, tenant, transport, issuedAt string) (envelope []byte, pinHex string) {
	t.Helper()
	signer, pin := newIssuer(t)
	return signEnvelopeWith(t, signer, tenant, transport, issuedAt), pin
}

func useTempEscrow(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := escrowDirOverride
	escrowDirOverride = dir
	t.Cleanup(func() { escrowDirOverride = prev })
	return dir
}

// The defect this whole file exists for: uninstall clears the config store, and before the escrow copy there
// was nothing on the device to put back. The sequence below is the measured one, with the fix in place.
func TestUninstallThenReinstallRecoversTheProfile(t *testing.T) {
	dir := useTempEscrow(t)
	env, pin := signEnvelope(t, "tenant_example", "https://edge.example:18543", "2026-08-17T04:56:40Z")
	be := configstore.NewMemoryBackend()

	if _, err := configstore.Apply(be, env, pin, "path", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := escrowProfile(env); err != nil {
		t.Fatalf("escrow: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, escrowFileName)); err != nil {
		t.Fatalf("the escrow copy was not written: %v", err)
	}

	// Uninstall.
	if err := configstore.Clear(be); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, meta, err := configstore.Load(be, pin); err != nil || meta.Present {
		t.Fatalf("after clear the store should be empty; present=%v err=%v", meta.Present, err)
	}

	// Reinstall.
	restored, line, err := restoreProfileFromEscrow(be, pin, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !restored {
		t.Fatalf("the profile was not restored; the installer would say: %s", line)
	}
	prof, meta, err := configstore.Load(be, pin)
	if err != nil {
		t.Fatalf("load after restore: %v", err)
	}
	if !meta.Verified || prof.TransportURL != "https://edge.example:18543" {
		t.Fatalf("the restored profile is not the one that was in force: verified=%v transport=%q", meta.Verified, prof.TransportURL)
	}
	// The line an operator reads has to name the transport that is now in force, not just say "ok".
	if !strings.Contains(line, "RESTORED") || !strings.Contains(line, "https://edge.example:18543") {
		t.Fatalf("the installer line does not say what is in force: %s", line)
	}
}

// Restoring must never overwrite a profile the control plane issued AFTER the escrow copy was taken. The
// re-point is the case that matters: a device that was moved to a new Edge and then reinstalled must not be
// dragged back to the old one by a stale copy on its own disk.
func TestRestoreLeavesANewerProfileAlone(t *testing.T) {
	useTempEscrow(t)
	signer, pin := newIssuer(t)
	now := time.Now().UTC().Format(time.RFC3339)
	be := configstore.NewMemoryBackend()

	// The escrow copy is taken while the device is pointed at the old Edge.
	oldEnv := signEnvelopeWith(t, signer, "org", "https://old-edge:18543", "2026-08-01T00:00:00Z")
	if _, err := configstore.Apply(be, oldEnv, pin, "path", now); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	if err := escrowProfile(oldEnv); err != nil {
		t.Fatalf("escrow old: %v", err)
	}

	// The issuer then re-points the device. Same key, later issued_at. The escrow on disk is now stale.
	newEnv := signEnvelopeWith(t, signer, "org", "https://new-edge:18543", "2026-08-20T00:00:00Z")
	if _, err := configstore.Apply(be, newEnv, pin, "path", now); err != nil {
		t.Fatalf("apply new: %v", err)
	}

	restored, line, err := restoreProfileFromEscrow(be, pin, now)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored {
		t.Fatal("a box already holding a verified profile must not be touched by the restore path")
	}
	if !strings.Contains(line, "not needed") {
		t.Fatalf("the no-op line should say nothing was changed: %s", line)
	}
	prof, _, err := configstore.Load(be, pin)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if prof.TransportURL != "https://new-edge:18543" {
		t.Fatalf("the stale escrow dragged the device back to the old Edge: %q", prof.TransportURL)
	}
}

// Even if something DOES empty the store, the anti-rollback floor still applies to the escrowed copy: it goes
// back in through configstore.Apply, not around it. Here the floor is gone with the store, so the stale copy is
// accepted — and that is the correct, stated limit of this mechanism. It restores the last profile this device
// verified; it does not know what the issuer did afterwards. A device that was re-pointed and then uninstalled
// comes back on the OLD Edge and must be re-issued, which is strictly better than not coming back at all.
func TestRestoreIsTheLastVerifiedProfileNotNecessarilyTheNewest(t *testing.T) {
	useTempEscrow(t)
	signer, pin := newIssuer(t)
	now := time.Now().UTC().Format(time.RFC3339)
	be := configstore.NewMemoryBackend()

	oldEnv := signEnvelopeWith(t, signer, "org", "https://old-edge:18543", "2026-08-01T00:00:00Z")
	if _, err := configstore.Apply(be, oldEnv, pin, "path", now); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	if err := escrowProfile(oldEnv); err != nil {
		t.Fatalf("escrow old: %v", err)
	}
	newEnv := signEnvelopeWith(t, signer, "org", "https://new-edge:18543", "2026-08-20T00:00:00Z")
	if _, err := configstore.Apply(be, newEnv, pin, "path", now); err != nil {
		t.Fatalf("apply new: %v", err)
	}
	// The escrow still holds the OLD one — escrowProfile was not called for the re-point in this test, which is
	// the pessimistic case (in the product every apply escrows, so this window is one install wide).
	if err := configstore.Clear(be); err != nil {
		t.Fatalf("clear: %v", err)
	}

	restored, _, err := restoreProfileFromEscrow(be, pin, now)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !restored {
		t.Fatal("the device should have come back on the last profile it verified")
	}
	prof, _, err := configstore.Load(be, pin)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if prof.TransportURL != "https://old-edge:18543" {
		t.Fatalf("expected the escrowed (older) profile, got %q", prof.TransportURL)
	}
}

// An escrowed envelope is re-verified on the way back in. Editing the file on disk buys an administrator a
// refusal, not a configuration — the copy is a convenience, never a second authority.
func TestATamperedEscrowIsRefusedNotApplied(t *testing.T) {
	dir := useTempEscrow(t)
	env, pin := signEnvelope(t, "org", "https://edge.example:18543", "2026-08-17T04:56:40Z")
	if err := escrowProfile(env); err != nil {
		t.Fatalf("escrow: %v", err)
	}
	// Flip the transport inside the signed payload's envelope by corrupting the payload wholesale.
	tampered := strings.Replace(string(env), `"payload_b64":"`, `"payload_b64":"eyJraW5kIjoi`, 1)
	if err := os.WriteFile(filepath.Join(dir, escrowFileName), []byte(tampered), 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	be := configstore.NewMemoryBackend()
	restored, _, err := restoreProfileFromEscrow(be, pin, time.Now().UTC().Format(time.RFC3339))
	if err == nil {
		t.Fatal("a tampered escrow must be refused loudly, not applied and not silently skipped")
	}
	if restored {
		t.Fatal("a tampered escrow was restored")
	}
	if !strings.Contains(err.Error(), "refused on re-verification") {
		t.Fatalf("the refusal does not say the escrow was the thing refused: %v", err)
	}
	if _, meta, e := configstore.Load(be, pin); e == nil && meta.Present {
		t.Fatal("the store was written from a tampered escrow")
	}
}

// A device that has never had a profile is not a fault, but it IS the device that cannot recover from an
// uninstall — so the installer log has to say so instead of staying quiet.
func TestNoEscrowSaysWhatTheDeviceNeeds(t *testing.T) {
	useTempEscrow(t)
	_, pin := signEnvelope(t, "org", "https://edge.example:18543", "")
	be := configstore.NewMemoryBackend()

	restored, line, err := restoreProfileFromEscrow(be, pin, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("a missing escrow is a fact about the device, not an error: %v", err)
	}
	if restored {
		t.Fatal("nothing should have been restored")
	}
	if !strings.Contains(line, "no escrowed copy") || !strings.Contains(line, "--apply") {
		t.Fatalf("the line does not tell the operator what to do next: %s", line)
	}
}

// Write-then-rename: the escrow is only ever read on a recovery path where nobody is watching, so a truncated
// file there reads as "the profile is just gone".
func TestEscrowLeavesNoTemporaryFilesBehind(t *testing.T) {
	dir := useTempEscrow(t)
	env, _ := signEnvelope(t, "org", "https://edge.example:18543", "2026-08-17T04:56:40Z")
	for i := 0; i < 3; i++ {
		if err := escrowProfile(env); err != nil {
			t.Fatalf("escrow %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != escrowFileName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("escrow left temporary files behind: %v", names)
	}
	got, err := os.ReadFile(filepath.Join(dir, escrowFileName))
	if err != nil {
		t.Fatalf("read escrow: %v", err)
	}
	if string(got) != string(env) {
		t.Fatal("the escrowed bytes are not the envelope that was applied")
	}
}

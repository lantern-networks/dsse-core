package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★ THE PUBLIC HALF IS WHAT AN AGENT PACKAGE IS BUILT WITH. Without it nobody can produce an agent that
// trusts this deployment, and the only place it could be read was an Edge's start-up log. A deployment whose
// key predates this installer — every deployment that let an Edge generate one — never received the file,
// because the mint step returned early the moment the key existed.
func TestTheDeploymentGetsThePublicHalfEvenWhenTheKeyAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	keyPath := filepath.Join(dir, agentPolicySigningKeyFile)
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeAgentPolicySigningKey(dir); err != nil {
		t.Fatalf("write: %v", err)
	}

	pubPath := filepath.Join(dir, agentPolicySigningPublicFile)
	got, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("the public half was not written beside a key that already existed: %v", err)
	}
	want := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("public half %q does not belong to the key on disk (want %q)", strings.TrimSpace(string(got)), want)
	}

	// ★ AND THE SEED IS UNTOUCHED. Replacing it would orphan every device that has already pinned the public
	// half — the failure this early return was protecting against, which must survive the fix.
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(after)) != hex.EncodeToString(seed) {
		t.Fatalf("the existing signing key was replaced; every device pinned to the old one is now orphaned")
	}
}

// The guard: a key this installer mints itself also gets its public half, so the check above is about the
// pre-existing case and not about the file being written at all.
func TestAMintedKeyAlsoLeavesItsPublicHalf(t *testing.T) {
	dir := t.TempDir()
	if err := writeAgentPolicySigningKey(dir); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, agentPolicySigningKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("the minted key is not a hex seed: %v", err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, agentPolicySigningPublicFile))
	if err != nil {
		t.Fatalf("a minted key left no public half: %v", err)
	}
	want := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if strings.TrimSpace(string(pub)) != want {
		t.Fatalf("public half %q does not belong to the minted key", strings.TrimSpace(string(pub)))
	}
}

// A key this installer cannot read the shape of (the HSM lane holds other shapes) must not make a supported
// deployment uninstallable — it says what was not written instead.
func TestAKeyOfAnotherShapeDoesNotFailTheInstall(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, agentPolicySigningKeyFile),
		[]byte("-----BEGIN PRIVATE KEY-----\nnot-hex\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentPolicySigningKey(dir); err != nil {
		t.Fatalf("an unreadable key shape failed the install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, agentPolicySigningPublicFile)); err == nil {
		t.Fatalf("a public half was written for a key whose seed could not be read — it would be wrong, and an " +
			"agent built against it would refuse everything this deployment signs")
	}
}

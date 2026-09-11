package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/installprofile"
)

// ★★★ THE DEFECT THIS COMMAND EXISTS TO END (2026-08-29). The macOS installer decoded the profile without
// checking its signature, took deployment.agent_policy_signing_public_key out of the decoded body, and wrote
// that as the pin the profile would be verified against. A profile substituted anywhere between the Console
// and the device — signed by whoever substituted it — verified perfectly, and the profile decides the door,
// the anchors that door is verified against, which keys may sign this device's updates, and which processes
// are exempt from steering.
//
// So the property under test is not "a good profile verifies". It is "a profile signed by a key the operator
// did not place is REFUSED, however convincingly it names itself".
// newTestSigner makes a throwaway deployment signing key. The package exposes loaders rather than a
// constructor, so the test builds one the same way a deployment's key file would be loaded.
func newTestSigner() (*agentpolicy.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return agentpolicy.NewSignerFromCrypto(priv)
}

func writeProfile(t *testing.T, dir string, signer *agentpolicy.Signer, claimedKey string) string {
	t.Helper()
	p := installprofile.SafeDefaults()
	p.TenantID = "tenant_test"
	p.TransportURL = "https://agents.example.test"
	p.Deployment = installprofile.DeploymentSpec{AgentPolicySigningPublicKey: claimedKey}
	env, err := installprofile.Sign(signer, p, time.Now().UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "install_profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func buildVerifier(t *testing.T, dir string) string {
	t.Helper()
	// The suffix is not cosmetic: without it "go build -o" writes a file Windows will not execute, and the
	// test fails as "executable file not found in %PATH%" -- a refusal that looks like the verifier rejecting
	// the profile rather than the harness never running it. Every CI runner is green; the Windows box alone is
	// red, for a reason that is not about this code (2026-08-14).
	bin := filepath.Join(dir, "dsse-profileverify")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestAProfileSignedByItsOwnClaimedKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	deployment, err := newTestSigner()
	if err != nil {
		t.Fatalf("deployment signer: %v", err)
	}
	attacker, err := newTestSigner()
	if err != nil {
		t.Fatalf("attacker signer: %v", err)
	}
	attackerKey := attacker.PublicKeyHex()

	// The forged profile is signed by the attacker AND names the attacker's key as the deployment's. Every
	// field inside it agrees with every other field. Only the operator's file disagrees.
	forged := writeProfile(t, dir, attacker, attackerKey)

	pin := filepath.Join(dir, "profile_signing_key.txt")
	if err := os.WriteFile(pin, []byte(deployment.PublicKeyHex()+"\n"), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}

	bin := buildVerifier(t, dir)
	out, err := exec.Command(bin, "-profile", forged, "-pin", pin).CombinedOutput()
	if err == nil {
		t.Fatalf("a profile signed by its own claimed key was ACCEPTED; output: %s", out)
	}
	if len(out) == 0 {
		t.Fatal("it refused and said nothing — an operator cannot act on an empty refusal")
	}
}

func TestTheDeploymentsOwnProfileIsAccepted(t *testing.T) {
	dir := t.TempDir()
	deployment, err := newTestSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	key := deployment.PublicKeyHex()
	genuine := writeProfile(t, dir, deployment, key)
	pin := filepath.Join(dir, "profile_signing_key.txt")
	if err := os.WriteFile(pin, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	bin := buildVerifier(t, dir)
	out, err := exec.Command(bin, "-profile", genuine, "-pin", pin).Output()
	if err != nil {
		t.Fatalf("the deployment's own profile was refused: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatalf("what it printed is not the payload: %v (%s)", err, out)
	}
	if body["tenant_id"] != "tenant_test" {
		t.Fatalf("it printed a payload for %v", body["tenant_id"])
	}
}

func TestNoPinDerivesNothing(t *testing.T) {
	dir := t.TempDir()
	signer, err := newTestSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	genuine := writeProfile(t, dir, signer, signer.PublicKeyHex())
	bin := buildVerifier(t, dir)
	if out, err := exec.Command(bin, "-profile", genuine, "-pin", filepath.Join(dir, "absent.txt")).CombinedOutput(); err == nil {
		t.Fatalf("a missing pin was treated as no pin required; output: %s", out)
	}
}

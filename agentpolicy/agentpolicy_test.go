package agentpolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	signer, err := LoadOrGenerateSigner("", true) // lab ephemeral key
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	payload := map[string]any{
		"schema_version":           EnvelopeType,
		"device_identity":          "mac-dev-1",
		"excluded_app_signing_ids": []string{"com.example.vpn"},
	}
	env, err := signer.Sign(payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != EnvelopeType || env.SigningKeyID != signer.KeyID() {
		t.Fatalf("envelope metadata wrong: %+v", env)
	}
	got, err := Verify(env, signer.PublicKeyHex())
	if err != nil {
		t.Fatalf("valid envelope must verify: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["device_identity"] != "mac-dev-1" {
		t.Fatalf("verified payload wrong: %v", parsed)
	}

	// Tamper with the payload (keeping the old checksum) -> must fail.
	tampered := env
	tampered.PayloadB64 = "eyJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmF0dGFja2VyIl19"
	if _, err := Verify(tampered, signer.PublicKeyHex()); err == nil {
		t.Fatal("a tampered payload must fail verification")
	}

	// Wrong pinned key -> must fail.
	other, _ := LoadOrGenerateSigner("", true)
	if _, err := Verify(env, other.PublicKeyHex()); err == nil {
		t.Fatal("an untrusted key must fail verification")
	}
}

func TestSigningKeyPersists(t *testing.T) {
	path := t.TempDir() + "/key.hex"
	s1, err := LoadOrGenerateSigner(path, true)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrGenerateSigner(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if s1.PublicKeyHex() != s2.PublicKeyHex() || s1.KeyID() != s2.KeyID() {
		t.Fatal("the signing key must be stable across reloads (persisted seed)")
	}
}

// Review #34: a read error that is NOT "file absent" must fail loud and leave the seed UNTOUCHED — the old
// code treated every read error as absent and overwrote the seed, silently rotating the signing identity and
// locking out every endpoint that pinned the old public key. A write-only (0o200) file makes os.ReadFile
// fail with EACCES (non-IsNotExist) while os.WriteFile would still succeed — the exact overwrite scenario.
// Unix-perm dependent, so it is skipped on Windows (which ignores 0o200); Linux CI is the enforcing check.
func TestSigningKeyReadErrorFailsLoudWithoutOverwrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on Unix file permissions to make a file read-fail but write-succeed")
	}
	path := t.TempDir() + "/key.hex"
	// A valid existing seed the fix must NOT clobber on a read failure.
	original := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := os.WriteFile(path, []byte(original), 0o200); err != nil { // write-only: read will EACCES
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateSigner(path, true); err == nil {
		t.Fatal("a non-absent read error must fail loud, not regenerate + overwrite the seed")
	}
	// Make it readable again and confirm the ORIGINAL seed is intact (never overwritten).
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != original {
		t.Fatal("the seed file was overwritten on a read error — the signing identity was silently rotated")
	}
}

// The macOS NE (Swift/CryptoKit) verifies the very same Go-produced fixture in
// DSSESignedAgentPolicyTests.swift. Verifying it here too keeps the Go and Swift verifiers — and
// now the Windows agent, which uses this Go verifier — byte-compatible.
func TestCrossLanguageFixtureVerifies(t *testing.T) {
	const pubKeyHex = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"
	const envelopeJSON = `{"type":"dsse_agent_steer_policy.v1","version":"1","signing_key_id":"edge-agent-policy-65b60673d6ed884b","created_at":"2026-06-19T00:00:00Z","payload_sha256":"d36582e645945d1ff924a9e9b8ca298cbbe9a2891131fcf0c3b2fc040e17ff9c","payload_b64":"eyJkZXZpY2VfZ3JvdXAiOiIiLCJkZXZpY2VfaWRlbnRpdHkiOiJtYWMtZGV2LTEiLCJleGNsdWRlZF9hcHBfc2lnbmluZ19pZHMiOlsiY29tLmNvcnAudnBuY2xpZW50IiwiY29tLmV4YW1wbGUuZGV2dG9vbCJdLCJzY2hlbWFfdmVyc2lvbiI6ImRvbWVzdGljX3NzZV9hZ2VudF9zdGVlcl9wb2xpY3kudjEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnRfdHJhY2tfYV91YzAzYV9sYWIifQ==","signature":"ed25519:rOnMYYF_h9O6iWoBsSq8y2qmZ3KleakbjkRbpooZMsPNi6tXW_WrBcQ64DoVy4rRJUiNpIIdQf2LKlA7ACjbDQ"}`
	var env Envelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		t.Fatal(err)
	}
	payload, err := Verify(env, pubKeyHex)
	if err != nil {
		t.Fatalf("Go-signed cross-language fixture must verify: %v", err)
	}
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	want := []string{"com.corp.vpnclient", "com.example.devtool"}
	if !reflect.DeepEqual(p.ExcludedAppSigningIDs, want) {
		t.Fatalf("excluded ids = %v, want %v", p.ExcludedAppSigningIDs, want)
	}
}

func TestFetchVerifiedExclusionsOverHTTP(t *testing.T) {
	signer, _ := LoadOrGenerateSigner("", true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pubKeyPath:
			json.NewEncoder(w).Encode(PubKey{KeyID: signer.KeyID(), PublicKey: signer.PublicKeyHex()})
		case policyPath:
			env, _ := signer.Sign(map[string]any{
				"schema_version":           EnvelopeType,
				"tenant_id":                "tenant_swg_lab",
				"device_identity":          "win-dev-1",
				"excluded_app_signing_ids": []string{"corpvpn.exe", "backup-agent.exe"},
			}, time.Now())
			json.NewEncoder(w).Encode(env)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	// Provision: fetch the pin (TOFU lab step), then verify against it.
	pk, err := FetchPubKey(ctx, srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := FetchVerifiedExclusions(ctx, srv.Client(), srv.URL, pk.PublicKey)
	if err != nil {
		t.Fatalf("fetch+verify: %v", err)
	}
	if p.DeviceIdentity != "win-dev-1" || !reflect.DeepEqual(p.ExcludedAppSigningIDs, []string{"corpvpn.exe", "backup-agent.exe"}) {
		t.Fatalf("verified payload wrong: %+v", p)
	}

	// A wrong pin must be rejected (tamper-resistance).
	if _, err := FetchVerifiedExclusions(ctx, srv.Client(), srv.URL,
		"0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("a policy verified against the wrong pin must be rejected")
	}
}

func TestMergeExclusionsIsAdditiveAndDeduped(t *testing.T) {
	// Loop-prevention infra (the agent self + a co-located edge egress) must SURVIVE the server set.
	local := []string{"windivert-steer.exe", "limactl"}
	server := []string{"corpvpn.exe", "LIMACTL", "backup-agent.exe"} // LIMACTL dupes local case-insensitively
	got := MergeExclusions(local, server)
	want := []string{"windivert-steer.exe", "limactl", "corpvpn.exe", "backup-agent.exe"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v, want %v (infra first, additive, deduped)", got, want)
	}
	// Empty server set leaves the infra list intact (no signed policy => local only).
	if got := MergeExclusions(local, nil); !reflect.DeepEqual(got, local) {
		t.Fatalf("with no server set, infra list must be returned unchanged: %v", got)
	}
}

// The signing key's file mode. This key signs the policy every agent applies, and its public half is PINNED
// by every agent — anyone who can read it can sign policy the whole fleet accepts. The reference deployment
// was found carrying it at 0644 with nothing anywhere saying so. Production refuses; lab warns and runs, so
// a lab does not become something to work around.
func TestLoadOrGenerateSignerRefusesAWorldReadableKeyInProduction(t *testing.T) {
	// Unix file modes: Windows has no POSIX permission bits (0600 reads back as 0666), so the guard this
	// tests cannot apply there and the check is skipped rather than reported as a failure.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.hex")
	seed := strings.Repeat("ab", ed25519.SeedSize)
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	// A restrictive umask must not turn this refusal fixture into a safe key.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerateSigner(path, false); err == nil {
		t.Fatal("production must refuse a signing key readable beyond its owner")
	} else if !strings.Contains(err.Error(), "readable beyond its owner") {
		t.Fatalf("the refusal must say what is wrong, got: %v", err)
	}

	// Dev mode keeps running — and still returns a working signer, so the warning is not a disguised failure.
	signer, err := LoadOrGenerateSigner(path, true)
	if err != nil || signer == nil {
		t.Fatalf("devMode must continue with a warning: signer=%v err=%v", signer, err)
	}

	// Tightened: accepted everywhere.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateSigner(path, false); err != nil {
		t.Fatalf("a 0600 key must load in production: %v", err)
	}
}

// A key this process generates is owner-only from the start; nothing should have to tighten it afterwards.
func TestLoadOrGenerateSignerWritesAnOwnerOnlyKey(t *testing.T) {
	// Unix file modes: Windows has no POSIX permission bits (0600 reads back as 0666), so the guard this
	// tests cannot apply there and the check is skipped rather than reported as a failure.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "fresh.hex")
	if _, err := LoadOrGenerateSigner(path, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("a generated signing key must be owner-only, got %04o", mode)
	}
}

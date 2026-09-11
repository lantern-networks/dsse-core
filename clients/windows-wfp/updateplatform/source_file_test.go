package updateplatform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func newSigner(t *testing.T) (*agentpolicy.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s, s.PublicKeyHex()
}

func signedManifestFile(t *testing.T, signer *agentpolicy.Signer, m agentupdate.Manifest, now time.Time) string {
	t.Helper()
	env, err := agentupdate.Sign(signer, m, now)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	p := filepath.Join(t.TempDir(), ManifestFileName)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	return p
}

func srcManifest(body []byte) agentupdate.Manifest {
	sum := sha256.Sum256(body)
	now := time.Now().UTC()
	return agentupdate.Manifest{
		Schema:         agentupdate.SchemaVersion,
		Version:        "0.2.0",
		Platform:       agentupdate.PlatformWindows,
		Arch:           agentupdate.ArchAMD64,
		Channel:        "stable",
		Delivery:       agentupdate.DeliveryDSSE,
		ArtifactKind:   agentupdate.ArtifactKindMSI,
		ArtifactURL:    "https://example.test/dsse-agent-0.2.0.msi",
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		ArtifactSize:   int64(len(body)),
		ReleasedAt:     now.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:       now.Add(720 * time.Hour).Format(time.RFC3339),
	}
}

func TestFileSourceOpensASignedManifest(t *testing.T) {
	now := time.Now().UTC()
	signer, pub := newSigner(t)
	want := srcManifest([]byte("payload"))
	p := signedManifestFile(t, signer, want, now)

	got, err := FileManifestSource{Path: p, TrustedKeys: []string{pub}}.Fetch(context.Background(), now)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Version != want.Version || got.ArtifactSHA256 != want.ArtifactSHA256 {
		t.Fatalf("Fetch returned %+v, want version %s / digest %s", got, want.Version, want.ArtifactSHA256)
	}
}

// TestAbsentFileIsQuiet: a device with nothing published is the normal state, and it must not read as a
// fault — most devices, most of the time.
func TestAbsentFileIsQuiet(t *testing.T) {
	_, pub := newSigner(t)
	src := FileManifestSource{Path: filepath.Join(t.TempDir(), "nothing-here.json"), TrustedKeys: []string{pub}}
	if _, err := src.Fetch(context.Background(), time.Now()); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err = %v, want ErrNoManifest", err)
	}
}

// TestAManifestSignedByTheWrongKeyIsRefused is the property that makes reading from a file acceptable at all:
// whoever writes the file does not have to be trusted, because this is what decides.
func TestAManifestSignedByTheWrongKeyIsRefused(t *testing.T) {
	now := time.Now().UTC()
	attacker, _ := newSigner(t)
	_, realPub := newSigner(t)
	p := signedManifestFile(t, attacker, srcManifest([]byte("payload")), now)

	_, err := FileManifestSource{Path: p, TrustedKeys: []string{realPub}}.Fetch(context.Background(), now)
	if err == nil {
		t.Fatal("a manifest signed by an untrusted key was accepted")
	}
	if !errors.Is(err, agentupdate.ErrUntrusted) {
		t.Fatalf("err = %v, want ErrUntrusted", err)
	}
}

// TestNoTrustedKeysIsAConfigurationError, not "trust everything". A verifier with no keys that accepts
// anything is worse than no verifier, because it looks like one.
func TestNoTrustedKeysIsAConfigurationError(t *testing.T) {
	now := time.Now().UTC()
	signer, _ := newSigner(t)
	p := signedManifestFile(t, signer, srcManifest([]byte("payload")), now)

	_, err := FileManifestSource{Path: p}.Fetch(context.Background(), now)
	if err == nil {
		t.Fatal("a manifest was opened with no trusted keys configured")
	}
	if errors.Is(err, ErrNoManifest) {
		t.Fatal("a missing-keys misconfiguration was reported as 'nothing published', which hides it")
	}
	if !strings.Contains(err.Error(), "trusted") {
		t.Fatalf("error does not name the misconfiguration: %v", err)
	}
}

// TestAnExpiredManifestIsRefused: not_after is what bounds replay, and replay is the one thing a signature
// alone does not stop — a manifest from six months ago is still validly signed.
func TestAnExpiredManifestIsRefused(t *testing.T) {
	signedAt := time.Now().UTC().Add(-90 * 24 * time.Hour)
	signer, pub := newSigner(t)
	m := srcManifest([]byte("payload"))
	m.ReleasedAt = signedAt.Format(time.RFC3339)
	m.NotAfter = signedAt.Add(24 * time.Hour).Format(time.RFC3339)
	p := signedManifestFile(t, signer, m, signedAt)

	_, err := FileManifestSource{Path: p, TrustedKeys: []string{pub}}.Fetch(context.Background(), time.Now().UTC())
	if !errors.Is(err, agentupdate.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// TestGarbageIsReportedNotSwallowed: a fleet that is not updating must never do so silently. A malformed drop
// is something an operator has to be told about.
func TestGarbageIsReportedNotSwallowed(t *testing.T) {
	_, pub := newSigner(t)
	p := filepath.Join(t.TempDir(), ManifestFileName)
	if err := os.WriteFile(p, []byte("this is not an envelope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := FileManifestSource{Path: p, TrustedKeys: []string{pub}}.Fetch(context.Background(), time.Now())
	if err == nil {
		t.Fatal("a malformed manifest file was accepted")
	}
	if errors.Is(err, ErrNoManifest) {
		t.Fatal("a malformed manifest was reported as 'nothing published', so a stalled fleet would have no visible cause")
	}
}

func TestDefaultManifestPathIsUnderProgramData(t *testing.T) {
	t.Setenv("ProgramData", filepath.Join("X:", "PD"))
	want := filepath.Join("X:", "PD", "DSSE", ManifestFileName)
	if got := DefaultManifestPath(); got != want {
		t.Fatalf("DefaultManifestPath = %q, want %q", got, want)
	}
}

// ★ Refusals and faults must be distinguishable by the caller that reports, because the responses differ: one
// needs a person tonight, the other may fix itself. By the time a classifier sees an error the distinction is
// gone unless it is carried in the error itself.
func TestARefusedManifestIsDistinguishableFromAFaultAndKeepsItsReason(t *testing.T) {
	signer, signerKey := newSigner(t)
	_, otherKey := newSigner(t)
	path := signedManifestFile(t, signer, srcManifest([]byte("payload")), time.Now().UTC())

	// Signed by a key this device does not pin.
	_, ferr := FileManifestSource{Path: path, TrustedKeys: []string{otherKey}}.Fetch(context.Background(), time.Now().UTC())
	if !errors.Is(ferr, ErrManifestRejected) {
		t.Fatalf("err = %v, want ErrManifestRejected", ferr)
	}
	// The sentinel must not swallow the SPECIFIC reason: an operator asking "why" gets it from the chain.
	if !errors.Is(ferr, agentupdate.ErrUntrusted) {
		t.Fatalf("the specific reason was lost behind the sentinel: %v", ferr)
	}

	// A device with nothing published is not refusing anything.
	_, nerr := FileManifestSource{Path: filepath.Join(t.TempDir(), "absent.json"), TrustedKeys: []string{signerKey}}.
		Fetch(context.Background(), time.Now().UTC())
	if errors.Is(nerr, ErrManifestRejected) {
		t.Fatalf("an absent manifest was reported as a refusal: %v", nerr)
	}
	if !errors.Is(nerr, ErrNoManifest) {
		t.Fatalf("err = %v, want ErrNoManifest", nerr)
	}
}

// No keys is a configuration error and must be loud, not a quiet device. It is a refusal because the outcome
// is the same — this box will never update — and because nothing else will ever say so.
func TestNoTrustedKeysIsAReportedRefusal(t *testing.T) {
	_, err := FileManifestSource{Path: "irrelevant"}.Fetch(context.Background(), time.Now().UTC())
	if !errors.Is(err, ErrManifestRejected) {
		t.Fatalf("err = %v, want ErrManifestRejected", err)
	}
	if !strings.Contains(err.Error(), "never update") {
		t.Fatalf("the message must state the consequence, got %q", err)
	}
}

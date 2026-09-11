package agentupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

var testNow = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func newTestSigner(t *testing.T) (*agentpolicy.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, signer.PublicKeyHex()
}

// artifact returns some bytes plus the digest/size a manifest must declare for them.
func artifact(body string) (string, int64) {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]), int64(len(body))
}

func goodManifest() Manifest {
	digest, size := artifact("the-msi-bytes")
	return Manifest{
		Schema:         SchemaVersion,
		Version:        "0.2.0",
		Platform:       PlatformWindows,
		Arch:           ArchAMD64,
		Channel:        "stable",
		Delivery:       DeliveryDSSE,
		ArtifactKind:   ArtifactKindMSI,
		ArtifactURL:    "https://releases.example.test/dsse-steer-0.2.0-amd64.msi",
		ArtifactSHA256: digest,
		ArtifactSize:   size,
		MinFromVersion: "0.1.0",
		ReleasedAt:     "2026-08-09T00:00:00Z",
		NotAfter:       "2026-11-09T00:00:00Z",
	}
}

func TestOpenAcceptsAWellFormedSignedManifest(t *testing.T) {
	signer, pub := newTestSigner(t)
	env, err := Sign(signer, goodManifest(), testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if env.Type != EnvelopeType {
		t.Fatalf("envelope type = %q, want %q", env.Type, EnvelopeType)
	}
	got, err := Open(env, []string{pub}, testNow)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Version != "0.2.0" || got.ArtifactSize != goodManifest().ArtifactSize {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	if err := got.Applicable("0.1.0+fb5ed5e7", PlatformWindows, ArchAMD64); err != nil {
		t.Fatalf("applicable: %v", err)
	}
	if err := VerifyArtifact(strings.NewReader("the-msi-bytes"), got); err != nil {
		t.Fatalf("verify artifact: %v", err)
	}
}

// The step-1 acceptance condition: a manifest whose signature was altered and an artifact whose hash does not
// match are BOTH refused, and refused for DIFFERENT reasons. Asserting only "an error came back" would pass
// against code that refuses everything, which is the failure mode a negative test is most likely to have.
func TestTamperedSignatureAndBadArtifactAreRefusedForDifferentReasons(t *testing.T) {
	signer, pub := newTestSigner(t)
	m := goodManifest()
	env, err := Sign(signer, m, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// (1) one byte of the signature flipped.
	tampered := env
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(env.Signature, agentpolicy.SignaturePrefix))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	raw[0] ^= 0x01
	tampered.Signature = agentpolicy.SignaturePrefix + base64.RawURLEncoding.EncodeToString(raw)

	_, sigErr := Open(tampered, []string{pub}, testNow)
	if !errors.Is(sigErr, ErrUntrusted) {
		t.Fatalf("tampered signature: got %v, want ErrUntrusted", sigErr)
	}

	// (2) signature intact, but the bytes on disk are not the ones the manifest names.
	opened, err := Open(env, []string{pub}, testNow)
	if err != nil {
		t.Fatalf("open untampered: %v", err)
	}
	artErr := VerifyArtifact(strings.NewReader("not-the-msi!"), opened)
	if !errors.Is(artErr, ErrArtifactDigestMismatch) && !errors.Is(artErr, ErrArtifactSizeMismatch) {
		t.Fatalf("bad artifact: got %v, want a digest/size mismatch", artErr)
	}

	// The two must be distinguishable, which is the whole point.
	if errors.Is(sigErr, ErrArtifactDigestMismatch) || errors.Is(artErr, ErrUntrusted) {
		t.Fatalf("refusal reasons are not distinct: sig=%v artifact=%v", sigErr, artErr)
	}
}

// Same length, different bytes: the size check must not be what catches this, or the digest check is untested.
func TestArtifactOfTheRightLengthButWrongBytesIsRefusedByDigest(t *testing.T) {
	m := goodManifest()
	same := strings.Repeat("x", int(m.ArtifactSize))
	err := VerifyArtifact(strings.NewReader(same), m)
	if !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("got %v, want ErrArtifactDigestMismatch", err)
	}
}

func TestTruncatedAndOverlongArtifactsAreRefusedBySize(t *testing.T) {
	m := goodManifest()
	if err := VerifyArtifact(strings.NewReader("the-msi-byte"), m); !errors.Is(err, ErrArtifactSizeMismatch) {
		t.Fatalf("truncated: got %v, want ErrArtifactSizeMismatch", err)
	}
	// A reader yielding a superset that STARTS with the signed bytes is the dangerous case: stopping at the
	// declared length would hash a matching prefix and pass.
	if err := VerifyArtifact(strings.NewReader("the-msi-bytes-and-more"), m); !errors.Is(err, ErrArtifactSizeMismatch) {
		t.Fatalf("overlong: got %v, want ErrArtifactSizeMismatch", err)
	}
}

// A signature made by the right key over the WRONG kind of artefact must not be accepted here. agentpolicy's
// crypto does not look at the envelope type, so this is the only thing standing between a steer policy and an
// update manifest when one key signs both.
func TestASignedSteerPolicyIsNotAcceptedAsAnUpdateManifest(t *testing.T) {
	signer, pub := newTestSigner(t)
	env, err := signer.Sign(map[string]any{"exclusions": []string{"/usr/bin/ssh"}}, testNow)
	if err != nil {
		t.Fatalf("sign policy: %v", err)
	}
	if _, err := agentpolicy.Verify(env, pub); err != nil {
		t.Fatalf("precondition: the policy envelope must itself be crypto-valid, got %v", err)
	}
	if _, err := Open(env, []string{pub}, testNow); !errors.Is(err, ErrWrongEnvelopeType) {
		t.Fatalf("got %v, want ErrWrongEnvelopeType", err)
	}
}

func TestAnUnknownKeyIsRefused(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, otherPub := newTestSigner(t)
	env, err := Sign(signer, goodManifest(), testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Open(env, []string{otherPub}, testNow); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	// An empty key set must be a refusal, never a pass — "nothing to check against" must not read as "checked".
	if _, err := Open(env, nil, testNow); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("empty keyring: got %v, want ErrUntrusted", err)
	}
}

func TestAnExpiredManifestIsRefused(t *testing.T) {
	signer, pub := newTestSigner(t)
	env, err := Sign(signer, goodManifest(), testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	late := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Open(env, []string{pub}, late); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

// R2.3: the update channel must not be usable as a configuration channel. A payload carrying an extra field
// is refused rather than ignored, so a newer manifest cannot smuggle a setting past an older agent.
func TestAManifestCarryingAnUndefinedFieldIsRefused(t *testing.T) {
	signer, pub := newTestSigner(t)
	payload, err := json.Marshal(goodManifest())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["service_args"] = "--fail-open" // exactly the thing that must never ride this path
	smuggled, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal smuggled: %v", err)
	}
	env, err := signer.SignTyped(EnvelopeType, json.RawMessage(smuggled), testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Open(env, []string{pub}, testNow); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed for an undefined field", err)
	}
}

func TestApplicableRefusesDowngradeSameVersionAndTooOldAnOrigin(t *testing.T) {
	m := goodManifest() // publishes 0.2.0, min_from 0.1.0

	if err := m.Applicable("0.3.0", PlatformWindows, ArchAMD64); !errors.Is(err, ErrNotAnUpgrade) {
		t.Fatalf("downgrade: got %v, want ErrNotAnUpgrade", err)
	}
	// Build metadata is ignored, so a different build of the SAME version is not an upgrade. This asserts the
	// documented limitation rather than pretending it is not there.
	if err := m.Applicable("0.2.0+deadbeef", PlatformWindows, ArchAMD64); !errors.Is(err, ErrNotAnUpgrade) {
		t.Fatalf("same core version: got %v, want ErrNotAnUpgrade", err)
	}
	if err := m.Applicable("0.0.9", PlatformWindows, ArchAMD64); !errors.Is(err, ErrMinFromNotMet) {
		t.Fatalf("too old: got %v, want ErrMinFromNotMet", err)
	}
	if err := m.Applicable("0.1.0", PlatformDarwin, ArchAMD64); !errors.Is(err, ErrPlatformMismatch) {
		t.Fatalf("platform: got %v, want ErrPlatformMismatch", err)
	}
	if err := m.Applicable("0.1.0", PlatformWindows, ArchARM64); !errors.Is(err, ErrArchMismatch) {
		t.Fatalf("arch: got %v, want ErrArchMismatch", err)
	}
}

// An unreadable version must not silently read as 0.0.0 and make the endpoint a candidate for everything.
func TestAnUnparseableRunningVersionIsAnErrorNotAZero(t *testing.T) {
	m := goodManifest()
	for _, bad := range []string{"", "wfp-steer", "0.1", "0.1.x", "01.2.3", "0.1.0+"} {
		if err := m.Applicable(bad, PlatformWindows, ArchAMD64); !errors.Is(err, ErrMalformed) {
			t.Fatalf("running version %q: got %v, want ErrMalformed", bad, err)
		}
	}
}

// The unstamped default must sort below every real build, so an unstamped agent reads as needing an update.
func TestUnstampedDevVersionIsOlderThanEveryRelease(t *testing.T) {
	dev, err := ParseVersion("0.0.0-dev")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rel, err := ParseVersion("0.1.0+20260808104421")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if CompareVersions(dev, rel) >= 0 {
		t.Fatalf("0.0.0-dev must sort below 0.1.0")
	}
	zero, _ := ParseVersion("0.0.0")
	if CompareVersions(dev, zero) >= 0 {
		t.Fatalf("a pre-release must sort below its own core release")
	}
}

// The two versions the live fleet actually reports today must parse, and must compare as equal cores — the
// mac stamps a timestamp and Windows a commit, and neither is an ordering.
func TestTheVersionsTheLiveFleetReportsParse(t *testing.T) {
	mac, err := ParseVersion("0.1.0+20260808104421")
	if err != nil {
		t.Fatalf("macOS stamp: %v", err)
	}
	win, err := ParseVersion("0.1.0+fb5ed5e7.dirty")
	if err != nil {
		t.Fatalf("windows stamp: %v", err)
	}
	if CompareVersions(mac, win) != 0 {
		t.Fatalf("build metadata must not affect ordering")
	}
	if !win.Dirty() || mac.Dirty() {
		t.Fatalf("dirty detection wrong: win=%v mac=%v", win.Dirty(), mac.Dirty())
	}
}

func TestValidateRefusesADirtyBuildAsAReleaseTarget(t *testing.T) {
	m := goodManifest()
	m.Version = "0.2.0+fb5ed5e7.dirty"
	if err := m.Validate(); !errors.Is(err, ErrDirtyTarget) {
		t.Fatalf("got %v, want ErrDirtyTarget", err)
	}
}

func TestDeliveryModes(t *testing.T) {
	mdm := goodManifest()
	mdm.Delivery = DeliveryMDM
	mdm.ArtifactURL = ""
	if err := mdm.Validate(); err != nil {
		t.Fatalf("delivery=mdm without a URL must be valid: %v", err)
	}
	// Still carries the digest, so the agent can report whether what the MDM installed is what was authorised.
	if mdm.ArtifactSHA256 == "" {
		t.Fatalf("delivery=mdm must still pin a digest")
	}

	mdmWithURL := mdm
	mdmWithURL.ArtifactURL = "https://releases.example.test/x.pkg"
	if err := mdmWithURL.Validate(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("delivery=mdm with a URL must be refused, got %v", err)
	}

	noURL := goodManifest()
	noURL.ArtifactURL = ""
	if err := noURL.Validate(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("delivery=dsse without a URL must be refused, got %v", err)
	}
	plain := goodManifest()
	plain.ArtifactURL = "http://releases.example.test/x.msi"
	if err := plain.Validate(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a non-https artifact_url must be refused, got %v", err)
	}
}

func TestSignRefusesToSignAnInvalidManifest(t *testing.T) {
	signer, _ := newTestSigner(t)
	bad := goodManifest()
	bad.ArtifactSize = 0
	if _, err := Sign(signer, bad, testNow); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// The envelope must stay byte-compatible with the steer-policy scheme the Swift and Windows verifiers already
// implement, or "reuse the existing verifier" is not true. This checks the wire shape, not the crypto.
func TestEnvelopeStaysCompatibleWithTheSteerPolicyWireScheme(t *testing.T) {
	signer, pub := newTestSigner(t)
	env, err := Sign(signer, goodManifest(), testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		t.Fatalf("payload_b64 must be standard base64: %v", err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != env.PayloadSHA256 {
		t.Fatalf("payload_sha256 must be hex(sha256(payload bytes))")
	}
	if !strings.HasPrefix(env.Signature, agentpolicy.SignaturePrefix) {
		t.Fatalf("signature prefix = %q", env.Signature)
	}
	// The generic verifier must still verify it; only the type distinguishes the two artefact kinds.
	if _, err := agentpolicy.Verify(env, pub); err != nil {
		t.Fatalf("agentpolicy.Verify must accept the update envelope: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"schema":"1"`)) {
		t.Fatalf("schema must be inside the signed payload, got %s", payload)
	}
}

func TestPreservedStateIsNotEmpty(t *testing.T) {
	// R2.3 exists as a list the platform updaters share. An empty list would make every updater's "I preserved
	// everything" assertion vacuously true.
	got := PreservedState()
	if len(got) < 3 {
		t.Fatalf("PreservedState() = %v, want the R2.3 list", got)
	}
	joined := strings.Join(got, "|")
	for _, must := range []string{"client certificate", "service arguments", "steer-exclusion"} {
		if !strings.Contains(joined, must) {
			t.Fatalf("PreservedState() is missing %q: %v", must, got)
		}
	}
}

// ★ The key id must not name the wrong class of authority.
//
// agentpolicy labels every key "edge-agent-policy-<fingerprint>", which is correct for its own documents and
// misleading on this one: an update manifest signed by the update key was arriving at endpoints announcing
// itself as agent-policy-signed — the exact collapse the two-key split exists to prevent. Observed on
// win-dev-1 in the first manifest to reach a device, where the reader ran a control rather than believe it.
//
// The field is annotation and not authority — verification is against the pinned key list — which is why this
// could be corrected at all. It is also why it matters: a label nobody verifies is a label someone eventually
// reads as evidence.
func TestTheSignedManifestNamesTheUpdateKeyNotThePolicyKey(t *testing.T) {
	signer, pub := newTestSigner(t)
	env, err := Sign(signer, goodManifest(), time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(env.SigningKeyID, "agent-policy") {
		t.Fatalf("signing_key_id = %q; an update manifest must not announce itself as agent-policy signed",
			env.SigningKeyID)
	}
	if !strings.HasPrefix(env.SigningKeyID, "agent-update-") {
		t.Fatalf("signing_key_id = %q, want an agent-update- prefix", env.SigningKeyID)
	}
	// And re-labelling must not have disturbed what actually carries trust.
	if _, verr := Open(env, []string{pub}, time.Now()); verr != nil {
		t.Fatalf("the re-labelled envelope no longer verifies: %v", verr)
	}
}

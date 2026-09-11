package agentpolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testLeafPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "not-a-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := LoadOrGenerateSigner("", true)
	if err != nil || s == nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

// The bundle exists to be carried over a channel the device cannot authenticate, so everything rests on the
// signature. A device that has already accepted serial N must end up with the anchors the Edge published.
func TestTrustBundleRoundTrips(t *testing.T) {
	s := testSigner(t)
	caPEM := testCAPEM(t, "DSSE Transport CA") + testCAPEM(t, "DSSE Transport CA (previous)")

	env, err := s.SignTrustBundle("tenant-a", 7, caPEM, ":18545", time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyTrustBundle(env, s.PublicKeyHex(), 6)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	anchors, err := got.Anchors()
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2 — an overlap is the normal mid-rotation state", len(anchors))
	}
	if got.RenewalRecoveryEndpoint != ":18545" {
		t.Fatalf("recovery endpoint = %q", got.RenewalRecoveryEndpoint)
	}
	fps, err := got.Fingerprints()
	if err != nil || len(fps) != 2 {
		t.Fatalf("fingerprints = %v, %v", fps, err)
	}
}

// The attack the serial exists for. Whoever can serve an unauthenticated document can serve an OLD one, so a
// bundle from before a compromised CA was withdrawn must not be accepted again.
func TestTrustBundleRefusesReplayOfAnOlderSerial(t *testing.T) {
	s := testSigner(t)
	ca := testCAPEM(t, "DSSE Transport CA")
	old, err := s.SignTrustBundle("tenant-a", 3, ca, "", time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The device has since accepted serial 9.
	if _, err := VerifyTrustBundle(old, s.PublicKeyHex(), 9); err == nil {
		t.Fatal("a bundle older than the one already accepted was taken — a withdrawn CA could be restored")
	}
	// Re-serving the SAME serial is equally a replay.
	same, err := s.SignTrustBundle("tenant-a", 9, ca, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustBundle(same, s.PublicKeyHex(), 9); err == nil {
		t.Fatal("a bundle at the accepted serial was taken; only a strict advance is safe")
	}
}

// The envelope type is shared across signed documents, so only the payload schema keeps them apart. Without the
// check, a body signed for another purpose could be served in a trust bundle's place.
func TestTrustBundleRejectsAnotherPayloadSchema(t *testing.T) {
	s := testSigner(t)
	env, err := s.Sign(RegionEndpointsPayload{
		SchemaVersion: RegionEndpointsSchema,
		TenantID:      "tenant-a",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustBundle(env, s.PublicKeyHex(), 0); err == nil {
		t.Fatal("a region-endpoints payload was accepted as a trust bundle")
	}
}

// Signed by the wrong key, or tampered with after signing — the two shapes an unauthenticated channel invites.
func TestTrustBundleFailsClosedOnBadSignature(t *testing.T) {
	s := testSigner(t)
	other := testSigner(t)
	ca := testCAPEM(t, "DSSE Transport CA")
	env, err := s.SignTrustBundle("tenant-a", 1, ca, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTrustBundle(env, other.PublicKeyHex(), 0); err == nil {
		t.Fatal("a bundle signed by an unpinned key was accepted")
	}
	// Tamper with the SIGNED BYTES deterministically, and keep the checksum consistent with the tampered
	// payload so the signature is the check that has to refuse it. (An earlier version replaced the first "A"
	// in the base64 — but the payload is printable-ASCII JSON, whose base64 can legitimately contain no "A" at
	// all, making the tamper a silent no-op and the test flaky.)
	raw, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x20
	sum := sha256.Sum256(raw)
	tampered := env
	tampered.PayloadB64 = base64.StdEncoding.EncodeToString(raw)
	tampered.PayloadSHA256 = hex.EncodeToString(sum[:])
	if _, err := VerifyTrustBundle(tampered, s.PublicKeyHex(), 0); err == nil {
		t.Fatal("a tampered payload was accepted")
	}
	if _, err := VerifyTrustBundle(env, "", 0); err == nil {
		t.Fatal("verification without a pinned key was allowed")
	}
}

// An empty anchor set must be an error, not an empty list: at a call site "no anchors" is indistinguishable from
// "trust nothing" and invites a fallback, which is exactly the wrong move on a document that failed.
func TestTrustBundleRefusesUnusableAnchors(t *testing.T) {
	s := testSigner(t)
	if _, err := s.SignTrustBundle("tenant-a", 1, "", "", time.Now()); err == nil {
		t.Fatal("a bundle with no CA was signed; it would burn a serial and lock out the good one behind it")
	}
	if _, err := s.SignTrustBundle("tenant-a", 1, testLeafPEM(t), "", time.Now()); err == nil {
		t.Fatal("a non-CA certificate was accepted as an anchor")
	}
	if _, err := s.SignTrustBundle("tenant-a", 0, testCAPEM(t, "CA"), "", time.Now()); err == nil {
		t.Fatal("a bundle without a serial was signed; replays could not be detected")
	}
}

// The bundle must not be able to grant anything. It says which CA verifies the EDGE — nothing about which device
// this is — so swapping it cannot make one device impersonate another.
func TestTrustBundleCarriesNoDeviceIdentity(t *testing.T) {
	s := testSigner(t)
	env, err := s.SignTrustBundle("tenant-a", 1, testCAPEM(t, "CA"), ":18545", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Verify(env, s.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	// Assert on the FIELD NAMES, not on the text: the payload legitimately contains "BEGIN CERTIFICATE",
	// because carrying CA certificates is its whole job. What must never appear is a field naming a device, or
	// any private key material.
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "device") || strings.Contains(lower, "client_identity") ||
			strings.Contains(lower, "private") || strings.Contains(lower, "key") {
			t.Fatalf("the signed payload carries a %q field; a bundle must not be able to identify or authorise a device", name)
		}
	}
	if strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatal("the signed payload carries private key material")
	}
}

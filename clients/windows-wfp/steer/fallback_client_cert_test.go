package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// fallbackClientCertPEM returns the LEAF of the bootstrap certificate — and never key material. The Edge's
// retire gate parses this to decide whether a CA still issues somebody's safety net, so it has to be a
// certificate and nothing else.
func TestFallbackClientCertPEMReturnsLeafOnly(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, "bootstrap issuing CA")
	leafDER := issueLeafFor(t, ca, &key.PublicKey, "win-dev-1")

	// A file holding the leaf AND (as some deployments do) an extra chain certificate.
	extra := newTestCA(t, "chain filler")
	path := filepath.Join(dir, "device.crt")
	body := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), extra.pem...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	got := fallbackClientCertPEM(filepath.Dir(path), path)
	if got == "" {
		t.Fatal("no fallback certificate returned")
	}
	// Exactly ONE certificate, and it is the leaf.
	block, rest := pem.Decode([]byte(got))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("returned PEM is not a certificate: %q", got)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("more than one certificate was returned; only the leaf may be sent")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "win-dev-1" || cert.Issuer.CommonName != "bootstrap issuing CA" {
		t.Fatalf("returned the wrong certificate: subject=%q issuer=%q", cert.Subject.CommonName, cert.Issuer.CommonName)
	}
	// Nothing key-shaped is ever produced, whatever sits in the directory.
	if strings.Contains(got, "PRIVATE KEY") {
		t.Fatal("the fallback report contained key material")
	}
}

// A key file passed by mistake, a missing file, or an empty path must yield NOTHING rather than something the
// Edge would try to parse — reporting nothing simply leaves the gate as permissive as it was.
func TestFallbackClientCertPEMRefusesNonCertificates(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "device.key")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := fallbackClientCertPEM(filepath.Dir(keyPath), keyPath); got != "" {
		t.Fatalf("a key file produced a report: %q", got)
	}
	if got := fallbackClientCertPEM(dir, filepath.Join(dir, "absent.crt")); got != "" {
		t.Fatalf("a missing file produced a report: %q", got)
	}
	if got := fallbackClientCertPEM("", ""); got != "" {
		t.Fatalf("an empty path produced a report: %q", got)
	}
	garbage := filepath.Join(dir, "garbage.crt")
	os.WriteFile(garbage, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o644)
	if got := fallbackClientCertPEM(filepath.Dir(garbage), garbage); got != "" {
		t.Fatalf("an unparseable certificate produced a report: %q", got)
	}
}

// The report carries the fallback, and omits it when there is none — an unreported device must keep the gate
// exactly as permissive as before.
func TestExclusionSyncReportsFallbackClientCert(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool

	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, "bootstrap issuing CA")
	leafDER := issueLeafFor(t, ca, &key.PublicKey, "win-dev-1")
	certPath := filepath.Join(dir, "device.crt")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o644)

	var cap capturedReport
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:              func([]string) {},
		fallbackClientCert: func() string { return fallbackClientCertPEM(filepath.Dir(certPath), certPath) },
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	got, _ := body["fallback_client_cert_pem"].(string)
	if got == "" {
		t.Fatalf("fallback_client_cert_pem missing: %v", body["fallback_client_cert_pem"])
	}
	blk, _ := pem.Decode([]byte(got))
	if blk == nil {
		t.Fatal("reported fallback is not PEM")
	}
	// The Edge decides by asking whether the retiring CA signed this certificate — so that check must pass here.
	reported, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := reported.CheckSignatureFrom(ca.cert); err != nil {
		t.Fatalf("the reported fallback does not verify against its issuing CA: %v", err)
	}

	// No fallback available => the field is absent.
	var cap2 capturedReport
	srv2 := reportingPolicyServer(t, signer, nil, &reportFails, &cap2)
	defer srv2.Close()
	s2 := &exclusionSync{
		client: srv2.Client(), baseURL: srv2.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:              func([]string) {},
		fallbackClientCert: func() string { return "" },
	}
	if _, err := s2.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body2, _ := cap2.body.Load().(map[string]any)
	if _, present := body2["fallback_client_cert_pem"]; present {
		t.Fatal("an empty fallback must be omitted, not sent as an empty string")
	}
}

// issueLeafFor mints a client leaf under ca for the given public key.
func issueLeafFor(t *testing.T, ca testCA, pub *ecdsa.PublicKey, cn string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// With a retained previous generation, THAT is what gets reported — not the day-0 bootstrap. This is what
// lets the bootstrap age out harmlessly instead of pinning a CA the fleet wants to retire: the retained
// identity was issued by the CURRENT CA and proved itself on a real handshake when it was installed.
func TestFallbackPrefersRetainedPreviousIdentity(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "retired issuing CA") // the bootstrap's issuer
	curCA := newTestCA(t, "current issuing CA") // the issuer of the retained generation
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	bootstrapPath := filepath.Join(dir, "device.crt")
	os.WriteFile(bootstrapPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: issueLeafFor(t, oldCA, &key.PublicKey, "win-dev-1")}), 0o644)

	prevPath := filepath.Join(dir, "device-prev.crt")
	os.WriteFile(prevPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: issueLeafFor(t, curCA, &key.PublicKey, "win-dev-1")}), 0o644)

	// A pointer whose current identity retains the previous generation.
	writePointer(t, dir, deviceIdentityPointer{
		CertificateSHA256: "current", CertFile: filepath.Join(dir, "device-cur.crt"), KeyContainer: "dsse-cur", KeyStorage: "tpm",
		Previous: &supersededIdentity{CertificateSHA256: "previous", CertFile: prevPath, KeyStorage: "tpm"},
	})

	got := fallbackClientCertPEM(filepath.Dir(bootstrapPath), bootstrapPath)
	blk, _ := pem.Decode([]byte(got))
	if blk == nil {
		t.Fatalf("no fallback reported")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Issuer.CommonName != "current issuing CA" {
		t.Fatalf("reported issuer = %q, want the RETAINED generation's issuer (not the bootstrap's)", cert.Issuer.CommonName)
	}
}

// If the retained material has gone missing, the report falls back to the bootstrap rather than reporting
// nothing — reporting nothing would silently drop the gate's constraint for this device.
func TestFallbackFallsBackToBootstrapWhenRetainedMissing(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "bootstrap issuing CA")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bootstrapPath := filepath.Join(dir, "device.crt")
	os.WriteFile(bootstrapPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: issueLeafFor(t, oldCA, &key.PublicKey, "win-dev-1")}), 0o644)

	writePointer(t, dir, deviceIdentityPointer{
		CertificateSHA256: "current", CertFile: filepath.Join(dir, "device-cur.crt"), KeyContainer: "dsse-cur",
		Previous: &supersededIdentity{CertificateSHA256: "previous", CertFile: filepath.Join(dir, "gone.crt")},
	})

	got := fallbackClientCertPEM(filepath.Dir(bootstrapPath), bootstrapPath)
	blk, _ := pem.Decode([]byte(got))
	if blk == nil {
		t.Fatal("a missing retained identity must fall back to the bootstrap, not report nothing")
	}
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if cert.Issuer.CommonName != "bootstrap issuing CA" {
		t.Fatalf("reported issuer = %q, want the bootstrap's", cert.Issuer.CommonName)
	}
}

// With no renewal yet (no pointer), the bootstrap is the fallback — the day-0 state.
func TestFallbackUsesBootstrapBeforeAnyRenewal(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "bootstrap issuing CA")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bootstrapPath := filepath.Join(dir, "device.crt")
	os.WriteFile(bootstrapPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: issueLeafFor(t, ca, &key.PublicKey, "win-dev-1")}), 0o644)

	blk, _ := pem.Decode([]byte(fallbackClientCertPEM(filepath.Dir(bootstrapPath), bootstrapPath)))
	if blk == nil {
		t.Fatal("no fallback reported on a device that has never renewed")
	}
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if cert.Issuer.CommonName != "bootstrap issuing CA" {
		t.Fatalf("reported issuer = %q", cert.Issuer.CommonName)
	}
}

// The RETIRE GATE is told (fallbackClientCertPEM) that the safety net is N-1, so loadDeviceIdentity must
// actually PRESENT N-1 when the current identity will not load — not the day-0 bootstrap. Reporting N-1 (current
// CA) while loading the bootstrap (a CA the fleet may have retired) is the false assurance behind the seven
// minute outage on 2026-08-02: the gate retires the old CA, then a device whose current identity fails presents
// the bootstrap and is refused at every handshake.
func TestLoadDeviceIdentityFallsBackToPreviousNotBootstrap(t *testing.T) {
	dir := t.TempDir()
	oldCA := newTestCA(t, "retired issuing CA")
	curCA := newTestCA(t, "current issuing CA")

	// Bootstrap identity (file), issued by the OLD CA — what the buggy load path would wrongly present.
	bootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bootstrapCert := filepath.Join(dir, "device.crt")
	bootstrapKey := filepath.Join(dir, "device.key")
	writeCertKey(t, bootstrapCert, bootstrapKey, issueLeafFor(t, oldCA, &bootKey.PublicKey, "win-dev-1"), bootKey)

	// Retained previous identity (N-1, file), issued by the CURRENT CA — the real safety net.
	prevKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prevCert := filepath.Join(dir, "device-prev.crt")
	prevKeyFile := filepath.Join(dir, "device-prev.key")
	writeCertKey(t, prevCert, prevKeyFile, issueLeafFor(t, curCA, &prevKey.PublicKey, "win-dev-1"), prevKey)

	// The current pointer names material that no longer exists (a wiped file / lost TPM container), so the
	// current identity cannot load and the fallback path is exercised.
	writePointer(t, dir, deviceIdentityPointer{
		CertificateSHA256: "current",
		CertFile:          filepath.Join(dir, "device-cur-gone.crt"),
		KeyFile:           filepath.Join(dir, "device-cur-gone.key"),
		Previous: &supersededIdentity{
			CertificateSHA256: "previous", CertFile: prevCert, KeyFile: prevKeyFile, KeyStorage: "file",
		},
	})

	cert, kind, err := loadDeviceIdentity(bootstrapCert, bootstrapKey)
	if err != nil {
		t.Fatalf("loadDeviceIdentity: %v", err)
	}
	if kind != "previous" {
		t.Fatalf("kind = %q, want \"previous\" (the retained N-1, not the bootstrap)", kind)
	}
	leaf := cert.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf.Issuer.CommonName != "current issuing CA" {
		t.Fatalf("fell back to issuer %q, want the current CA's N-1 (not the retired bootstrap CA)", leaf.Issuer.CommonName)
	}
}

// With no retained previous, the fallback is still the bootstrap — unchanged day-0 behaviour.
func TestLoadDeviceIdentityFallsBackToBootstrapWithoutPrevious(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "bootstrap issuing CA")
	bootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bootstrapCert := filepath.Join(dir, "device.crt")
	bootstrapKey := filepath.Join(dir, "device.key")
	writeCertKey(t, bootstrapCert, bootstrapKey, issueLeafFor(t, ca, &bootKey.PublicKey, "win-dev-1"), bootKey)

	writePointer(t, dir, deviceIdentityPointer{
		CertificateSHA256: "current",
		CertFile:          filepath.Join(dir, "gone.crt"),
		KeyFile:           filepath.Join(dir, "gone.key"),
	})

	if _, kind, err := loadDeviceIdentity(bootstrapCert, bootstrapKey); err != nil || kind != "bootstrap" {
		t.Fatalf("kind=%q err=%v, want kind=\"bootstrap\"", kind, err)
	}
}

func writeCertKey(t *testing.T, certPath, keyPath string, certDER []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePointer(t *testing.T, dir string, p deviceIdentityPointer) {
	t.Helper()
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, renewalPointerFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

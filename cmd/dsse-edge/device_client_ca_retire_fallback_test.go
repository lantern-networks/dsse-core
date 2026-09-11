package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
)

// Mints a CA, returning the parsed certificate, its PEM, and its key (for issuing leaves).
func mintTestCA(t *testing.T, cn string) (*x509.Certificate, string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

// Mints a client leaf signed by the given CA.
func mintTestLeaf(t *testing.T, cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Reproduces the 2026-08-02 outage shape at the gate: the fleet PRESENTS certificates from the current CA,
// so the old CA looks retirable — but a device's reported BOOTSTRAP (fallback) credential still chains from
// it, and a device that falls back after the retirement is refused at every handshake. The gate must read
// the reported fallback, and only the reported fallback: absence keeps the gate exactly as strict as before.
func TestDeviceClientCARetireGateBlocksOnReportedFallback(t *testing.T) {
	oldCA, oldPEM, oldKey := mintTestCA(t, "Old Bootstrap CA")
	newCA, newPEM, newKey := mintTestCA(t, "Current Issuing CA")

	store, err := openTransportTrustStore(filepath.Join(t.TempDir(), "device_client_cas.json"),
		oldPEM+newPEM, 1, func(string, int64) (func(), error) { return func() {}, nil })
	if err != nil {
		t.Fatal(err)
	}
	prevStore := deviceClientCAs
	deviceClientCAs = store
	defer func() { deviceClientCAs = prevStore }()

	const tenant = "tenant-fallback-gate"
	const identity = "fallback-gate-dev-1"
	ledger := enrolledinventory.NewLedger()
	ledger.SeedFromStatic(map[string]struct{}{identity: {}}, "t0")

	presented, _ := mintTestLeaf(t, identity, newCA, newKey)
	deviceCertificates.observe(identity, presented, time.Now())

	observed := newObservedExclusionStore(16)
	config := serverConfig{EnrolledLedger: ledger, ObservedExclusions: observed}

	_, fallbackFromOld := mintTestLeaf(t, identity, oldCA, oldKey)
	_, fallbackFromNew := mintTestLeaf(t, identity, newCA, newKey)
	oldFP := certFingerprint(oldCA)

	record := func(fallbackPEM string, reportedAt time.Time) {
		observed.Record(observedExclusionEntry{
			TenantID: tenant, DeviceIdentity: identity, ReportedAt: reportedAt,
			FallbackClientCertPEM: normalizeReportedFallbackCert(fallbackPEM),
		})
	}

	// No fallback reported: the gate behaves exactly as it did before the field existed.
	record("", time.Now())
	if ok, v := deviceClientCARetireGate(config, tenant, oldFP); !ok {
		t.Fatalf("with no fallback report the old CA must be retirable (presented certs all chain from the new CA), got %s: %s", v.Code, v.Text)
	}

	// The fallback chains from the CA being retired: refuse, and name the device.
	record(fallbackFromOld, time.Now())
	ok, v := deviceClientCARetireGate(config, tenant, oldFP)
	if ok {
		t.Fatal("the old CA issues this device's bootstrap credential — retiring it strands the device on fallback (2026-08-02)")
	}
	if v.Code != "issues_a_fallback_credential" {
		t.Fatalf("refusal must name the fallback condition, got %s: %s", v.Code, v.Text)
	}
	if len(v.Params) != 1 || v.Params[0] != identity {
		t.Fatalf("refusal must name the device holding the fallback, got %v", v.Params)
	}

	// The fallback chains from a CA that is staying: the old CA is retirable again.
	record(fallbackFromNew, time.Now())
	if ok, v := deviceClientCARetireGate(config, tenant, oldFP); !ok {
		t.Fatalf("a fallback issued by a remaining CA must not block, got %s: %s", v.Code, v.Text)
	}

	// A stale report is not evidence: past the telemetry shelf life it adds no constraint.
	record(fallbackFromOld, time.Now().Add(-transportCAReportShelfLife-time.Hour))
	if ok, v := deviceClientCARetireGate(config, tenant, oldFP); !ok {
		t.Fatalf("a fallback report older than the shelf life must not block, got %s: %s", v.Code, v.Text)
	}
}

// A report that omits the fallback must not erase the one on record: the store is latest-wins on whole
// entries, and on 2026-08-02 the recorded fallback vanished for both platforms while their agents were
// sending it — turning the retire gate's refusal into a silent green. A new value still replaces the old.
func TestCarryForwardFallbackCert(t *testing.T) {
	const tenant, id = "t-carry", "dev-carry"
	store := newObservedExclusionStore(4)
	_, oldPEM, _ := mintTestCA(t, "old fallback")
	_, newPEM, _ := mintTestCA(t, "new fallback")

	if got := carryForwardFallbackCert(store, tenant, id, ""); got != "" {
		t.Fatal("no prior entry: nothing to carry forward")
	}
	store.Record(observedExclusionEntry{TenantID: tenant, DeviceIdentity: id,
		ReportedAt: time.Now(), FallbackClientCertPEM: normalizeReportedFallbackCert(oldPEM)})

	if got := carryForwardFallbackCert(store, tenant, id, ""); got != normalizeReportedFallbackCert(oldPEM) {
		t.Fatal("an omitting report must keep the recorded fallback")
	}
	if got := carryForwardFallbackCert(store, tenant, id, normalizeReportedFallbackCert(newPEM)); got != normalizeReportedFallbackCert(newPEM) {
		t.Fatal("a report carrying a new fallback must replace, not carry forward")
	}
}

// The sanitizer stores only what parsed, re-encoded — never the reporter's bytes.
func TestNormalizeReportedFallbackCert(t *testing.T) {
	_, pemOK, _ := mintTestCA(t, "any")
	if got := normalizeReportedFallbackCert(pemOK); got == "" {
		t.Fatal("a valid certificate must be kept")
	}
	for _, bad := range []string{"", "not pem at all",
		"-----BEGIN CERTIFICATE-----\nZ29vZA==\n-----END CERTIFICATE-----\n"} {
		if got := normalizeReportedFallbackCert(bad); got != "" {
			t.Fatalf("unparseable input must record as empty, got %q", got)
		}
	}
}

package main

import (
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
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// The recovery listener exists so a device switched off across its certificate's expiry can come back without
// a human re-enrolling it. It accepts an EXPIRED certificate, which is the one thing the normal transport must
// never do — so what it still enforces matters more than what it relaxes.

func graceTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "grace test device CA"},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func graceTestDeviceCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func graceTestConfig(t *testing.T, window time.Duration) (enrollRenewGraceConfig, *enrolledinventory.Ledger) {
	t.Helper()
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("holiday-laptop", "tenant_test", "seeded for the recovery test",
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return enrollRenewGraceConfig{Ledger: ledger, Window: window}, ledger
}

// The case the whole thing exists for: a laptop switched off for three weeks, coming back after its
// certificate lapsed.
func TestADeviceThatExpiredWhileSwitchedOffCanRecover(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	now := time.Now()

	// A 60-day certificate that ran out 21 days ago.
	cert := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-81*24*time.Hour), now.Add(-21*24*time.Hour))

	identity, err := verifyRecoveringClient(cert, nil, pool, cfg, now)
	if err != nil {
		t.Fatalf("a device that came back after a holiday could not recover: %v", err)
	}
	if identity != "holiday-laptop" {
		t.Fatalf("recovered as %q, want holiday-laptop", identity)
	}
}

// ★ Revocation must stay terminal. If a killed device could come back this way, "revoked" would only mean
// "revoked until its certificate expires" — the opposite of what the kill-switch is for.
func TestARevokedDeviceCannotRecover(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	revocations := revocation.NewAdmissionRevocations()
	revocations.Revoke("holiday-laptop", "admin kill-switch")
	cfg.Revocations = revocations
	now := time.Now()

	cert := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-81*24*time.Hour), now.Add(-21*24*time.Hour))

	_, err := verifyRecoveringClient(cert, nil, pool, cfg, now)
	if err == nil {
		t.Fatal("a REVOKED device recovered through the expiry grace path — revocation would then mean nothing " +
			"more than a wait for the certificate to lapse")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected the refusal to name revocation, got %v", err)
	}
}

// A device removed from the inventory must not come back either.
func TestAnUnenrolledDeviceCannotRecover(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	cfg, ledger := graceTestConfig(t, 30*24*time.Hour)
	ledger.Remove("holiday-laptop", "2026-08-24T00:00:00Z")
	now := time.Now()

	cert := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-81*24*time.Hour), now.Add(-21*24*time.Hour))

	if _, err := verifyRecoveringClient(cert, nil, pool, cfg, now); err == nil {
		t.Fatal("a device that is no longer enrolled recovered through the expiry grace path")
	}
}

// The window has to actually bound. Without it this would be "any certificate this CA ever issued works
// forever", which is not a recovery path but a permanent bypass of expiry.
func TestRecoveryIsRefusedBeyondTheWindow(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	now := time.Now()

	cert := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-120*24*time.Hour), now.Add(-31*24*time.Hour))

	_, err := verifyRecoveringClient(cert, nil, pool, cfg, now)
	if err == nil {
		t.Fatal("a certificate expired beyond the recovery window was accepted")
	}
	if !strings.Contains(err.Error(), "window") {
		t.Fatalf("expected the refusal to name the window, got %v", err)
	}
}

// A certificate from an unrelated CA must not be usable here. The relaxation is about TIME, not about trust.
func TestACertificateFromAnotherCACannotRecover(t *testing.T) {
	_, _, pool := graceTestCA(t)
	otherCA, otherKey, _ := graceTestCA(t)
	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	now := time.Now()

	cert := graceTestDeviceCert(t, otherCA, otherKey, "holiday-laptop",
		now.Add(-81*24*time.Hour), now.Add(-21*24*time.Hour))

	if _, err := verifyRecoveringClient(cert, nil, pool, cfg, now); err == nil {
		t.Fatal("a certificate from an untrusted CA recovered — the grace window relaxes expiry, not trust")
	}
}

// A device whose certificate is still good belongs on the normal transport. Serving it here would quietly
// route healthy traffic through the relaxed path, and hide how often the recovery path is really used.
func TestAStillValidCertificateIsSentToTheNormalTransport(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	now := time.Now()

	cert := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-40*24*time.Hour), now.Add(20*24*time.Hour))

	_, err := verifyRecoveringClient(cert, nil, pool, cfg, now)
	if err == nil {
		t.Fatal("a still-valid certificate was admitted to the recovery listener")
	}
	if !strings.Contains(err.Error(), "still valid") {
		t.Fatalf("expected the refusal to say the certificate is still valid, got %v", err)
	}
}

// The refusals must be distinguishable. "Past the window" and "revoked" call for completely different
// operator actions — re-enrol the device, versus do not.
func TestRefusalReasonsAreDistinguishable(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	now := time.Now()
	expired := graceTestDeviceCert(t, ca, caKey, "holiday-laptop",
		now.Add(-81*24*time.Hour), now.Add(-21*24*time.Hour))

	revoked, _ := graceTestConfig(t, 30*24*time.Hour)
	rv := revocation.NewAdmissionRevocations()
	rv.Revoke("holiday-laptop", "admin kill-switch")
	revoked.Revocations = rv
	_, revokedErr := verifyRecoveringClient(expired, nil, pool, revoked, now)

	narrow, _ := graceTestConfig(t, time.Hour)
	_, windowErr := verifyRecoveringClient(expired, nil, pool, narrow, now)

	if revokedErr == nil || windowErr == nil {
		t.Fatal("both cases must be refused")
	}
	if revokedErr.Error() == windowErr.Error() {
		t.Fatal("a revoked device and a device past the window produce the same message — an operator cannot " +
			"tell whether to re-enrol it or to leave it dead")
	}
}

// graceTenantRegistry writes two tenants' CAs to disk and loads a real registry from them, because the
// anchor->tenant map is unexported and can only be built through the file loader the Edge itself uses.
func graceTenantRegistry(t *testing.T, tenantA, tenantB *x509.Certificate) *tenantca.TenantCARegistry {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, c *x509.Certificate) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	doc := tenantca.TenantCARegistryFile{Tenants: []tenantca.TenantCAEntry{
		{TenantID: "tenant-a", CAFile: write("a.pem", tenantA)},
		{TenantID: "tenant-b", CAFile: write("b.pem", tenantB)},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(regPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// The recovery listener trusts the WHOLE multi-tenant pool, so chaining successfully only proves a certificate
// came from SOME tenant. The (T) transport additionally binds the chain to this Edge's tenant; the recovery
// path must not be laxer. Device identities are matched by name, so without this a tenant-B laptop whose name
// collides with a tenant-A entry would be issued a TENANT-A certificate — a cross-tenant credential grant.
func TestACertificateFromAnotherTenantCannotRecover(t *testing.T) {
	caA, keyA, _ := graceTestCA(t)
	caB, keyB, _ := graceTestCA(t)
	reg := graceTenantRegistry(t, caA, caB)

	cfg, _ := graceTestConfig(t, 30*24*time.Hour)
	cfg.TenantRegistry = reg
	cfg.Tenant = "tenant-a"

	now := time.Now()
	expired := func(ca *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
		return graceTestDeviceCert(t, ca, key, "holiday-laptop", now.Add(-400*24*time.Hour), now.Add(-3*24*time.Hour))
	}

	// Same identity, but issued by the OTHER tenant's CA.
	if _, err := verifyRecoveringClient(expired(caB, keyB), nil, reg.Pool, cfg, now); err == nil {
		t.Fatal("a tenant-B certificate recovered against tenant-A's listener — cross-tenant credential grant")
	} else if !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("rejected, but not as a tenant mismatch: %v", err)
	}

	// The same device from the CORRECT tenant must still recover — the check must not break the feature.
	identity, err := verifyRecoveringClient(expired(caA, keyA), nil, reg.Pool, cfg, now)
	if err != nil {
		t.Fatalf("a tenant-A device could not recover against its own tenant: %v", err)
	}
	if identity != "holiday-laptop" {
		t.Fatalf("identity = %q, want holiday-laptop", identity)
	}
}

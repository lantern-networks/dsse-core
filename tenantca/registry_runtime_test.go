package tenantca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ★ THE MEASURED BLOCKER (2026-08-15). This registry was load-once from a startup file, so an organization
// created through the Console had no way to acquire the CA that identifies its devices — the file had to be
// edited and every Edge restarted. Measured while standing up a second tenant on the lab: there is no API at
// all, /admin/tenant-cas answered 404, and the tenant's devices were therefore unadmittable by construction.
func TestATenantCARegisteredAtRuntimeResolvesItsDevices(t *testing.T) {
	registry := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	caCert, caPEM := selfSignedCAForTest(t, "Northwind Device CA")

	added, err := registry.Register("tenant_northwind", caPEM)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("added %d anchors, want 1", len(added))
	}

	tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}})
	if !ok || tenant != "tenant_northwind" {
		t.Fatalf("a chain anchored at the registered CA resolved to %q/%v", tenant, ok)
	}
	if registry.TenantCount != 1 {
		t.Fatalf("TenantCount = %d", registry.TenantCount)
	}
	if got := registry.Registrations()["tenant_northwind"]; got != 1 {
		t.Fatalf("Registrations = %v", registry.Registrations())
	}

	// Idempotent: the same CA again is not a second anchor.
	if added, err := registry.Register("tenant_northwind", caPEM); err != nil || len(added) != 0 {
		t.Fatalf("re-registering the same CA added %d anchors (err %v)", len(added), err)
	}
}

// ★ A CA CANNOT BE MOVED BETWEEN ORGANIZATIONS. It is what identifies every device already holding a
// certificate under it, so re-pointing it would move a whole fleet to another tenant — the same cross-tenant
// takeover the invite path was fixed for, one layer down and with no login required.
func TestACARegisteredToOneTenantCannotBeMovedToAnother(t *testing.T) {
	registry := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	caCert, caPEM := selfSignedCAForTest(t, "Acme Device CA")
	if _, err := registry.Register("tenant_acme", caPEM); err != nil {
		t.Fatalf("first register: %v", err)
	}

	_, err := registry.Register("tenant_northwind", caPEM)
	if err == nil {
		t.Fatal("moving a CA to another tenant was allowed — a whole fleet would change organization")
	}
	if !strings.Contains(err.Error(), "tenant_acme") {
		t.Fatalf("the refusal must name the current owner, got %v", err)
	}
	// And nothing moved.
	if tenant, _ := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}}); tenant != "tenant_acme" {
		t.Fatalf("the CA now resolves to %q", tenant)
	}
}

// Withdrawing a tenant's CA stops its devices resolving AND stops them being trusted. A pool cannot have a
// certificate removed, so it is rebuilt — a withdrawn CA that stayed in the pool would go on admitting
// exactly the devices the withdrawal exists to stop.
func TestWithdrawingATenantCAAlsoRemovesItFromThePool(t *testing.T) {
	registry := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	goneCert, gonePEM := selfSignedCAForTest(t, "Gone Device CA")
	keptCert, keptPEM := selfSignedCAForTest(t, "Kept Device CA")
	if _, err := registry.Register("tenant_gone", gonePEM); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := registry.Register("tenant_kept", keptPEM); err != nil {
		t.Fatalf("register: %v", err)
	}

	if removed := registry.Withdraw("tenant_gone"); removed != 1 {
		t.Fatalf("withdrew %d", removed)
	}
	if _, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{goneCert}}); ok {
		t.Fatal("a withdrawn CA still resolves to its tenant")
	}
	if _, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{keptCert}}); !ok {
		t.Fatal("withdrawing one tenant's CA took another's with it")
	}
	// The rebuilt pool must still trust what was kept, and no longer trust what went.
	if !poolContains(registry.Pool, keptCert) {
		t.Fatal("the rebuilt pool lost a CA that was not withdrawn")
	}
	if poolContains(registry.Pool, goneCert) {
		t.Fatal("the withdrawn CA is still trusted, so its devices are still admitted")
	}
}

func poolContains(pool *x509.CertPool, cert *x509.Certificate) bool {
	if pool == nil {
		return false
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func selfSignedCAForTest(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ★ A REGISTRATION THAT DOES NOT SURVIVE A RESTART IS THE DEFECT, NOT THE FIX. The per-tenant interception
// root already behaves that way — created through the API, listed, and gone after a restart (measured on the
// lab, 2026-08-15) — which is why it still counts as broken. The tenant CA must not repeat it.
func TestARuntimeRegistrationSurvivesAReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tenant_ca_registry.json"
	registry := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	caCert, caPEM := selfSignedCAForTest(t, "Northwind Device CA")
	if _, err := registry.Register("tenant_northwind", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := registry.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := LoadTenantCARegistry(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	tenant, ok := reloaded.TenantForVerifiedChains([][]*x509.Certificate{{caCert}})
	if !ok || tenant != "tenant_northwind" {
		t.Fatalf("after a reload the CA resolves to %q/%v — the registration did not survive", tenant, ok)
	}
	if reloaded.TenantCount != 1 {
		t.Fatalf("TenantCount = %d after reload", reloaded.TenantCount)
	}
	if !poolContains(reloaded.Pool, caCert) {
		t.Fatal("the reloaded pool does not trust the CA, so the tenant's devices are refused at the handshake")
	}
}

// Saving without a configured path must fail loudly rather than quietly succeed: a registration nobody wrote
// down is one restart from vanishing, and the API would have answered 200.
func TestSavingWithNoPathIsAnError(t *testing.T) {
	registry := &TenantCARegistry{Pool: x509.NewCertPool(), byAnchorKey: map[string]string{}}
	if err := registry.Save(""); err == nil {
		t.Fatal("saving with no path must fail — otherwise the registration silently lives only in memory")
	}
}

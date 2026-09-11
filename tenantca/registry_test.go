package tenantca

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
	"testing"
	"time"
)

func mkCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A device cert chained to a registered tenant CA resolves to that tenant; an unregistered CA does not.
func TestTenantForVerifiedChains(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPEM := mkCA(t, "acme CA")
	caPath := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(caPath, caPEM, 0o600)
	regJSON, _ := json.Marshal(TenantCARegistryFile{Tenants: []TenantCAEntry{{TenantID: "acme", CAFile: caPath}}})
	regPath := filepath.Join(dir, "registry.json")
	_ = os.WriteFile(regPath, regJSON, 0o600)

	reg, err := LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if reg.TenantCount != 1 {
		t.Fatalf("tenant count = %d, want 1", reg.TenantCount)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device-1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if tenant, ok := reg.TenantForVerifiedChains([][]*x509.Certificate{{leaf, caCert}}); !ok || tenant != "acme" {
		t.Fatalf("verified chain should resolve to acme, got %q ok=%v", tenant, ok)
	}

	otherCA, _, _ := mkCA(t, "other CA")
	if tenant, ok := reg.TenantForVerifiedChains([][]*x509.Certificate{{leaf, otherCA}}); ok {
		t.Fatalf("an unregistered CA must not resolve, got %q", tenant)
	}
}

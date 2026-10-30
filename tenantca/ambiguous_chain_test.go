package tenantca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestVerifiedChainWithAuthoritiesFromDifferentTenantsIsAmbiguous(t *testing.T) {
	root, rootKey, rootPEM := mkCA(t, "shared parent")
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	intermediateDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(12345), Subject: pkix.Name{CommonName: "customer issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(67890), Subject: pkix.Name{CommonName: "device"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(intermediate)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatal(err)
	}
	reg := NewTenantCARegistry()
	if _, err := reg.Register("tenant-parent", rootPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register("tenant-customer", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})); err != nil {
		t.Fatal(err)
	}
	if owner, ok := reg.TenantForVerifiedChains(chains); ok {
		t.Fatalf("chain carried two tenants but resolved to %q", owner)
	}
	// The registry currently permits distinct authorities under tenant IDs
	// that differ only by case. Runtime tenant IDs are exact identifiers, so
	// those owners must not be merged with EqualFold here.
	caseDistinct := NewTenantCARegistry()
	if _, err := caseDistinct.Register("Tenant-X", rootPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := caseDistinct.Register("tenant-x", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})); err != nil {
		t.Fatal(err)
	}
	if owner, ok := caseDistinct.TenantForVerifiedChains(chains); ok {
		t.Fatalf("case-distinct tenant IDs resolved as the same owner: %q", owner)
	}
}

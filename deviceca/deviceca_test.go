package deviceca

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

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DSSE Device CA (test)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func testCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSign_ChainsToCA_ClientAuth(t *testing.T) {
	caCert, caKey := testCA(t)
	signer := NewSigner(caCert, caKey)

	// The CSR carries a SPOOFED subject; the CP-authoritative subject must win.
	authoritative := pkix.Name{CommonName: "win-dev-1", Organization: []string{"acme"}}
	certPEM, err := signer.Sign(testCSR(t, "spoofed-cn"), authoritative, 48*time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "win-dev-1" || len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != "acme" {
		t.Fatalf("cert must carry CP-authoritative subject, not the CSR's: %+v", leaf.Subject)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Fatalf("leaf must be CA:FALSE with basic constraints stamped")
	}
	// chains to the CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf must chain to CA with ClientAuth: %v", err)
	}
	// short-lived
	if d := time.Until(leaf.NotAfter); d > 49*time.Hour {
		t.Fatalf("ttl too long: %v", d)
	}
}

func TestSign_RejectsBadCSR(t *testing.T) {
	caCert, caKey := testCA(t)
	signer := NewSigner(caCert, caKey)
	if _, err := signer.Sign([]byte("not a csr"), pkix.Name{CommonName: "x"}, time.Hour); err == nil {
		t.Fatalf("garbage CSR must be rejected")
	}
}

// The device-certificate namespace: a name-constrained per-tenant intermediate can only verify leaves that
// carry a name inside its permitted subtree, and device certificates had none — a bare CN is not a name a
// constraint can permit. That mismatch rejected two renewals on 2026-08-02 and forced the constraint to be
// withdrawn from the lab hierarchy.
//
// The test proves the whole point end to end: an intermediate constrained to the tenant subtree verifies a
// leaf issued with the suffix, and refuses one from a DIFFERENT tenant's namespace — which is the property
// the constraint exists for. It also pins that the CN is untouched, because both agents match on it.
func TestNameSpaceSuffixMakesLeavesVerifiableUnderANameConstrainedIntermediate(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	// The intermediate the ideal hierarchy calls for: constrained to this tenant's namespace.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tenant-a issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"tenant-a.dsse.local"},
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, _ := x509.ParseCertificate(intDER)

	signer := NewSigner(intermediate, intKey)
	signer.NameSpaceSuffix = "tenant-a.dsse.local"

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "whatever-the-device-asked"}}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	leafPEM, err := signer.Sign(csrPEM, pkix.Name{CommonName: "mac-dev-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(lb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "mac-dev-1" {
		t.Fatalf("the common name must stay the device id (both agents match on it), got %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "mac-dev-1.tenant-a.dsse.local" {
		t.Fatalf("leaf must carry a name inside the tenant namespace, got %v", leaf.DNSNames)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	inter.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("a leaf inside the permitted namespace must verify under the constrained intermediate: %v", err)
	}

	// The constraint doing its job: this intermediate cannot mint into another tenant's namespace.
	signer.NameSpaceSuffix = "tenant-b.dsse.local"
	otherPEM, err := signer.Sign(csrPEM, pkix.Name{CommonName: "mac-dev-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := pem.Decode(otherPEM)
	other, _ := x509.ParseCertificate(ob.Bytes)
	if _, err := other.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("a cross-tenant name must be refused by the constraint — that is what the constraint is for")
	}
}

// Unset (the default) issues exactly what it issued before: no SAN, so nothing changes for a hierarchy that
// has not adopted constraints yet.
func TestNameSpaceSuffixUnsetIssuesNoSAN(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "plain ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	leafPEM, err := NewSigner(ca, caKey).Sign(csrPEM, pkix.Name{CommonName: "win-dev-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := pem.Decode(leafPEM)
	leaf, _ := x509.ParseCertificate(lb.Bytes)
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("with no suffix configured the issued certificate must be unchanged, got SANs %v", leaf.DNSNames)
	}
}

package main

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

// ★★★ THE ROOT STAYS WITH THE CUSTOMER, AND WHAT AN EDGE GETS EXPIRES (decided 2026-08-20).
//
// An organization's devices trust its interception ROOT. Creating one here would mean asking every device to
// trust something the operator made — the opposite of the ownership line — so the customer signs an issuing
// authority FOR the operator, once, and this mints short-lived per-Edge intermediates under it. A device sees
// the same root before and after, which is why this tier can rotate without an adoption dance.
//
// The refusals are the interesting half: material that does not chain to the root the customer named, or a
// key that does not belong to the certificate, produces leaves the BROWSER refuses — far from here, where
// nothing can explain it.
func TestTheControlPlaneMintsInterceptionMaterialUnderTheCustomersRoot(t *testing.T) {
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	rootCert, rootKey := interceptionTestCA(t, "Northwind Interception Root 2028", nil, nil, now)
	issuingCert, issuingKey := interceptionTestCA(t, "Northwind Interception Issuing CA (operator)", rootCert, rootKey, now)
	rootPEM := certPEMForTest(rootCert)
	issuingPEM := certPEMForTest(issuingCert)
	issuingKeyPEM := ecKeyPEMForTest(t, issuingKey)

	saved := 0
	a := newTenantInterceptionAuthority(nil, func([]byte) error { saved++; return nil }, func() time.Time { return now })

	// Refusals first: each of these would surface as a browser error on somebody's laptop.
	strangerCert, strangerKey := interceptionTestCA(t, "Somebody Else's Issuing CA", nil, nil, now)
	if _, err := a.Import("tenant_northwind", rootPEM, certPEMForTest(strangerCert), ecKeyPEMForTest(t, strangerKey)); err == nil {
		t.Fatal("an issuing authority that does not chain to the organization's root was accepted — every leaf " +
			"it signs is refused at the browser, with nothing on this side to explain it")
	}
	if _, err := a.Import("tenant_northwind", rootPEM, issuingPEM, ecKeyPEMForTest(t, strangerKey)); err == nil {
		t.Fatal("a key that does not belong to the issuing certificate was accepted")
	}
	if _, err := a.Import("", rootPEM, issuingPEM, issuingKeyPEM); err == nil {
		t.Fatal("an authority was imported for no organization — it would sign for everybody")
	}

	row, err := a.Import("tenant_northwind", rootPEM, issuingPEM, issuingKeyPEM)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if row.TenantID != "tenant_northwind" || saved == 0 {
		t.Fatalf("the authority was not stored against its organization: %+v (saved=%d)", row, saved)
	}

	// An organization that has delegated nothing gets nothing — never a fallback to somebody else's authority.
	if _, err := a.IssueFor("tenant_unknown", "edge-a2", time.Hour); err == nil {
		t.Fatal("an Edge was handed the right to intercept for an organization that delegated it nothing")
	}
	if _, err := a.IssueFor("tenant_northwind", "edge-a2", 0); err == nil {
		t.Fatal("interception material with no expiry was issued to a node that may vanish")
	}

	mat, err := a.IssueFor("tenant_northwind", "edge-a2", 6*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// What arrives must chain: per-Edge intermediate -> issuing authority -> the customer's root.
	blocks := parseAllCerts([]byte(mat.ChainPEM))
	if len(blocks) != 2 {
		t.Fatalf("the chain handed over has %d certificate(s); an Edge must be able to present everything "+
			"between its leaf and the root a device holds", len(blocks))
	}
	edgeIntermediate := blocks[0]
	if !edgeIntermediate.IsCA || edgeIntermediate.MaxPathLen != 0 || !edgeIntermediate.MaxPathLenZero {
		t.Fatal("the per-Edge intermediate may mint further CAs — a node could then delegate this " +
			"organization's interception onward")
	}
	if !edgeIntermediate.NotAfter.After(now) || edgeIntermediate.NotAfter.After(now.Add(7*time.Hour)) {
		t.Fatalf("material handed to a disposable node does not expire soon enough: %s", edgeIntermediate.NotAfter)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(mat.RootPEM)) {
		t.Fatal("the root handed alongside is not a certificate")
	}
	inter := x509.NewCertPool()
	inter.AddCert(blocks[1])
	if _, err := edgeIntermediate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("a device holding this organization's root could not verify what the Edge would present: %v", err)
	}

	// ★ AND THE ROOT IS UNCHANGED, which is why this tier rotates without asking any device to adopt anything.
	if strings.TrimSpace(mat.RootPEM) != strings.TrimSpace(rootPEM) {
		t.Fatal("the material names a different root than the customer's — every device would have to be " +
			"re-provisioned, which is the one thing this shape exists to avoid")
	}
}

func interceptionTestCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func certPEMForTest(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func ecKeyPEMForTest(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

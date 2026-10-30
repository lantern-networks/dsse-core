package edgeplane

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

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

func TestTenantLeafCDPRequiresAcknowledgedFreshSignedCRL(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, MaxPathLen: 1}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bases := []string{"http://crl-a.example.test:8080", "http://crl-b.example.test:8080", "http://crl-c.example.test:8080"}
	rootCDPs, err := inspectioncrl.URLs(bases, "tenant_test", root)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "edge issuer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, CRLDistributionPoints: rootCDPs}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, issuerKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(issuerKey)
	eng, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = eng.LoadOfflineTenantIntermediate("tenant_test",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.leafCertificate("tenant_test", "example.com"); err == nil || !strings.Contains(err.Error(), "CRL") {
		t.Fatalf("CDP leaf was minted before status publication: %v", err)
	}
	fp, crlDER, enabled, err := eng.SignTenantLeafCRL("tenant_test", now)
	if err != nil || !enabled || fp != inspectioncrl.Fingerprint(issuer) {
		t.Fatalf("sign leaf CRL: enabled=%v err=%v", enabled, err)
	}
	if err = eng.ConfirmTenantLeafCRL("tenant_test", fp, crlDER, now); err != nil {
		t.Fatal(err)
	}
	leafTLS, err := eng.leafCertificate("tenant_test", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leafCDPs, _ := inspectioncrl.URLs(bases, "tenant_test", issuer)
	if len(leaf.CRLDistributionPoints) != len(leafCDPs) {
		t.Fatalf("wrong leaf CDP: %v", leaf.CRLDistributionPoints)
	}
	for i, point := range leafCDPs {
		if leaf.CRLDistributionPoints[i] != point {
			t.Fatalf("wrong leaf CDP %d: %v", i, leaf.CRLDistributionPoints)
		}
	}
	if _, err = inspectioncrl.ParseAndValidate(crlDER, issuer, now); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(6 * time.Minute)
	if _, err = eng.leafCertificate("tenant_test", "example.com"); err == nil || !strings.Contains(err.Error(), "CRL") {
		t.Fatalf("cached leaf survived expired CRL: %v", err)
	}
	fp, freshDER, enabled, err := eng.SignTenantLeafCRL("tenant_test", clock)
	if err != nil || !enabled {
		t.Fatalf("sign CRL after publication resumes: enabled=%v err=%v", enabled, err)
	}
	if err = eng.ConfirmTenantLeafCRL("tenant_test", fp, freshDER, clock); err != nil {
		t.Fatal(err)
	}
	if _, err = eng.leafCertificate("tenant_test", "example.com"); err != nil {
		t.Fatalf("leaf issuance did not resume after fresh CRL acknowledgement: %v", err)
	}
	for _, mismatch := range []string{"tenant", "issuer"} {
		t.Run("mismatched_cdp_"+mismatch, func(t *testing.T) {
			badTemplate := *issuerTemplate
			badTemplate.SerialNumber = big.NewInt(13)
			if mismatch == "tenant" {
				badTemplate.CRLDistributionPoints, err = inspectioncrl.URLs(bases, "tenant_other", root)
			} else {
				badTemplate.CRLDistributionPoints, err = inspectioncrl.URLs(bases, "tenant_test", issuer)
			}
			if err != nil {
				t.Fatal(err)
			}
			badDER, err := x509.CreateCertificate(rand.Reader, &badTemplate, root, issuerKey.Public(), rootKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = eng.LoadOfflineTenantIntermediate("tenant_test",
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: badDER}),
				pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
				t.Fatal(err)
			}
			if _, _, enabled, err := eng.SignTenantLeafCRL("tenant_test", clock); err == nil || enabled {
				t.Fatalf("mismatched tenant CDP was treated as unprotected legacy material: enabled=%v error=%v", enabled, err)
			}
			if _, err := eng.leafCertificate("tenant_test", "example.com"); err == nil || !strings.Contains(err.Error(), "CRL") {
				t.Fatalf("mismatched tenant CDP permitted a leaf: %v", err)
			}
		})
	}
}

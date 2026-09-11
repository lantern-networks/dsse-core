package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ★★★ COMPLETING ROADMAP D REMOVED THE LAST RESORT FOR THAT ORGANIZATION (2026-08-20, measured the same night
// it first completed).
//
// The deployment-wide recovery name is answered with the deployment-wide certificate — it must be, because a
// server picks its certificate from the name and every organization was told the same one. An organization that
// has moved onto its own authority no longer trusts that certificate. Measured on the lab with openssl, from a
// device's own bundle:
//
//	lab.dsse.invalid      -> OK
//	recovery.dsse.invalid -> FAILED
//
// And the dedicated recovery port had already been retired, on evidence that every device HELD the name.
// Nobody had asked whether they could VERIFY what answers to it. A device of that organization whose
// certificate expired had no way back at all.
//
// So the name is per organization and rides on the certificate its transport already uses. After the change,
// the same measurement says OK for both.
func TestARecoveryNameBelongsToTheOrganizationThatCanVerifyIt(t *testing.T) {
	// The fixture carries BOTH names, which is what the control plane issues — a certificate with only the
	// transport name gives its organization no recovery name of its own, and the deployment's is used instead.
	// That fallback is the state every organization was in before this change.
	dir := t.TempDir()
	writeTenantCertWithNames(t, dir, "tenant_northwind",
		[]string{"northwind.dsse.invalid", "recovery.northwind.dsse.invalid"})
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}

	if got := organizationRecoveryName("Northwind.DSSE.Invalid"); got != "recovery.northwind.dsse.invalid" {
		t.Fatalf("the recovery name is not derived from the name devices already send: %q", got)
	}
	if organizationRecoveryName("  ") != "" {
		t.Fatal("an organization with no name of its own was given a recovery name")
	}

	// The deployment-wide name still relaxes the handshake — organizations without their own certificate keep
	// exactly what they had.
	if !isRecoveryName("recovery.dsse.invalid", "recovery.dsse.invalid") {
		t.Fatal("the deployment's own recovery name stopped being one")
	}
	// A recovery name this node serves is one too.
	if !isRecoveryName("recovery.northwind.dsse.invalid", "recovery.dsse.invalid") {
		t.Fatal("an organization's own recovery name was not recognised, so its devices cannot recover")
	}
	// ★ And one it does NOT serve is not: an unknown recovery.* must never relax a handshake.
	if isRecoveryName("recovery.somebody.else.invalid", "recovery.dsse.invalid") {
		t.Fatal("a name this node does not serve relaxed the handshake")
	}
	if isRecoveryName("", "recovery.dsse.invalid") {
		t.Fatal("a handshake that named nothing was treated as a recovery")
	}
}

// writeTenantCertWithNames is the fixture for a certificate carrying several names, as the control plane issues
// them: the organization's transport name and the recovery name that rides on the same certificate.
func writeTenantCertWithNames(t *testing.T, dir, tenant string, names []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(97), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

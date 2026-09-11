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
	"strings"
	"testing"
	"time"
)

// selfSigned mints a root with the given common name. Two calls with the SAME name produce two certificates
// that a trust store cannot tell apart — which is the whole subject of this file.
func selfSigned(t *testing.T, commonName string) parsedRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Lantern DSSE"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRoot(der)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ★★ THE OUTAGE THIS EXISTS TO PREVENT. Two authorities under one name have taken this product down twice:
// two same-subject intermediates side by side on 2026-08-02, and the per_tenant collision win-dev-1 reported
// on 2026-08-16, where two organizations' roots were both "Lantern DSSE Interception Root". A trust store
// shows the NAME, so an operator cleaning up cannot tell them apart, and the wrong choice breaks every HTTPS
// site on the machine.
func TestASecondAuthorityUnderAnExistingNameIsRefused(t *testing.T) {
	existing := selfSigned(t, "Lantern DSSE Interception Root")
	incoming := selfSigned(t, "Lantern DSSE Interception Root") // same name, different key

	_, err := planRootInstall([]parsedRoot{existing}, []parsedRoot{incoming})
	if err == nil {
		t.Fatal("a second authority under an existing name was accepted — that is the state that breaks every " +
			"HTTPS site on the machine")
	}
	// The operator has to be able to act, which means both fingerprints have to be in the sentence: the
	// resolution is a removal BY FINGERPRINT, and the name cannot distinguish them.
	if !strings.Contains(err.Error(), existing.SHA256) || !strings.Contains(err.Error(), incoming.SHA256) {
		t.Fatalf("the refusal must name both fingerprints, got: %v", err)
	}
}

// Re-installing is not a collision. The same certificate arriving again is the ordinary case and must not
// fail an install.
func TestTheSameRootTwiceIsANoOp(t *testing.T) {
	root := selfSigned(t, "Lantern DSSE Interception Root (tenant_reference_lab)")

	plan, err := planRootInstall([]parsedRoot{root}, []parsedRoot{root})
	if err != nil {
		t.Fatalf("re-installing the same root was refused: %v", err)
	}
	if len(plan.Add) != 0 {
		t.Fatalf("the same root was added again: %+v", plan.Add)
	}
	if len(plan.AlreadyPresent) != 1 {
		t.Fatalf("the no-op was not reported: %+v", plan)
	}
}

// Two organizations whose roots are NAMED after them coexist, which is the point of the naming fix.
func TestTwoOrganizationsWithDistinctNamesBothInstall(t *testing.T) {
	a := selfSigned(t, "Lantern DSSE Interception Root (tenant_reference_lab)")
	b := selfSigned(t, "Lantern DSSE Interception Root (tenant_northwind)")

	plan, err := planRootInstall(nil, []parsedRoot{a, b})
	if err != nil {
		t.Fatalf("two differently named roots collided: %v", err)
	}
	if len(plan.Add) != 2 {
		t.Fatalf("want both added, got %d", len(plan.Add))
	}
}

// A rotation's normal state is an overlap: the old and the new authority together in one file. Both install,
// because a device has to be able to verify traffic signed under either while the fleet moves.
func TestARotationOverlapInstallsBoth(t *testing.T) {
	oldRoot := selfSigned(t, "Northwind Traders Interception Root")
	newRoot := selfSigned(t, "Northwind Traders Interception Root 2027")

	plan, err := planRootInstall(nil, []parsedRoot{oldRoot, newRoot})
	if err != nil {
		t.Fatalf("a rotation overlap was refused: %v", err)
	}
	if len(plan.Add) != 2 {
		t.Fatalf("want both halves of the overlap, got %d", len(plan.Add))
	}
}

// The collision is caught even when both halves arrive in ONE file, so a malformed bundle cannot walk past
// the rule by not being in the store yet.
func TestACollisionInsideOneBundleIsRefused(t *testing.T) {
	a := selfSigned(t, "Lantern DSSE Interception Root")
	b := selfSigned(t, "Lantern DSSE Interception Root")

	if _, err := planRootInstall(nil, []parsedRoot{a, b}); err == nil {
		t.Fatal("one file carrying two authorities under one name was accepted")
	}
}

func TestAPEMWithNoCertificateIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInterceptionRoots(path); err == nil {
		t.Fatal("a PEM with no certificate was accepted — the failure would surface later as 'TLS is broken'")
	}
}

func TestAPEMCarryingBothHalvesOfAnOverlapIsRead(t *testing.T) {
	a := selfSigned(t, "Northwind Traders Interception Root")
	b := selfSigned(t, "Northwind Traders Interception Root 2027")
	var buf []byte
	for _, r := range []parsedRoot{a, b} {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.DER})...)
	}
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readInterceptionRoots(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d certificates, want 2", len(got))
	}
}

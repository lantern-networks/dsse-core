package main

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"
)

// ★ A RE-PARENT IS NOT A ROTATION, AND THE GATE COULD NOT TELL (2026-08-19, hit live while moving the lab
// organization out of the provider's PKI tree).
//
// Moving an organization's device CA under its own root is done by re-issuing the CA's OWN certificate with
// the SAME subject and the SAME key, signed by the new root. Every device certificate that verified under the
// old one verifies under the new one — same issuer name to chain by, same key to check the signature with —
// so withdrawing the old certificate cannot lock anybody out.
//
// The withdrawal gate saw two unrelated CAs and refused, naming every device still admitted. Its refusal is
// right in general and impossible here, and without this an organization can only leave the provider's tree
// by re-issuing every device certificate first — which is the one thing a re-parent exists to avoid.
func TestWithdrawingAReparentedDeviceCAIsAllowed(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "Lab Device Issuing CA", 41)

	old, err := x509.ParseCertificate(ca.cert.Raw)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	// The replacement: identical subject, identical public key, a different issuer and serial.
	reparented := reparentedCopyForTest(t, old)

	if !deviceCAIsReparentOf(reparented, old) {
		t.Fatalf("a certificate with the same subject and the same key was not recognised as a re-parent of " +
			"the one it replaces, so withdrawing the old one will be refused and the organization cannot leave " +
			"the provider's tree without re-issuing every device")
	}

	// The controls, and they are the whole safety of this: a DIFFERENT key is a real rotation, and a
	// different subject cannot even chain the same leaves.
	otherKey := makeTestCA(t, dir, "Lab Device Issuing CA", 42) // same name, new key
	if deviceCAIsReparentOf(otherKey.cert, old) {
		t.Fatalf("a certificate with the same subject but a DIFFERENT key was treated as a re-parent — every " +
			"device certificate signed by the old key would stop verifying")
	}
	// Same KEY, different NAME — the case that isolates the subject half. A leaf naming the old issuer cannot
	// chain to this at all, however identical the key is, which is exactly what was measured with openssl
	// before this rule was written.
	renamed := renamedCopyForTest(t, old, "Lab Device Issuing CA 2028")
	if deviceCAIsReparentOf(renamed, old) {
		t.Fatalf("a certificate with the same key but a DIFFERENT subject was treated as a re-parent — a leaf " +
			"naming the old issuer cannot chain to it at all")
	}
}

// renamedCopyForTest returns a certificate with cert's public key under a DIFFERENT subject.
func renamedCopyForTest(t *testing.T, cert *x509.Certificate, commonName string) *x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	root := makeTestCA(t, dir, "Lab Tenant Device Root", 45)
	subject := cert.Subject
	subject.CommonName = commonName
	template := &x509.Certificate{
		SerialNumber:          cert.SerialNumber,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(nil, template, root.cert, cert.PublicKey, root.key)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse renamed: %v", err)
	}
	return out
}

// reparentedCopyForTest returns a certificate with cert's subject and public key, issued by a fresh root.
func reparentedCopyForTest(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	root := makeTestCA(t, dir, "Lab Tenant Device Root", 44)
	template := &x509.Certificate{
		SerialNumber:          cert.SerialNumber,
		Subject:               cert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(nil, template, root.cert, cert.PublicKey, root.key)
	if err != nil {
		t.Fatalf("re-parent: %v", err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse re-parented: %v", err)
	}
	return out
}

var _ = tenantca.CAAnchorKey
var _ = strings.EqualFold

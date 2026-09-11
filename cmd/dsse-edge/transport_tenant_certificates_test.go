package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

// ★★★ ROADMAP D, FIRST SLICE (2026-08-19). The trust bundle's transport anchor is one certificate for every
// organization, so whoever holds the provider's anchor can impersonate this Edge to ANY organization's
// devices. The selector for a per-organization certificate has to be the SNI — GetConfigForClient runs before
// the client certificate arrives, so the credential cannot choose it — and this asserts the two halves that
// make the slice safe to land: the name selects, and everything else is untouched.
func TestAnOrganizationsOwnTransportCertificateIsServedForItsName(t *testing.T) {
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if n, err := loadTransportTenantCertificates(dir); err != nil || n != 1 {
		t.Fatalf("loaded %d (%v)", n, err)
	}

	sharedCalled := 0
	shared := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		sharedCalled++
		return &tls.Certificate{}, nil
	}
	get := transportCertificateForClientHello(shared)

	own, err := get(&tls.ClientHelloInfo{ServerName: "northwind.dsse.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if own.Leaf == nil || own.Leaf.Subject.CommonName != "northwind.dsse.invalid" {
		t.Fatalf("the organization's own name was answered with %+v", own.Leaf)
	}
	if sharedCalled != 0 {
		t.Fatal("the shared certificate was consulted for a name an organization's own certificate carries")
	}

	// ★ THE CONTROL, and it is the whole reason this slice is safe to land: every OTHER connection is served
	// exactly what it was served before. No device sends these names yet, so nothing changes for anybody.
	for _, sni := range []string{"", "203.0.113.10", "somebody-elses.dsse.invalid"} {
		if _, err := get(&tls.ClientHelloInfo{ServerName: sni}); err != nil {
			t.Fatalf("SNI %q: %v", sni, err)
		}
	}
	if sharedCalled != 3 {
		t.Fatalf("the shared certificate was consulted %d times for 3 connections that are not any organization's", sharedCalled)
	}
}

// ★ A CERTIFICATE THAT NO SNI CAN SELECT IS NOT LOADED. Counting it would report an organization as being on
// its own certificate while every one of its handshakes is served the shared one — the shape this whole file
// exists to end, arriving through the loader instead of through the wire.
func TestATransportCertificateWithNoNamesIsRefusedRatherThanCounted(t *testing.T) {
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_nameless", "")
	useEmptyTenantCertificateIndex(t)
	n, err := loadTransportTenantCertificates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a certificate carrying no names was loaded as %d organization(s) served their own", n)
	}
	if len(transportTenantCertificates.Names()) != 0 {
		t.Fatalf("it is reported as in force: %v", transportTenantCertificates.Names())
	}
}

func writeTenantCert(t *testing.T, dir, tenant, dnsName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(31), Subject: pkix.Name{CommonName: dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if dnsName != "" {
		tmpl.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ★★★ THE ORGANIZATION'S OWN ANCHOR IS ADDED TO ITS BUNDLE, NEVER SUBSTITUTED FOR THE SHARED ONE
// (roadmap D, S2, 2026-08-19).
//
// The shared transport anchor is what every organization's devices verify this Edge with, so whoever holds it
// can impersonate the Edge to any of them — the last violation of the ownership line. The way out is not to
// swap it: a device that has not taken the new bundle would fail its next handshake, which is the same shape
// as the interception root switch that took win-dev-1 off the network the same day. Both are distributed,
// adoption is measured per device, and the shared one is withdrawn from that organization's bundle afterwards.
//
// Asserted on the anchor material rather than on a signed envelope, because the property is about WHAT IS
// NAMED: the organization's own certificate must be there, and it must be the one this node actually presents.
func TestAnOrganizationsBundleGainsItsAnchorWithoutLosingTheSharedOne(t *testing.T) {
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}

	own, ok := transportTenantCertificates.AnchorFor("tenant_northwind")
	if !ok || len(parseAllCerts([]byte(own))) != 1 {
		t.Fatalf("the organization's own anchor was not derived from what this node serves it: %q", own)
	}
	// It is the certificate actually served — read out of the chain rather than configured beside it, so the
	// bundle cannot name an anchor the handshake does not chain to.
	served, _, found := transportTenantCertificates.For("northwind.dsse.invalid")
	if !found {
		t.Fatal("no certificate is served for that name")
	}
	if certFingerprint(parseAllCerts([]byte(own))[0]) != certFingerprint(served.Leaf) {
		t.Fatal("the anchor named in the bundle is not the certificate this node presents (self-signed fixture: they are the same certificate)")
	}

	// An organization with no certificate of its own gets nothing added — its bundle is exactly as before.
	if _, ok := transportTenantCertificates.AnchorFor("tenant_somebody_else"); ok {
		t.Fatal("an organization with no certificate of its own was given an anchor")
	}

	// And the serial follows it: content that changes while the serial stays behind never reaches a device,
	// which is how a box came to answer from a fifteen-day-old bundle.
	fps := transportTenantCertificates.AnchorFingerprints()
	if len(fps) != 1 || !strings.HasPrefix(fps[0], "tenant_northwind=") {
		t.Fatalf("the anchors do not feed the announcement the serial follows: %v", fps)
	}
}

// useEmptyTenantCertificateIndex swaps in a clean index for one test and puts the previous one back.
//
// ★ WITHOUT THE RESTORE, THESE TESTS CHANGED OTHER TESTS (2026-08-19, seen immediately). The index is package
// state that the per-organization trust bundle reads, so a test that loaded Northwind's certificate and walked
// away made every later bundle for Northwind carry an extra anchor — and three unrelated tests failed in the
// full run while passing alone. A test that leaves state behind is a test that reports on a deployment nobody
// configured.
func useEmptyTenantCertificateIndex(t *testing.T) {
	t.Helper()
	previous := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = previous })
}

// ★★★ AND THE DOOR DEVICES ACTUALLY ARRIVE AT HAS THE SEAM (2026-08-28, added after finding that it did not).
//
// Everything above tests transportCertificateForClientHello, and all of it passed while an organization on the
// lab was served the deployment-wide certificate for its own name: the seam was installed on the secure
// transport listener, the agent plane was folded onto the MAIN listener, and nothing moved it. The material was
// issued by the control plane, fetched by every Edge, installed, and counted — and never once presented.
//
// So this asks the listener, not the helper. It is the same shape as every "verify the call site" finding in
// this tree, and the one the helper's own tests are structurally blind to.
func TestTheDoorDevicesArriveAtServesAnOrganizationsOwnCertificate(t *testing.T) {
	dir := t.TempDir()
	writeTenantCert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if n, err := loadTransportTenantCertificates(dir); err != nil || n != 1 {
		t.Fatalf("loaded %d (%v)", n, err)
	}

	sharedCalled := 0
	cfg := mainEdgeListenerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		sharedCalled++
		return &tls.Certificate{}, nil
	})
	if cfg.GetCertificate == nil {
		t.Fatal("the main listener has no GetCertificate at all")
	}
	own, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "northwind.dsse.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if own.Leaf == nil || own.Leaf.Subject.CommonName != "northwind.dsse.invalid" {
		t.Fatalf("the door devices arrive at answered this organization's own name with %+v — its devices hold "+
			"only their own anchor and refuse that, so every one of them loses the deployment", own.Leaf)
	}
	if sharedCalled != 0 {
		t.Fatal("the shared certificate was consulted for a name an organization's own certificate carries")
	}
	// The control: everything else is served exactly what it was before.
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "agents.dsse.lab"}); err != nil {
		t.Fatal(err)
	}
	if sharedCalled != 1 {
		t.Fatalf("a name no organization carries was not served the shared certificate (%d)", sharedCalled)
	}
}

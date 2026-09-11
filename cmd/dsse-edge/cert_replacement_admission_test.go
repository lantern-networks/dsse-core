package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// issueLeaf mints a leaf from a CA, with the extensions given — so a test can omit exactly what the
// 2026-07-31 certificate omitted.
func issueLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	// Defaults only: a test that sets a validity on purpose (an over-long certificate, say) must keep it.
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func testAdmissionCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Transport CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// THE regression: the certificate that stranded the fleet on 2026-07-31 must be refused here, and the
// refusal must name what is missing. It was valid, in date, key-matched, chained correctly and covered the
// right names — every check this path had — and had no basicConstraints.
func TestCertificateMissingBasicConstraintsIsRefused(t *testing.T) {
	ca, caKey, caPEM := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "dsse-transport"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// BasicConstraintsValid deliberately false — exactly what `openssl x509 -req` produced.
	})
	err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: leaf, TrustedPEM: caPEM, DialNames: []string{"203.0.113.10"},
	})
	if err == nil {
		t.Fatal("the certificate that caused the 2026-07-31 outage must be refused")
	}
	if !strings.Contains(err.Error(), "basicConstraints") {
		t.Fatalf("the refusal must name what is missing, got: %v", err)
	}
}

// The same certificate WITH basicConstraints is accepted — the check refuses a defect, not a workflow.
func TestWellFormedCertificateIsAccepted(t *testing.T) {
	ca, caKey, caPEM := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "dsse-transport"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	if err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: leaf, TrustedPEM: caPEM, DialNames: []string{"203.0.113.10", "localhost"},
	}); err != nil {
		t.Fatalf("a well-formed certificate must be accepted, got: %v", err)
	}
}

// A certificate no distributed certificate can verify is refused BEFORE it is served — the strand-the-fleet
// case the trust-distribution order exists to prevent.
func TestCertificateFromAnUntrustedIssuerIsRefused(t *testing.T) {
	_, _, trustedPEM := testAdmissionCA(t)
	otherCA, otherKey, _ := testAdmissionCA(t)
	leaf := issueLeaf(t, otherCA, otherKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "dsse-transport"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: leaf, TrustedPEM: trustedPEM, DialNames: []string{"203.0.113.10"},
	})
	if err == nil || !strings.Contains(err.Error(), "distribute the issuing certificate to devices FIRST") {
		t.Fatalf("an untrusted issuer must be refused with the ordering stated, got: %v", err)
	}
}

// A valid certificate that drops an address agents dial is refused naming that address — the failure whose
// error, on the device, mentions no names at all.
func TestCertificateNotCoveringADialledAddressIsRefused(t *testing.T) {
	ca, caKey, caPEM := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "dsse-transport"},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: leaf, TrustedPEM: caPEM, DialNames: []string{"203.0.113.10"},
	})
	if err == nil || !strings.Contains(err.Error(), "203.0.113.10") {
		t.Fatalf("the uncovered address must be named, got: %v", err)
	}
}

// The dial names come from this deployment's own configuration, hosts only.
func TestTransportDialNames(t *testing.T) {
	got := transportDialNames(serverConfig{TransportTLSURL: "https://203.0.113.10:18543"},
		regionEndpointHostsFrom("region-a=https://203.0.113.10:18543;region-b=https://edge-b.example:18544"))
	if len(got) != 2 || got[0] != "203.0.113.10" || got[1] != "edge-b.example" {
		t.Fatalf("dial names should be deduped hosts, got %v", got)
	}
}

// R2: rollback reaches back to material stored under a DIFFERENT trust distribution, so it must be
// admitted on today's terms. The guard is shared with replace precisely so the next path cannot forget.
func TestTheGuardAdmitsOnTodaysTrustNotYesterdays(t *testing.T) {
	oldCA, oldKey, oldPEM := testAdmissionCA(t)
	_, _, currentPEM := testAdmissionCA(t)

	// A certificate that was perfectly acceptable when it was stored: well-formed, right names, chaining
	// to the CA the fleet trusted at the time.
	stored := issueLeaf(t, oldCA, oldKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "transport"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	in := certAdmissionInput{Leaf: stored, DialNames: []string{"203.0.113.10"}}

	in.TrustedPEM = oldPEM
	if err := verifyCertificateWouldBeAcceptedByDevices(in); err != nil {
		t.Fatalf("it was acceptable under the distribution of the day: %v", err)
	}
	// That anchor has since been withdrawn. Nobody can verify this certificate now, so rolling back to it
	// would strand the fleet — the same outage, on request.
	in.TrustedPEM = currentPEM
	if err := verifyCertificateWouldBeAcceptedByDevices(in); err == nil {
		t.Fatal("a version whose issuer is no longer distributed must be refused today")
	}
}

// The guard covers every certificate this node serves, but not with the same questions: the shape a
// platform verifier demands applies to whoever the peer is, while "can the fleet still verify it" is only
// meaningful for the certificate devices verify (review C5 — it used to be wired to one name).
func TestTheGuardAppliesShapeEverywhereAndThePathCheckWhereItMeans(t *testing.T) {
	unparseable := "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"
	cfg := serverConfig{TransportCertFile: "/x/transport.pem"}
	for _, name := range []string{"edge", "transport"} {
		if err := guardServedCertificateChange(cfg, name, unparseable); err == nil {
			t.Fatalf("unparseable material must be refused for %q too", name)
		}
	}

	// A management certificate with the right shape passes without a trust distribution being involved —
	// this node has none to judge it against, and inventing one would refuse correct material.
	ca, caKey, _ := testAdmissionCA(t)
	shaped := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "dsse-edge"},
		DNSNames:              []string{"edge"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	shapedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: shaped.Raw}))
	if err := guardServedCertificateChange(cfg, "edge", shapedPEM); err != nil {
		t.Fatalf("a well-formed management certificate must pass: %v", err)
	}

	// The same certificate, missing basicConstraints, is refused wherever it is served.
	flawed := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "dsse-edge"},
		DNSNames:    []string{"edge"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	flawedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: flawed.Raw}))
	if err := guardServedCertificateChange(cfg, "edge", flawedPEM); err == nil {
		t.Fatal("the outage's defect must be refused on a management certificate too")
	}
}

// C4: keyUsage and extendedKeyUsage are required, not optional-if-present, and the platform's key and
// validity floors are enforced. Two of the outage certificate's three defects used to pass.
func TestShapeChecksAreRequirementsNotSuggestions(t *testing.T) {
	ca, caKey, caPEM := testAdmissionCA(t)
	base := func(mut func(*x509.Certificate)) certAdmissionInput {
		tmpl := &x509.Certificate{
			Subject:               pkix.Name{CommonName: "transport"},
			IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		mut(tmpl)
		return certAdmissionInput{Leaf: issueLeaf(t, ca, caKey, tmpl), TrustedPEM: caPEM, DialNames: []string{"203.0.113.10"}}
	}
	for name, mut := range map[string]func(*x509.Certificate){
		"no keyUsage":         func(c *x509.Certificate) { c.KeyUsage = 0 },
		"no extendedKeyUsage": func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"valid for too long":  func(c *x509.Certificate) { c.NotAfter = c.NotBefore.AddDate(3, 0, 0) },
	} {
		if err := verifyCertificateWouldBeAcceptedByDevices(base(mut)); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	// And a node that cannot say what agents dial, or has no distribution, must say so rather than pass.
	in := base(func(*x509.Certificate) {})
	in.DialNames = nil
	if err := verifyCertificateWouldBeAcceptedByDevices(in); err == nil {
		t.Fatal("with no dial names the SAN check must refuse, not silently do nothing")
	}
	in = base(func(*x509.Certificate) {})
	in.TrustedPEM = ""
	if err := verifyCertificateWouldBeAcceptedByDevices(in); err == nil {
		t.Fatal("with no trust distribution the path check must refuse, not be skipped")
	}
}

// R2, at the handler's own terms: the guard is what rollback consults, so a stored version that today's
// trust distribution cannot verify is refused by the same call the rollback path makes. (Exercised here
// rather than against the deployment: applying a certificate to a live Edge to see whether it is refused
// is the experiment that costs an outage when the answer is "no".)
func TestRollbackGuardRefusesAStoredVersionTodaysFleetCannotVerify(t *testing.T) {
	oldCA, oldKey, _ := testAdmissionCA(t)
	_, _, currentPEM := testAdmissionCA(t)
	stored := issueLeaf(t, oldCA, oldKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "transport"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	storedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stored.Raw}))

	dir := t.TempDir()
	certPath := dir + "/transport.pem"
	if err := os.WriteFile(certPath, []byte(storedPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := transportTrust
	transportTrust = &transportTrustStore{pems: currentPEM, serial: 9}
	defer func() { transportTrust = prev }()

	cfg := serverConfig{TransportCertFile: certPath, TransportTLSURL: "https://203.0.113.10:18543"}
	err := guardServedCertificateChange(cfg, "transport", storedPEM)
	if err == nil {
		t.Fatal("rollback to a version no distributed certificate can verify must be refused")
	}
	if !strings.Contains(err.Error(), "distribute the issuing certificate to devices FIRST") {
		t.Fatalf("the refusal must state the ordering: %v", err)
	}
}

// R8①: distributed is not adopted. A candidate that only the newly-added certificate can verify passes
// the distribution check and strands every device that has not taken the new distribution yet — the
// outage's shape, arriving at the next handshake instead of immediately.
func TestACandidateOnlyTheUnadoptedCertificateCanVerifyIsRefused(t *testing.T) {
	adoptedCA, adoptedKey, adoptedPEM := testAdmissionCA(t)
	freshCA, freshKey, freshPEM := testAdmissionCA(t)

	leafFrom := func(ca *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
		return issueLeaf(t, ca, key, &x509.Certificate{
			Subject:               pkix.Name{CommonName: "transport"},
			IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		})
	}
	in := certAdmissionInput{
		TrustedPEM:              adoptedPEM + freshPEM, // both are distributed
		AdoptedByEveryDevicePEM: []string{adoptedPEM},  // only one is held by everyone
		NotYetAdoptedBy:         []string{"mac-dev-1"},
		DialNames:               []string{"203.0.113.10"},
	}

	in.Leaf = leafFrom(freshCA, freshKey)
	err := verifyCertificateWouldBeAcceptedByDevices(in)
	if err == nil {
		t.Fatal("a certificate only the unadopted CA can verify must be refused")
	}
	if !strings.Contains(err.Error(), "mac-dev-1") {
		t.Fatalf("the device that would be stranded must be named: %v", err)
	}

	// The same candidate, issued by the CA every device already holds, is accepted.
	in.Leaf = leafFrom(adoptedCA, adoptedKey)
	if err := verifyCertificateWouldBeAcceptedByDevices(in); err != nil {
		t.Fatalf("a certificate the whole fleet can already verify must be accepted: %v", err)
	}
}

// Adoption that cannot be measured must not be invented: with no measurement the distribution check
// stands alone rather than the guard pretending the fleet is ready.
func TestUnmeasurableAdoptionDoesNotBlockOnItsOwn(t *testing.T) {
	ca, caKey, caPEM := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "transport"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})
	if err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: leaf, TrustedPEM: caPEM, DialNames: []string{"203.0.113.10"},
	}); err != nil {
		t.Fatalf("with no adoption measurement the distribution check decides alone: %v", err)
	}
}

// C5: the guard ran on every change made through the Console and on none made by redeploying. A node could
// boot presenting a certificate the fleet refuses — the shape of the 2026-07-31 outage — in silence.
func TestStartupChecksTheCertificateItIsAboutToServe(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.pem")
	bad := filepath.Join(dir, "bad.pem")
	// The outage's own shape: a leaf with no basicConstraints.
	ca, caKey, _ := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "lantern-dsse-transport"},
		DNSNames:    []string{"localhost"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// BasicConstraintsValid deliberately false — the 2026-07-31 certificate's own shape.
	})
	writeFile(t, bad, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})))
	writeFile(t, good, string(testCertPEM(t, "fine")))
	_ = good

	// A file that cannot be read is a finding, not a pass: the listener is about to try the same file.
	missing := checkServedCertificatesAtStartup(serverConfig{TransportCertFile: filepath.Join(dir, "nope.pem")})
	if len(missing) != 1 || missing[0].Problem == "" {
		t.Fatalf("an unreadable certificate must be reported, not skipped: %+v", missing)
	}

	// And a certificate the guard refuses is reported with the guard's own reason.
	got := checkServedCertificatesAtStartup(serverConfig{TransportCertFile: bad})
	if len(got) != 1 || got[0].Problem == "" {
		t.Fatalf("a certificate devices would refuse must be reported at startup: %+v", got)
	}
	if !strings.Contains(got[0].Problem, "basicConstraints") {
		t.Fatalf("the reason must be the guard's, not a summary: %q", got[0].Problem)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

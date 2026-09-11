package transportca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func testKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// legacySelfSignedTransportCert reproduces what the lab actually runs today: the transport SERVER certificate,
// self-signed, CA:TRUE with Certificate Sign, and pinned by every device as its trust anchor. The migration has
// to start from exactly this, because this is what is deployed.
func legacySelfSignedTransportCert(t *testing.T, key crypto.Signer, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dsse-transport"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// verifyAs checks what a DEVICE would check: does this served chain validate against the ONE anchor that device
// pinned? anchors-only, exactly as both clients do (SecTrustSetAnchorCertificatesOnly / tls.Config.RootCAs).
func verifyAs(t *testing.T, anchor *x509.Certificate, leaf *x509.Certificate, intermediates []*x509.Certificate, at time.Time, host string) error {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   at,
		DNSName:       host,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// THE test for #33. Every deployed device is pinned to the old self-signed transport certificate. Introducing a
// real CA layer must not strand a single one of them — including a device that was switched off throughout and
// has never heard of the new CA.
func TestMigratingToACALayerStrandsNoPinnedDevice(t *testing.T) {
	now := time.Now()
	oldKey := testKey(t)
	oldAnchor := legacySelfSignedTransportCert(t, oldKey, now.Add(365*24*time.Hour))

	// The new, long-lived CA that devices will pin from now on.
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}

	// The old anchor vouches for the new CA. This is the whole migration.
	cross, err := CrossSign(oldAnchor, oldKey, newCA.Cert, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatalf("cross-sign: %v", err)
	}

	// The Edge's server certificate is now an ordinary leaf beneath the new CA.
	leaf, err := newCA.IssueServerLeaf(testKey(t), LeafRequest{
		Subject:   pkix.Name{CommonName: "dsse-transport"},
		DNSNames:  []string{"localhost"},
		IPs:       []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	served := []*x509.Certificate{cross}

	// A device that has never been updated — still pinned to the old self-signed certificate.
	if err := verifyAs(t, oldAnchor, leaf, served, now, "localhost"); err != nil {
		t.Fatalf("a device pinned to the OLD anchor could not validate the new chain — the migration stranded it: %v", err)
	}
	// A device that has already adopted the new CA.
	if err := verifyAs(t, newCA.Cert, leaf, served, now, "localhost"); err != nil {
		t.Fatalf("a device pinned to the NEW CA could not validate: %v", err)
	}
}

// The point of the CA layer: re-minting the server certificate must stop being a fleet-wide event. Today the
// leaf IS the anchor, so every re-mint invalidates every pin — the failure that has already caused outages.
func TestReMintingTheServerLeafDoesNotDisturbPinnedAnchors(t *testing.T) {
	now := time.Now()
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	first, err := newCA.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Re-mint with a DIFFERENT key and an extra SAN — the shape of a real operational change.
	second, err := newCA.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost", "edge.lab"},
		IPs:       []net.IP{net.ParseIP("203.0.113.11")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("re-mint reused a serial")
	}
	// The SAME pinned anchor validates both, without the device being touched.
	for name, leaf := range map[string]*x509.Certificate{"original": first, "re-minted": second} {
		if err := verifyAs(t, newCA.Cert, leaf, nil, now, "localhost"); err != nil {
			t.Fatalf("the %s leaf did not validate against the unchanged anchor: %v", name, err)
		}
	}
}

// Rotating the CA later uses the same construction, and must likewise strand nobody: a device that was switched
// off for the whole overlap comes back holding only the previous anchor.
func TestRotatingTheCAKeepsThePreviousAnchorValid(t *testing.T) {
	now := time.Now()
	caA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA A"}, testKey(t), now.Add(-2*365*24*time.Hour), now.Add(5*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	caB, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA B"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSign(caA.Cert, caA.Key, caB.Cert, now.Add(-time.Hour), now.Add(400*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := caB.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	served := []*x509.Certificate{cross}

	// A laptop switched off for a year, coming back with only CA A pinned. This is the case the runbook
	// currently calls unsolvable.
	comesBack := now.Add(360 * 24 * time.Hour)
	lateLeaf, err := caB.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: comesBack.Add(-time.Hour), NotAfter: comesBack.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAs(t, caA.Cert, lateLeaf, served, comesBack, "localhost"); err != nil {
		t.Fatalf("a device that slept through the whole overlap could not come back: %v", err)
	}
	if err := verifyAs(t, caB.Cert, leaf, served, now, "localhost"); err != nil {
		t.Fatalf("an up-to-date device could not validate: %v", err)
	}
}

// A cross-certificate must never promise more than its issuer can keep: validating past the issuer's own expiry
// would make an operator believe the overlap is longer than it is, and devices would strand at the real edge.
func TestCrossCertificateCannotOutliveItsIssuer(t *testing.T) {
	now := time.Now()
	issuerKey := testKey(t)
	issuer := legacySelfSignedTransportCert(t, issuerKey, now.Add(30*24*time.Hour))
	sub, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSign(issuer, issuerKey, sub.Cert, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if cross.NotAfter.After(issuer.NotAfter) {
		t.Fatalf("cross-certificate expires %s, after its issuer's %s", cross.NotAfter, issuer.NotAfter)
	}
}

// The old private key is needed ONLY to mint the cross-certificate. Once it exists the signature stands on its
// own, so the old key can be destroyed — which is what makes the overlap safe to leave running for a year.
func TestCrossCertificateKeepsWorkingWithoutTheIssuerKey(t *testing.T) {
	now := time.Now()
	oldKey := testKey(t)
	oldAnchor := legacySelfSignedTransportCert(t, oldKey, now.Add(2*365*24*time.Hour))
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSign(oldAnchor, oldKey, newCA.Cert, now.Add(-time.Hour), now.Add(400*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	oldKey = nil // the old key is gone from here on

	leaf, err := newCA.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAs(t, oldAnchor, leaf, []*x509.Certificate{cross}, now, "localhost"); err != nil {
		t.Fatalf("the cross-certificate stopped working once the issuer key was discarded: %v", err)
	}
}

// Serving only the leaf is the mistake that strands old-anchor devices: new-anchor devices keep working, so the
// breakage is invisible to whoever performs the rotation. Pin that the chain is what carries the migration.
func TestServingTheLeafAloneStrandsOldAnchorDevices(t *testing.T) {
	now := time.Now()
	oldKey := testKey(t)
	oldAnchor := legacySelfSignedTransportCert(t, oldKey, now.Add(365*24*time.Hour))
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CrossSign(oldAnchor, oldKey, newCA.Cert, now.Add(-time.Hour), now.Add(400*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	leaf, err := newCA.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Cross-certificate minted but NOT served.
	if err := verifyAs(t, oldAnchor, leaf, nil, now, "localhost"); err == nil {
		t.Fatal("an old-anchor device validated a chain that omitted the cross-certificate — the test cannot detect the stranding it exists to catch")
	}
	if err := verifyAs(t, newCA.Cert, leaf, nil, now, "localhost"); err != nil {
		t.Fatalf("a new-anchor device should still work, which is why this mistake goes unnoticed: %v", err)
	}
}

// Guards on the inputs, so a rotation script cannot quietly produce something unusable.
func TestCrossSignRefusesNonCAInputs(t *testing.T) {
	now := time.Now()
	key := testKey(t)
	ca, err := NewCA(pkix.Name{CommonName: "CA"}, key, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CrossSign(leaf, key, ca.Cert, now, now.Add(time.Hour)); err == nil {
		t.Fatal("a non-CA leaf was accepted as a cross-sign issuer")
	}
	if _, err := CrossSign(ca.Cert, key, leaf, now, now.Add(time.Hour)); err == nil {
		t.Fatal("a non-CA leaf was accepted as a cross-sign subordinate")
	}
}

// A leaf that outlives its CA would stop validating mid-life for reasons no operator would look for.
func TestServerLeafCannotOutliveItsCA(t *testing.T) {
	now := time.Now()
	ca, err := NewCA(pkix.Name{CommonName: "CA"}, testKey(t), now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "leaf"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
	}); err == nil {
		t.Fatal("a leaf outliving its CA was issued")
	}
	if _, err := ca.IssueServerLeaf(testKey(t), LeafRequest{
		Subject: pkix.Name{CommonName: "leaf"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}); err == nil {
		t.Fatal("a leaf with no SAN was issued; no client would accept it")
	}
}

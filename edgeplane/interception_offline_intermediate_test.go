package edgeplane

import (
	"bytes"
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

// offlineCAFixture builds an offline root + a name-constrained intermediate (as the vendor tool would), returning
// their PEMs. The root key is discarded after issuing the intermediate — mirroring "root stays offline".
func offlineCAFixture(t *testing.T, permittedDNS []string, interValidity time.Duration, now time.Time) (rootCertPEM, interCertPEM, interKeyPEM []byte, rootDER []byte) {
	t.Helper()
	sn := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: sn(), Subject: pkix.Name{CommonName: "Offline Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: sn(), Subject: pkix.Name{CommonName: "Offline Issuing CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(interValidity),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	if len(permittedDNS) > 0 {
		interTmpl.PermittedDNSDomainsCritical = true
		interTmpl.PermittedDNSDomains = permittedDNS
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interKeyDER, _ := x509.MarshalPKCS8PrivateKey(interKey)
	rootCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	interCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	interKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: interKeyDER})
	return rootCertPEM, interCertPEM, interKeyPEM, rootDER
}

// TestOfflineInterceptionIntermediate proves the Edge can run with ONLY a name-constrained intermediate (cert+key)
// issued by an offline root: every leaf chains [leaf, intermediate, root], validates to the offline root, the
// engine's anchor IS that offline root (not a generated one), and the engine holds no root signing key.
func TestOfflineInterceptionIntermediate(t *testing.T) {
	now := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	nowf := func() time.Time { return now }
	rootPEM, interPEM, interKeyPEM, rootDER := offlineCAFixture(t, []string{"example.com"}, 90*24*time.Hour, now)

	eng, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, nowf, rootPEM, interPEM, interKeyPEM, "")
	if err != nil {
		t.Fatalf("offline engine: %v", err)
	}
	// The anchor surfaced to clients is the OFFLINE root we supplied.
	rb, _ := pem.Decode(eng.RootCertificatePEM())
	if rb == nil || !bytes.Equal(rb.Bytes, rootDER) {
		t.Fatal("engine root anchor is not the supplied offline root")
	}
	// The Edge holds no root key: the issuer's signer is the intermediate key, and there is no root signer.
	if eng.offlineIssuer == nil {
		t.Fatal("offlineIssuer not set")
	}

	leaf, err := eng.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	// ★ THE ANCHOR IS NOT PRESENTED (2026-08-21). The chain is [leaf, intermediate]; the ROOT is what a device
	// holds in its own store, and sending it back to the device helps nobody. Measured the day a third tier
	// appeared: a four-deep chain ending in a self-signed certificate made git report "self signed certificate
	// in certificate chain" and stop reaching github from an intercepted machine.
	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain len=%d want 2 [leaf,intermediate] — the root is a trust anchor, not a chain member",
			len(leaf.Certificate))
	}
	leafX, _ := x509.ParseCertificate(leaf.Certificate[0])
	interX, _ := x509.ParseCertificate(leaf.Certificate[1])
	// ★ THE ANCHOR IS NOT ON THE WIRE. A device verifies against the root it holds, so the test does too —
	// see the note in loadOfflineInterceptionIssuer.
	rootX, _ := x509.ParseCertificate(rootDER)
	roots := x509.NewCertPool()
	roots.AddCert(rootX)
	inters := x509.NewCertPool()
	inters.AddCert(interX)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "host.example.com", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := leafX.Verify(opts); err != nil {
		t.Fatalf("leaf does not validate to the offline root via the intermediate: %v", err)
	}

	// Name constraint must bite.
	evil, _ := eng.leafCertificate("", "evil.com")
	evilX, _ := x509.ParseCertificate(evil.Certificate[0])
	if _, err := evilX.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "evil.com", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("name constraint did not bite for an out-of-namespace leaf")
	}
}

// issueInterUnderRoot issues a name-constrained intermediate signed by the given root key (same root = anchor
// unchanged), returning its cert+key PEM.
func issueInterUnderRoot(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, now time.Time) (interCertPEM, interKeyPEM []byte) {
	t.Helper()
	sn := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: sn(), Subject: pkix.Name{CommonName: "Rotating Issuing CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &k.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	kDER, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kDER})
}

// TestOfflineInterceptionIntermediateRotation proves offline rotation: the Edge hot-swaps to a fresh intermediate
// the offline root re-issued, new leaves chain through the NEW intermediate, the root anchor is unchanged, and a
// rotation that does not chain to the current root is rejected (device trust must not change).
func TestOfflineInterceptionIntermediateRotation(t *testing.T) {
	now := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	nowf := func() time.Time { return now }
	sn := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: sn(), Subject: pkix.Name{CommonName: "Offline Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	interA, interAKey := issueInterUnderRoot(t, root, rootKey, now)
	eng, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, nowf, rootPEM, interA, interAKey, "")
	if err != nil {
		t.Fatal(err)
	}
	leaf1, _ := eng.leafCertificate("", "a.example.com")
	interAon, _ := pem.Decode(interA)

	// Rotate to a fresh intermediate signed by the SAME root.
	interB, interBKey := issueInterUnderRoot(t, root, rootKey, now)
	if err := eng.ReloadOfflineIntermediate(rootPEM, interB, interBKey); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	leaf2, _ := eng.leafCertificate("", "a.example.com")
	if bytes.Equal(leaf1.Certificate[1], leaf2.Certificate[1]) {
		t.Fatal("rotation did not change the intermediate in the leaf chain")
	}
	if !bytes.Equal(leaf2.Certificate[1], interBon(interB)) {
		t.Fatal("post-rotation leaf does not chain through the new intermediate")
	}
	if len(leaf2.Certificate) != 2 {
		t.Fatalf("post-rotation chain len=%d, want 2 [leaf,intermediate] — the anchor is never presented",
			len(leaf2.Certificate))
	}
	_ = interAon

	// A rotation whose root is NOT the current anchor must be rejected.
	otherRootPEM, otherInter, otherInterKey, _ := offlineCAFixture(t, nil, 90*24*time.Hour, now)
	if err := eng.ReloadOfflineIntermediate(otherRootPEM, otherInter, otherInterKey); err == nil {
		t.Fatal("rotation to a different root anchor must be rejected")
	}
}

func interBon(interPEM []byte) []byte {
	b, _ := pem.Decode(interPEM)
	if b == nil {
		return nil
	}
	return b.Bytes
}

func TestOfflineInterceptionIntermediateRejectsBadBundles(t *testing.T) {
	now := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	nowf := func() time.Time { return now }

	// Intermediate not signed by the supplied root (mismatched root).
	_, interPEM, interKeyPEM, _ := offlineCAFixture(t, nil, 90*24*time.Hour, now)
	otherRootPEM, _, _, _ := offlineCAFixture(t, nil, 90*24*time.Hour, now)
	if _, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, nowf, otherRootPEM, interPEM, interKeyPEM, ""); err == nil {
		t.Fatal("must reject an intermediate not signed by the given root")
	}

	// Expired intermediate.
	rootPEM2, interPEM2, interKeyPEM2, _ := offlineCAFixture(t, nil, -time.Hour, now)
	if _, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, nowf, rootPEM2, interPEM2, interKeyPEM2, ""); err == nil {
		t.Fatal("must reject an expired intermediate")
	}

	// Mismatched key (intermediate cert from one fixture, key from another).
	rootPEM3, interPEM3, _, _ := offlineCAFixture(t, nil, 90*24*time.Hour, now)
	_, _, otherKeyPEM, _ := offlineCAFixture(t, nil, 90*24*time.Hour, now)
	if _, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate([]string{"*"}, nowf, rootPEM3, interPEM3, otherKeyPEM, ""); err == nil {
		t.Fatal("must reject when the key does not match the intermediate cert")
	}
}

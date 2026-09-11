package edgeplane

import (
	"bytes"
	"crypto"
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

// A stand-in for the token: a signer whose private key this test can use, standing where the PKCS#11 key
// stands. What matters is that adoption only ever calls Public()/Sign() on it — never asks for the key.
type reparentTestProvider struct {
	cert   *x509.Certificate
	signer *ecdsa.PrivateKey
}

func (p *reparentTestProvider) Certificate() *x509.Certificate { return p.cert }
func (p *reparentTestProvider) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw})
}
func (p *reparentTestProvider) Signer() crypto.Signer { return p.signer }

func mintReparentCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	signWith, signKey := tmpl, key
	if parent != nil {
		signWith, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signWith, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// newTestInterceptionForReparent stands up just enough of the interception object for the re-parenting path:
// a registry whose default provider holds the cert + signer that stand in for the token's.
func newTestInterceptionForReparent(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) *NetworkExtensionLabTLSInterception {
	t.Helper()
	provider := &reparentTestProvider{cert: cert, signer: key}
	return &NetworkExtensionLabTLSInterception{
		rootCert:         cert,
		rootCertPEM:      provider.CertPEM(),
		rootRegistry:     NewTenantInterceptionRootRegistry(provider, time.Now),
		leafCache:        map[string]tls.Certificate{},
		interceptIssuers: map[string]*InterceptionIssuer{},
		now:              time.Now,
	}
}

// The custody-preserving migration end to end: the Edge asks for a certificate for the key it already holds,
// a central root signs that request, and adopting the result moves the anchor without the key going anywhere.
// This is the shape docs/pki_hierarchy_gap_2026_08_01.ja.md asks for and that neither existing mode gave —
// runtime keeps the key in its token but makes the Edge the root; offline moves the root away but demands the
// key as a file.
func TestReparentingMovesTheAnchorWithoutMovingTheKey(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)

	// 1. The Edge asks. The request is signed BY the token key, and carries its public key.
	csrPEM, err := InterceptionIntermediateCSR(interception, "Lantern DSSE Interception Issuing CA", "Lantern DSSE")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a PEM certificate request, got %q", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("the request must be signed by the interception key: %v", err)
	}
	if csr.Subject.CommonName != "Lantern DSSE Interception Issuing CA" {
		t.Fatalf("subject not carried into the request: %q", csr.Subject.CommonName)
	}

	// 2. The central root signs it — for the SAME public key the token holds.
	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, centralRoot, csr.PublicKey, centralKey)
	if err != nil {
		t.Fatal(err)
	}
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})

	// 3. Adoption: the anchor becomes the central root, and the signer is still the same key. A state dir is
	// required now (a durable trust change is not allowed to be undurable), so give it one.
	if err := AdoptReparentedIntermediate(interception, rootPEM, interPEM, t.TempDir()); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if interception.rootCert.Subject.CommonName != "Central MSSP Root" {
		t.Fatalf("the anchor must become the central root, got %q", interception.rootCert.Subject.CommonName)
	}
	issuer := interception.offlineIssuer
	if issuer == nil {
		t.Fatal("adoption must install an issuer")
	}
	if issuer.signer != crypto.Signer(tokenKey) {
		t.Fatal("the signer must remain the key the Edge already held — the whole point is that it does not move")
	}
	// ★ [intermediate] ONLY (2026-08-21): the root is a trust anchor and is not presented — see
	// loadOfflineInterceptionIssuer. The leaf verification below is what proves the chain still reaches it.
	if len(issuer.chain) != 1 {
		t.Fatalf("the served chain must be [intermediate], got %d entries", len(issuer.chain))
	}
	// And a leaf minted now really does verify to the new root through the adopted intermediate.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"example.com"}, BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuer.signingCert, &leafKey.PublicKey, issuer.signer)
	if err != nil {
		t.Fatalf("the adopted intermediate must be able to sign leaves with the retained key: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(centralRoot)
	inter := x509.NewCertPool()
	inter.AddCert(issuer.signingCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: "example.com"}); err != nil {
		t.Fatalf("a leaf minted after adoption must verify to the new root: %v", err)
	}
}

// Adoption refuses anything that would leave the Edge presenting a chain it cannot sign under, or that is not
// a re-parenting at all. Each of these would otherwise fail at the first intercepted site, fleet-wide.
func TestReparentingRefusesCertificatesItCannotSignUnder(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})

	// A CA for somebody ELSE's key, correctly signed by the root: the Edge could not sign under it.
	strangerCA, _ := mintReparentCA(t, "Someone Else", centralRoot, centralKey)
	strangerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: strangerCA.Raw})
	if err := AdoptReparentedIntermediate(interception, rootPEM, strangerPEM, ""); err == nil {
		t.Fatal("a certificate for another key must be refused — the Edge cannot sign under it")
	} else if !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("the refusal must say the key does not match, got: %v", err)
	}

	// Correct key, but NOT signed by the supplied root: not a re-parenting.
	unrelatedRoot, unrelatedKey := mintReparentCA(t, "Unrelated Root", nil, nil)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, interTmpl, unrelatedRoot, tokenKey.Public(), unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := AdoptReparentedIntermediate(interception, rootPEM, otherPEM, ""); err == nil {
		t.Fatal("a certificate not signed by the supplied root must be refused")
	}

	// The anchor must be untouched after every refusal.
	if interception.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatalf("a refused adoption must leave the anchor alone, got %q", interception.rootCert.Subject.CommonName)
	}
}

// A persisted re-parent that cannot be restored at boot must be VISIBLE (degraded), not a silent revert to the
// self-signed root — a device on the MSSP root would reject the self-signed chain.
func TestReparentRestoreFailureIsVisibleNotSilent(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	dir := t.TempDir()

	// Persist a pair that will FAIL validation: an intermediate for a DIFFERENT key (not the token key).
	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	stranger, _ := mintReparentCA(t, "Someone Else", centralRoot, centralKey)
	if err := os.WriteFile(filepath.Join(dir, reparentedRootFileName),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, reparentedIntermediateFileName),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stranger.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	ReapplyPersistedReparent(interception, dir)

	if _, failed := interception.InterceptionIntermediateStatus()["reparent_restore_failed"]; !failed {
		t.Fatal("a persisted re-parent that fails to restore must surface reparent_restore_failed, not revert silently")
	}
	if interception.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatalf("the live anchor must stay self-signed on a failed restore, got %q", interception.rootCert.Subject.CommonName)
	}
	// A clean restore clears it.
	interception.setReparentRestoreFailed("")
	if _, failed := interception.InterceptionIntermediateStatus()["reparent_restore_failed"]; failed {
		t.Fatal("clearing the flag must remove it from the status")
	}
}

// A durable trust change may not be undurable: adopting with no state dir is REFUSED, and the live
// anchor is left untouched — because a warn-and-succeed here reads as "migration done" and the first redeploy
// silently reverts to the self-signed root.
func TestReparentRefusesAdoptWithoutAStateDir(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	csrPEM, err := InterceptionIntermediateCSR(interception, "Lantern DSSE Interception Issuing CA", "Lantern DSSE")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(51), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, centralRoot, csr.PublicKey, centralKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	// A VALID pair — the only thing wrong is that there is nowhere to persist it.
	if err := AdoptReparentedIntermediate(interception, rootPEM, interPEM, ""); err == nil {
		t.Fatal("a durable trust change with no state dir must be refused, not silently accepted")
	} else if !strings.Contains(err.Error(), "state-dir") {
		t.Fatalf("the refusal must name the state dir: %v", err)
	}
	if interception.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatalf("a refused adopt must leave the live anchor untouched, got %q", interception.rootCert.Subject.CommonName)
	}
}

// The two extension/validity traps behind past interception outages: an intermediate minted CA:TRUE but
// unable to ISSUE (keyUsage without certSign), and a root the endpoints pin that is outside its validity
// window. Both would be adopted by a check that only looks at IsCA + signature, then break every site.
func TestReparentRefusesAnUnusableIntermediateAndAnExpiredRoot(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})

	// (a) Correct key, correctly signed by the root, CA:TRUE — but keyUsage omits certSign, so it cannot issue
	// the per-site leaves. Endpoints would reject every leaf; adopt must refuse it up front.
	noCertSign := &x509.Certificate{
		SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "No CertSign Issuing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, noCertSign, centralRoot, tokenKey.Public(), centralKey)
	if err != nil {
		t.Fatal(err)
	}
	noCertSignPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := AdoptReparentedIntermediate(interception, rootPEM, noCertSignPEM, ""); err == nil {
		t.Fatal("an intermediate without certSign must be refused — it cannot issue leaves")
	} else if !strings.Contains(err.Error(), "certSign") {
		t.Fatalf("the refusal must name certSign, got: %v", err)
	}

	// (b) A well-formed intermediate under an EXPIRED root. The signature checks pass; the root's dates do not.
	expiredKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiredRootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(22), Subject: pkix.Name{CommonName: "Expired Root"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredRootTmpl, expiredRootTmpl, &expiredKey.PublicKey, expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredRoot, err := x509.ParseCertificate(expiredDER)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(23), Subject: pkix.Name{CommonName: "Issuing Under Expired Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, expiredRoot, tokenKey.Public(), expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER})
	interUnderExpiredPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	if err := AdoptReparentedIntermediate(interception, expiredRootPEM, interUnderExpiredPEM, ""); err == nil {
		t.Fatal("an expired root must be refused — endpoints pinning it would fail the whole chain")
	} else if !strings.Contains(err.Error(), "root is not currently valid") {
		t.Fatalf("the refusal must name the root validity, got: %v", err)
	}

	if interception.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatalf("a refused adoption must leave the anchor alone, got %q", interception.rootCert.Subject.CommonName)
	}
}

// The reparent must survive a restart. adopt is in-memory, so without persistence the first redeploy drops
// the Edge back to the self-signed interception root (docs/pki_hierarchy_gap_2026_08_01.ja.md). adopt
// writes the pair to a state dir, and a fresh interception object (a new boot) restores it — the token key
// is the same, so the persisted intermediate still matches.
func TestReparentPersistsAcrossARestart(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	first := newTestInterceptionForReparent(t, selfSigned, tokenKey)

	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	csrPEM, err := InterceptionIntermediateCSR(first, "Issuing CA", "Lantern DSSE")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, centralRoot, csr.PublicKey, centralKey)
	if err != nil {
		t.Fatal(err)
	}
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})

	dir := t.TempDir()
	if err := AdoptReparentedIntermediate(first, rootPEM, interPEM, dir); err != nil {
		t.Fatalf("adopt with persistence: %v", err)
	}

	// A NEW boot: same token key, fresh interception object on the self-signed root, nothing adopted in memory.
	second := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	if second.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatal("a fresh boot must start on the self-signed root before restore")
	}
	ReapplyPersistedReparent(second, dir)
	if second.rootCert.Subject.CommonName != "Central MSSP Root" {
		t.Fatalf("the persisted re-parent must be restored at boot, got anchor %q", second.rootCert.Subject.CommonName)
	}
	if second.offlineIssuer == nil || second.offlineIssuer.signer != crypto.Signer(tokenKey) {
		t.Fatal("the restored issuer must sign with the token key, unchanged")
	}

	// A boot whose token key does NOT match the persisted intermediate must refuse to restore and stay on the
	// self-signed root, never present a chain it cannot sign under.
	_, otherKey := mintReparentCA(t, "Different Edge Root", nil, nil)
	otherSelf, _ := mintReparentCA(t, "Different Edge Root", nil, nil)
	third := newTestInterceptionForReparent(t, otherSelf, otherKey)
	ReapplyPersistedReparent(third, dir)
	if third.rootCert.Subject.CommonName == "Central MSSP Root" {
		t.Fatal("a persisted intermediate for another key must NOT be restored — it cannot be signed under")
	}

	// No persisted pair = the ordinary never-reparented boot: unchanged, no error.
	fourth := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	ReapplyPersistedReparent(fourth, t.TempDir())
	if fourth.rootCert.Subject.CommonName != "Edge Interception Root" {
		t.Fatal("with no persisted reparent the self-signed root must stand")
	}
}

// ★ THE FILE DEVICES ARE TOLD TO INSTALL FROM WENT STALE ON A RE-PARENT (2026-08-16). -...-root-ca-cert-out
// exists for exactly one purpose: "this is the root to put in a machine's trust store". It was written once at
// startup and never again, so the moment the anchor moved, that file went on naming the previous root.
//
// Measured on the reference lab after its interception root was re-parented to the MSSP root: the Edge served
// 36973669… and the distribution file still held 5a74ac31…. An operator following the deployment's own
// procedure installs a root that verifies nothing, every HTTPS site fails on that machine, and the file that
// told them to do it looks perfectly valid — no error anywhere, because writing it was never attempted again.
func TestReparentRewritesTheRootFileDevicesAreToldToInstall(t *testing.T) {
	selfSigned, tokenKey := mintReparentCA(t, "Edge Interception Root", nil, nil)
	interception := newTestInterceptionForReparent(t, selfSigned, tokenKey)
	anchorFile := filepath.Join(t.TempDir(), "interception_root_ca.pem")
	if err := WriteNetworkExtensionLabTLSRootCertificatePEM(anchorFile, interception.rootCertPEM); err != nil {
		t.Fatalf("seed the distribution file: %v", err)
	}
	interception.rootCACertOutPath = anchorFile

	centralRoot, centralKey := mintReparentCA(t, "Central MSSP Root", nil, nil)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, centralRoot, tokenKey.Public(), centralKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: centralRoot.Raw})
	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	if err := AdoptReparentedIntermediate(interception, rootPEM, interPEM, t.TempDir()); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	onDisk, rerr := os.ReadFile(anchorFile)
	if rerr != nil {
		t.Fatalf("read the distribution file: %v", rerr)
	}
	distributed, perr := ParseInterceptionCertPEM(onDisk)
	if perr != nil {
		t.Fatalf("the distribution file is not a certificate any more: %v", perr)
	}
	if distributed.Subject.CommonName != "Central MSSP Root" {
		t.Fatalf("the file devices install from still names %q while the Edge serves %q — distributing it breaks "+
			"every HTTPS site on that machine", distributed.Subject.CommonName, interception.rootCert.Subject.CommonName)
	}
	// And it is the anchor in force, byte for byte: a file that merely CHANGED would be no better if it
	// changed to something else.
	if !bytes.Equal(distributed.Raw, interception.rootCert.Raw) {
		t.Fatal("the distribution file and the served anchor are different certificates")
	}
}

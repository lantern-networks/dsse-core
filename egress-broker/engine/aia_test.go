package engine

// aia_test.go — the invariants that make AIA chasing safe, stated as tests.
//
// The one that matters most is TestFetchIssuerRejectsACertificateThatIsItsOwnRoot: fetching a certificate named
// by an AIA URI must never be a way to INSTALL a trust anchor. If that test ever passes trivially (because the
// bar was relaxed), the feature has become a hole rather than a fix.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// mintCA issues a CA certificate. parent == nil makes it self-signed (a root).
func mintCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("mint %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", cn, err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

// mintLeaf issues an end-entity certificate carrying an AIA CA Issuers URI, the shape this whole feature exists
// to handle.
func mintLeaf(t *testing.T, cn string, parent *testCA, aiaURL string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	if aiaURL != "" {
		tmpl.IssuingCertificateURL = []string{aiaURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("mint leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func serveDER(t *testing.T, der []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestResolver(t *testing.T, roots *x509.CertPool) *aiaResolver {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.pem")
	if err := os.WriteFile(base, []byte("# base bundle\n"), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	a := newAIAResolver()
	a.failed = false
	a.basePath = base
	a.combined = filepath.Join(dir, "combined.pem")
	a.learned = map[string]learnedIssuer{}
	a.roots = func() (*x509.CertPool, error) { return roots, nil }
	return a
}

// The safety bar: an AIA URI serving a self-signed root must be refused. Accepting it would mean any origin
// could name a certificate and have the broker start trusting it — installing a trust anchor over plain HTTP.
func TestFetchIssuerRejectsACertificateThatIsItsOwnRoot(t *testing.T) {
	trusted := mintCA(t, "Trusted Root", nil)
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)

	rogue := mintCA(t, "Rogue Root", nil) // self-signed, chains to nothing we trust
	srv := serveDER(t, rogue.der)
	leaf := mintLeaf(t, "victim.example", rogue, srv.URL)

	a := newTestResolver(t, roots)
	if _, err := a.fetchIssuer(leaf, roots, x509.NewCertPool()); err == nil {
		t.Fatal("fetchIssuer accepted a self-signed root from an AIA URI — that is trust-anchor injection, not path completion")
	}
	if len(a.learned) != 0 {
		t.Fatalf("nothing may be learned from a refused fetch, got %d", len(a.learned))
	}
}

// The case the feature exists for: the issuer is published cross-signed by a CA we already trust, so keeping it
// completes a path without widening trust.
func TestFetchIssuerAcceptsACrossSignedIssuerThatChainsToATrustedRoot(t *testing.T) {
	trusted := mintCA(t, "Trusted Root", nil)
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)

	crossSigned := mintCA(t, "Origin Root G2", trusted) // the "- xsign" certificate
	srv := serveDER(t, crossSigned.der)
	leaf := mintLeaf(t, "origin.example", crossSigned, srv.URL)

	a := newTestResolver(t, roots)
	got, err := a.fetchIssuer(leaf, roots, x509.NewCertPool())
	if err != nil {
		t.Fatalf("fetchIssuer refused a legitimately cross-signed issuer: %v", err)
	}
	if got.Subject.CommonName != "Origin Root G2" {
		t.Fatalf("fetched the wrong certificate: %q", got.Subject.CommonName)
	}
}

func TestFetchIssuerRejectsANonCACertificate(t *testing.T) {
	trusted := mintCA(t, "Trusted Root", nil)
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)

	notACA := mintLeaf(t, "not-a-ca.example", trusted, "")
	srv := serveDER(t, notACA.Raw)
	leaf := mintLeaf(t, "origin.example", trusted, srv.URL)

	a := newTestResolver(t, roots)
	if _, err := a.fetchIssuer(leaf, roots, x509.NewCertPool()); err == nil {
		t.Fatal("fetchIssuer accepted an end-entity certificate as an issuer")
	}
}

func TestFetchIssuerReportsWhenNoAIAIsPublished(t *testing.T) {
	trusted := mintCA(t, "Trusted Root", nil)
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)
	leaf := mintLeaf(t, "no-aia.example", trusted, "")

	a := newTestResolver(t, roots)
	_, err := a.fetchIssuer(leaf, roots, x509.NewCertPool())
	if err == nil || !strings.Contains(err.Error(), "no CA Issuers URI") {
		t.Fatalf("want a 'publishes no CA Issuers URI' error, got %v", err)
	}
}

// Until a chase succeeds the engine must hand curl nothing, so a deployment that never needs this runs exactly
// as it did before the feature existed.
//
// REGRESSION (live, 2026-08-06): caInfo used to open as soon as a link was LEARNED, which is before the bundle
// file exists. Every concurrent request in that window got a CAINFO path pointing at nothing, and curl fails
// EVERY handshake when it cannot open its CA file — www.microsoft.com went from 200 to intermittent 000. The
// path may only be published once the file is on disk.
func TestCAInfoStaysEmptyUntilTheBundleIsActuallyOnDisk(t *testing.T) {
	a := newTestResolver(t, x509.NewCertPool())
	if got := a.caInfo(); got != "" {
		t.Fatalf("caInfo must be empty with nothing learned, got %q", got)
	}
	trusted := mintCA(t, "Trusted Root", nil)
	a.keep(trusted.cert)
	if got := a.caInfo(); got != "" {
		t.Fatalf("caInfo published %q before the bundle was written — that path does not exist yet and would break every handshake", got)
	}
	if _, err := os.Stat(a.combined); err == nil {
		t.Fatal("test is not exercising the window: the bundle already exists")
	}
	if err := a.writeCombined(); err != nil {
		t.Fatalf("writeCombined: %v", err)
	}
	if got := a.caInfo(); got != a.combined {
		t.Fatalf("caInfo = %q, want the combined bundle path %q once staged", got, a.combined)
	}
	if _, err := os.Stat(a.combined); err != nil {
		t.Fatalf("caInfo published a path that is not on disk: %v", err)
	}
}

// REGRESSION (live, 2026-08-06): assets.onestore.ms publishes its ALREADY-TRUSTED DigiCert root at its AIA URI.
// Accepting it satisfied "chains to a trusted root" trivially (a root verifies against itself), so every request
// "learned" it, rewrote the bundle, retried, and failed again — churn with no progress, and the cooldown never
// engaged because something was always learned. A self-signed certificate can never be a missing link.
func TestFetchIssuerRejectsASelfSignedRootEvenWhenItIsAlreadyTrusted(t *testing.T) {
	trusted := mintCA(t, "Already Trusted Root", nil)
	roots := x509.NewCertPool()
	roots.AddCert(trusted.cert)

	srv := serveDER(t, trusted.der) // the AIA URI serves the trusted root itself
	leaf := mintLeaf(t, "onestore.example", trusted, srv.URL)

	a := newTestResolver(t, roots)
	_, err := a.fetchIssuer(leaf, roots, x509.NewCertPool())
	if err == nil {
		t.Fatal("fetchIssuer kept an already-trusted self-signed root — it adds nothing and starts a retry loop")
	}
	if !strings.Contains(err.Error(), "self-signed") {
		t.Fatalf("want the refusal to name the reason, got %v", err)
	}
	if len(a.learned) != 0 {
		t.Fatalf("nothing may be learned, got %d", len(a.learned))
	}
}

// The combined bundle must EXTEND the base trust store, never replace it: a CAINFO holding only learned certs
// would silently narrow trust to whatever we happened to fetch.
func TestCombinedBundleIsBasePlusLearnedNeverLearnedAlone(t *testing.T) {
	a := newTestResolver(t, x509.NewCertPool())
	if err := os.WriteFile(a.basePath, []byte("# BASE-MARKER\n"), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	learnedCA := mintCA(t, "Learned Link", nil)
	a.keep(learnedCA.cert)
	if err := a.writeCombined(); err != nil {
		t.Fatalf("writeCombined: %v", err)
	}
	out, err := os.ReadFile(a.combined)
	if err != nil {
		t.Fatalf("read combined: %v", err)
	}
	if !strings.Contains(string(out), "BASE-MARKER") {
		t.Fatal("combined bundle dropped the base trust store")
	}
	blk, rest := pem.Decode(out[strings.Index(string(out), "-----BEGIN"):])
	if blk == nil {
		t.Fatal("combined bundle carries no certificate")
	}
	_ = rest
	if c, err := x509.ParseCertificate(blk.Bytes); err != nil || c.Subject.CommonName != "Learned Link" {
		t.Fatalf("combined bundle does not carry the learned link (err=%v)", err)
	}
}

// A learned link is not trusted forever: once past its TTL it is dropped and must re-prove itself.
func TestLearnedLinksExpire(t *testing.T) {
	a := newTestResolver(t, x509.NewCertPool())
	stale := mintCA(t, "Stale Link", nil)
	a.keep(stale.cert)
	a.mu.Lock()
	for k, v := range a.learned {
		v.learnedAt = time.Now().Add(-2 * aiaLearnedTTL)
		a.learned[k] = v
	}
	a.mu.Unlock()

	a.addLearnedTo(x509.NewCertPool())
	a.mu.Lock()
	n := len(a.learned)
	a.mu.Unlock()
	if n != 0 {
		t.Fatalf("an expired link must be dropped, %d remain", n)
	}
}

func TestParseCertificateAcceptsDERAndPEM(t *testing.T) {
	ca := mintCA(t, "Either Form", nil)
	if c, err := parseCertificate(ca.der); err != nil || c.Subject.CommonName != "Either Form" {
		t.Fatalf("DER form rejected: %v", err)
	}
	asPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
	if c, err := parseCertificate(asPEM); err != nil || c.Subject.CommonName != "Either Form" {
		t.Fatalf("PEM form rejected: %v", err)
	}
	if _, err := parseCertificate([]byte("not a certificate")); err == nil {
		t.Fatal("garbage accepted as a certificate")
	}
}

// A host that teaches us nothing must not be re-probed on every request — otherwise a genuinely untrusted
// origin turns one cheap refusal into a dial plus a fetch, every time.
func TestAHostThatTaughtUsNothingIsLeftAloneForTheCooldown(t *testing.T) {
	a := newTestResolver(t, x509.NewCertPool())
	a.mu.Lock()
	a.attempts["untrusted.example:443"] = time.Now()
	a.mu.Unlock()
	if a.learnFor("https://untrusted.example/whatever") {
		t.Fatal("learnFor re-probed a host inside its cooldown")
	}
}

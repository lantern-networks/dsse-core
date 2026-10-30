package deploymentcrl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	root, issuer, leaf, other *x509.Certificate
	rootKey, issuerKey        *ecdsa.PrivateKey
	base                      string
	now                       time.Time
}

func fixtureCert(t *testing.T, template, parent *x509.Certificate, key *ecdsa.PrivateKey, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeFixture(t *testing.T) fixture {
	return makeFixtureAt(t, "http://crl.example.test")
}

func makeFixtureAt(t *testing.T, base string) fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "deployment root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root := fixtureCert(t, rootTemplate, rootTemplate, rootKey, rootKey)
	rootPoints, err := DistributionPoints([]string{base}, root, root)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "transport issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, CRLDistributionPoints: rootPoints}
	issuer := fixtureCert(t, issuerTemplate, root, issuerKey, rootKey)
	issuerPoints, err := DistributionPoints([]string{base}, root, issuer)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "agents.example.test"}, DNSNames: []string{"agents.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CRLDistributionPoints: issuerPoints}
	leaf := fixtureCert(t, leafTemplate, issuer, leafKey, issuerKey)
	otherTemplate := *leafTemplate
	otherTemplate.SerialNumber = big.NewInt(4)
	other := fixtureCert(t, &otherTemplate, issuer, otherKey, issuerKey)
	return fixture{root, issuer, leaf, other, rootKey, issuerKey, base, now}
}

func TestOnlineProbeRequiresCurrentSignedStatusWithoutRedirect(t *testing.T) {
	var handler http.Handler
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			if status == http.StatusFound {
				http.Redirect(w, r, "/other", http.StatusFound)
			} else {
				http.Error(w, "unavailable", status)
			}
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	f := makeFixtureAt(t, server.URL)
	authority, public := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "public")
	issuers := []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}
	if err := Refresh(authority, public, f.root, issuers, nil, f.now); err != nil {
		t.Fatal(err)
	}
	var err error
	handler, err = Handler(public, f.root, []*x509.Certificate{f.root, f.issuer}, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{f.leaf, f.issuer, f.root}
	if err := ProbeOnline(context.Background(), chain, server.Client(), f.now); err != nil {
		t.Fatalf("reachable signed status denied: %v", err)
	}
	status = http.StatusFound
	if err := ProbeOnline(context.Background(), chain, server.Client(), f.now); err == nil {
		t.Fatal("redirect accepted as online revocation status")
	}
	status = http.StatusServiceUnavailable
	if err := ProbeOnline(context.Background(), chain, server.Client(), f.now); err == nil {
		t.Fatal("unavailable CDP accepted")
	}
	status = http.StatusOK
	if err := Refresh(authority, public, f.root, issuers, []Revocation{{f.issuer, f.leaf, 1}}, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := ProbeOnline(context.Background(), chain, server.Client(), f.now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked leaf accepted online: %v", err)
	}
}

func TestSignedPublicationRevocationAndRollback(t *testing.T) {
	f := makeFixture(t)
	authority, public := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "public")
	issuers := []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}
	if err := Refresh(authority, public, f.root, issuers, nil, f.now); err != nil {
		t.Fatal(err)
	}
	if err := Ready(authority, public, f.root, []*x509.Certificate{f.root, f.issuer}, f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	read := func(cert *x509.Certificate) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(public, Fingerprint(cert)+".crl"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	lists := map[string][]byte{Fingerprint(f.root): read(f.root), Fingerprint(f.issuer): read(f.issuer)}
	if err := VerifyStatus([]*x509.Certificate{f.leaf, f.issuer, f.root}, lists, f.now); err != nil {
		t.Fatal(err)
	}
	old := read(f.issuer)
	if err := Refresh(authority, public, f.root, issuers, []Revocation{{f.issuer, f.leaf, 1}}, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lists[Fingerprint(f.issuer)] = read(f.issuer)
	if err := VerifyStatus([]*x509.Certificate{f.leaf, f.issuer, f.root}, lists, f.now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked leaf accepted: %v", err)
	}
	if err := VerifyStatus([]*x509.Certificate{f.other, f.issuer, f.root}, lists, f.now.Add(time.Minute)); err != nil {
		t.Fatalf("unrelated leaf denied: %v", err)
	}
	if err := os.WriteFile(filepath.Join(public, Fingerprint(f.issuer)+".crl"), old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Ready(authority, public, f.root, []*x509.Certificate{f.root, f.issuer}, f.now.Add(time.Minute), time.Hour); err == nil {
		t.Fatal("rollback should make deployment unready")
	}
	if err := Refresh(authority, public, f.root, issuers, nil, f.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := Ready(authority, public, f.root, []*x509.Certificate{f.root, f.issuer}, f.now.Add(2*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedDeploymentIssuerDoesNotRevokeIndependentIssuer(t *testing.T) {
	f := makeFixture(t)
	otherIssuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherLeafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootPoints, _ := DistributionPoints([]string{f.base}, f.root, f.root)
	otherIssuer := fixtureCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "independent issuer"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(20 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: rootPoints,
	}, f.root, otherIssuerKey, f.rootKey)
	otherPoints, _ := DistributionPoints([]string{f.base}, f.root, otherIssuer)
	otherLeaf := fixtureCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(6), Subject: pkix.Name{CommonName: "other.example.test"},
		DNSNames: []string{"other.example.test"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(10 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: otherPoints,
	}, otherIssuer, otherLeafKey, otherIssuerKey)
	authority, public := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "public")
	issuers := []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}, {otherIssuer, otherIssuerKey}}
	if err := Refresh(authority, public, f.root, issuers, []Revocation{{f.root, f.issuer, 1}}, f.now); err != nil {
		t.Fatal(err)
	}
	lists := map[string][]byte{}
	for _, cert := range []*x509.Certificate{f.root, f.issuer, otherIssuer} {
		der, err := os.ReadFile(filepath.Join(public, Fingerprint(cert)+".crl"))
		if err != nil {
			t.Fatal(err)
		}
		lists[Fingerprint(cert)] = der
	}
	if err := VerifyStatus([]*x509.Certificate{f.leaf, f.issuer, f.root}, lists, f.now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked issuing CA remained valid: %v", err)
	}
	if err := VerifyStatus([]*x509.Certificate{otherLeaf, otherIssuer, f.root}, lists, f.now); err != nil {
		t.Fatalf("independent issuer was affected by revocation: %v", err)
	}
}

func TestPublisherOnlyServesCurrentSignedDERAtFixedHostAndPath(t *testing.T) {
	f := makeFixture(t)
	authority, public := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "public")
	if err := Refresh(authority, public, f.root, []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}, nil, f.now); err != nil {
		t.Fatal(err)
	}
	h, err := Handler(public, f.root, []*x509.Certificate{f.root, f.issuer}, []string{f.base})
	if err != nil {
		t.Fatal(err)
	}
	points, _ := DistributionPoints([]string{f.base}, f.root, f.issuer)
	request := func(raw, host string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, raw, nil)
		req.Host = host
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if got := request(points[0], "crl.example.test"); got.Code != http.StatusOK || got.Body.Len() == 0 || got.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("valid CRL not served: %d", got.Code)
	}
	for _, raw := range []string{points[0] + "?x=1", strings.Replace(points[0], Fingerprint(f.root), strings.Repeat("0", 64), 1), f.base + "/"} {
		if got := request(raw, "crl.example.test"); got.Code != http.StatusNotFound {
			t.Fatalf("unexpected path served: %d", got.Code)
		}
	}
	if got := request(points[0], "other.example.test"); got.Code != http.StatusNotFound {
		t.Fatalf("wrong host served: %d", got.Code)
	}
	if err := os.WriteFile(filepath.Join(public, publicationMarker), []byte("updating\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := request(points[0], "crl.example.test"); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("incomplete publication served: %d", got.Code)
	}
	if err := Ready(authority, public, f.root, []*x509.Certificate{f.root, f.issuer}, f.now, time.Hour); err == nil {
		t.Fatal("incomplete publication claimed ready")
	}
	if err := Refresh(authority, public, f.root, []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}, nil, f.now.Add(time.Minute)); err != nil {
		t.Fatalf("failed publication could not be repaired: %v", err)
	}
	if got := request(points[0], "crl.example.test"); got.Code != http.StatusOK {
		t.Fatalf("repaired publication not served: %d", got.Code)
	}
	if err := os.WriteFile(filepath.Join(public, Fingerprint(f.issuer)+".crl"), []byte("not signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := request(points[0], "crl.example.test"); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt CRL served: %d", got.Code)
	}
}

func TestCDPRejectsUnboundOrRecursiveLocations(t *testing.T) {
	f := makeFixture(t)
	for _, origin := range []string{"https://crl.example.test", "http://user@crl.example.test", "http://crl.example.test/path", "http://crl.example.test/?x=1"} {
		if _, err := DistributionPoints([]string{origin}, f.root, f.issuer); err == nil {
			t.Errorf("accepted invalid origin %s", origin)
		}
	}
	mutated := *f.leaf
	mutated.CRLDistributionPoints = []string{"http://crl.example.test/pki/deployment-crl/other/issuer.crl"}
	if _, err := DistributionPointsFromCertificate(&mutated, f.root, f.issuer); err == nil {
		t.Fatal("accepted unrelated issuer point")
	}
}

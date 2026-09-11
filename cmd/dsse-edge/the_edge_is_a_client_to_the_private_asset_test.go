package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/internalca"
)

// A private asset, signed by an authority no public root knows — an intranet server.
func privateAsset(t *testing.T) (server *httptest.Server, authorityPEM string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Kaede Internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "hq.kaede.internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"hq.kaede.internal"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "the intranet page")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func TestTheDecryptedFlowReachesAPrivateAssetOnlyForTheOrganizationThatVouchedForIt(t *testing.T) {
	now := time.Now().UTC()
	asset, authority := privateAsset(t)
	store, err := internalca.NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(internalca.Authority{
		ID: "a", TenantID: "kaede", Name: "Kaede internal", CertificatePEM: authority}, now); err != nil {
		t.Fatal(err)
	}

	base := http.DefaultTransport.(*http.Transport).Clone()

	// ★ THE CONTROL. Before this object existed, this was the ONLY behaviour: the Edge verified an intranet
	// server against the platform's public roots and refused it, after having decrypted it correctly.
	if _, err := (&http.Client{Transport: base}).Get(asset.URL); err == nil {
		t.Fatal("without an authored authority the asset must still be refused, or this test proves nothing")
	}

	// The organization that authored it reaches its own asset.
	mine := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, store, "kaede", now)
	resp, err := (&http.Client{Transport: mine}).Get(asset.URL)
	if err != nil {
		t.Fatalf("the organization that vouched for this authority must reach its own asset: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "the intranet page" {
		t.Fatalf("decrypted AND delivered is one measurement, got %q", body)
	}

	// ★★ ANOTHER ORGANIZATION MUST NOT. Widening is per organization; a shared Edge that widened once for
	// everybody would let one customer's authority vouch for any destination any other customer reaches.
	theirs := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, store, "northwind", now)
	if _, err := (&http.Client{Transport: theirs}).Get(asset.URL); err == nil {
		t.Fatal("another organization must not inherit this trust")
	}
}

func TestTheOrganizationsAnchorsAreADDEDToThePlatformsRootsNotSubstitutedForThem(t *testing.T) {
	now := time.Now().UTC()
	_, authority := privateAsset(t)
	store, _ := internalca.NewStore(nil)
	store.Upsert(internalca.Authority{ID: "a", TenantID: "kaede", CertificatePEM: authority}, now)

	base := http.DefaultTransport.(*http.Transport).Clone()
	widened := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, store, "kaede", now).(*http.Transport)

	system, err := x509.SystemCertPool()
	if err != nil || system == nil {
		t.Skip("no system pool on this machine to compare against")
	}
	// ★ A POOL BUILT FROM THE ORGANIZATION'S ANCHORS ALONE would fail every public origin for every device in
	// that organization — an outage shaped like a certificate problem on the internet rather than a change we
	// made. The pool must be strictly larger than the platform's.
	if len(widened.TLSClientConfig.RootCAs.Subjects()) <= len(system.Subjects()) { //nolint:staticcheck // comparing sizes is the point
		t.Fatal("the organization's anchors must be added to the platform's roots, not substituted for them")
	}
}

func TestAnOrganizationThatVouchedForNothingIsLeftExactlyAsItWas(t *testing.T) {
	store, _ := internalca.NewStore(nil)
	base := http.DefaultTransport.(*http.Transport).Clone()
	// The whole public web goes through here. It must stay on the platform's own verification, with no clone,
	// no extra pool and no second connection pool per organization.
	if got := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, store, "kaede", time.Now().UTC()); got != http.RoundTripper(base) {
		t.Fatal("an organization with no authored authority must get the untouched transport back")
	}
}

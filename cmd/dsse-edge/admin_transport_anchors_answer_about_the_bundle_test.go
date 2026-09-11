package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

// ★★★ THE SCREEN THAT DECIDES A WITHDRAWAL WAS LOOKING AT A DIFFERENT SET (2026-08-20, measured on the lab).
//
// /admin/transport-trust-anchors answered from the node's CONFIGURED bundle. Mid-overlap it listed ONE anchor —
// the shared, deployment-wide one — while the organization's devices were being handed THREE: the shared one
// plus the two authorities of its own it is being moved between. Readiness, "safe to cut" and the withdrawal
// button were therefore all computed about a set no device verifies against, on the one screen whose purpose is
// to decide when the shared anchor may leave that organization's bundle.
//
// Both now derive from announcedAnchorPEMs. This asserts the property in the direction that failed: the
// answer for an organization must contain that organization's own anchor.
func TestTheAnchorsScreenAnswersAboutTheBundleTheOrganizationIsSent(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	own, ok := transportTenantCertificates.AnchorFor("tenant_northwind")
	if !ok {
		t.Fatal("fixture: the organization has no anchor of its own")
	}

	// The deployment-wide set, standing in for the shared MSSP transport CA.
	sharedDir := t.TempDir()
	writeTenantCACert(t, sharedDir, "shared", "edge.dsse.invalid")
	sharedPEM, err := os.ReadFile(filepath.Join(sharedDir, "shared.crt"))
	if err != nil {
		t.Fatal(err)
	}
	shared := strings.TrimSpace(string(sharedPEM))
	bundles := newPerTenantTrustBundles(serverConfig{}, "tenant_reference_lab")
	bundles.SetTransportMaterial(shared+"\n", 12)

	pems, ownCount, withdrawn := bundles.AnnouncedAnchorsFor("tenant_northwind")
	if ownCount != 1 {
		t.Fatalf("the organization's own anchor is not counted: own=%d", ownCount)
	}
	if !strings.Contains(pems, strings.TrimSpace(own)) {
		t.Fatal("the answer does not carry the anchor this organization's devices are told to trust — which is " +
			"the whole content of the withdrawal decision this screen supports")
	}
	if !strings.Contains(pems, strings.TrimSpace(shared)) && !withdrawn {
		t.Fatal("the shared anchor is neither present nor reported as withdrawn, so the screen says nothing about " +
			"the state of the overlap")
	}

	// An organization with nothing of its own reads exactly the configured set, as every organization did
	// before roadmap D.
	plain, ownNone, _ := bundles.AnnouncedAnchorsFor("tenant_somebody_else")
	if ownNone != 0 || strings.TrimSpace(plain) != strings.TrimSpace(shared) {
		t.Fatalf("an organization with no authority of its own was answered something other than the shared set "+
			"(own=%d)", ownNone)
	}
}

// ★ AND THE ASSERTION IS ON THE ROUTE, NOT ON THE HELPER (the rule this repository wrote down after a guard
// that was never called passed for months). The test above proves announcedAnchorPEMs is right; only this one
// proves the screen asks it.
func TestTheAnchorsRouteItselfServesTheOrganizationsAnnouncedSet(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	own, ok := transportTenantCertificates.AnchorFor("tenant_northwind")
	if !ok {
		t.Fatal("fixture: the organization has no anchor of its own")
	}
	sharedDir := t.TempDir()
	writeTenantCACert(t, sharedDir, "shared", "edge.dsse.invalid")
	sharedPEM, err := os.ReadFile(filepath.Join(sharedDir, "shared.crt"))
	if err != nil {
		t.Fatal(err)
	}

	previous := perTenantTrustBundlesForAdmin
	t.Cleanup(func() { perTenantTrustBundlesForAdmin = previous })
	perTenantTrustBundlesForAdmin = newPerTenantTrustBundles(serverConfig{}, "tenant_northwind")
	perTenantTrustBundlesForAdmin.SetTransportMaterial(strings.TrimSpace(string(sharedPEM))+"\n", 12)

	mux := http.NewServeMux()
	config := serverConfig{TrustBundleCAPEM: string(sharedPEM), TrustBundleSerial: 12}
	registerTransportTrustAnchorsEndpoint(mux, config, "tenant_northwind",
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		func(*http.Request, string, string, string, map[string]any) {})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/transport-trust-anchors", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the screen refused: %d %s", rec.Code, rec.Body.String())
	}
	var out transportTrustAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OwnAnchors != 1 {
		t.Fatalf("the route does not report the organization's own authority: own_anchors=%d", out.OwnAnchors)
	}
	if len(out.Anchors) != 2 {
		t.Fatalf("the route listed %d anchor(s); this organization's devices are told to trust 2 (the shared "+
			"one and its own), and a withdrawal decided from the shorter list is decided about the wrong set",
			len(out.Anchors))
	}
	wanted := parseAllCerts([]byte(own))[0]
	found := false
	for _, a := range out.Anchors {
		if strings.EqualFold(a.SHA256, certFingerprint(wanted)) {
			found = true
		}
	}
	if !found {
		t.Fatal("the organization's own anchor is not among the ones the route lists")
	}
}

// writeTenantCACert is writeTenantCert with the certificate marked as an authority, which is what an ANCHOR is:
// the trust-bundle parser refuses a non-CA, correctly, and a fixture that does not survive that check would
// have tested the screen against material no deployment can announce.
func writeTenantCACert(t *testing.T, dir, tenant, dnsName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(41), Subject: pkix.Name{CommonName: dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tenant+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ★★★ A WITHDRAWAL THAT LEAVES THE SERIAL BEHIND IS NOT A WITHDRAWAL (2026-08-20, measured — and this is the
// last step of roadmap D slipping through a rule the announcement code states in its own comments).
//
// The shared anchor leaves ONE organization's bundle when that organization's devices have all adopted its own
// authority. The decision is made per organization while the bundle is built, and it moves nothing in the
// announcement string: the anchor index is the same, the names are the same. So the serial stood still while
// what a device is handed went from two anchors to one — and a device already holding that serial never
// fetches again, keeping for ever the shared anchor this step exists to take away from it.
//
// Measured on the lab: both devices reporting serial 87 with two anchors, the node serving serial 87 with one.
//
// This asserts the property at the seam where it is decided, so the announcement has something to carry.
func TestTheSharedAnchorWithdrawalIsVisibleToTheAnnouncement(t *testing.T) {
	dir := t.TempDir()
	writeTenantCACert(t, dir, "tenant_northwind", "northwind.dsse.invalid")
	useEmptyTenantCertificateIndex(t)
	if _, err := loadTransportTenantCertificates(dir); err != nil {
		t.Fatal(err)
	}
	sharedDir := t.TempDir()
	writeTenantCACert(t, sharedDir, "shared", "edge.dsse.invalid")
	sharedPEM, err := os.ReadFile(filepath.Join(sharedDir, "shared.crt"))
	if err != nil {
		t.Fatal(err)
	}
	bundles := newPerTenantTrustBundles(serverConfig{}, "tenant_reference_lab")
	bundles.SetTransportMaterial(strings.TrimSpace(string(sharedPEM))+"\n", 12)

	// With no measurement behind it the shared anchor stays, and the answer says so — an organization mid-way
	// must not be reported as finished.
	pems, own, withdrawn := bundles.AnnouncedAnchorsFor("tenant_northwind")
	if own != 1 {
		t.Fatalf("the organization's own authority is not counted: %d", own)
	}
	if withdrawn || !strings.Contains(pems, strings.TrimSpace(string(sharedPEM))) {
		t.Fatal("the shared anchor is reported as withdrawn while it is still in the bundle — an announcement " +
			"built from this would advance the serial for a change that did not happen")
	}
}

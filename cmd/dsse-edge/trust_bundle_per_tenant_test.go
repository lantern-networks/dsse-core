package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/enrolledinventory"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// testAgentPolicySigner is a throwaway Ed25519 signer: the bundle must be SIGNED for an agent to accept it,
// so a test that skipped signing would not be exercising the path a device takes.
func testAgentPolicySigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	signer, err := agentpolicy.NewSignerFromCrypto(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// trustBundleFor fetches the signed bundle the way an agent does and returns its payload.
func trustBundleFor(t *testing.T, handler http.Handler, deviceIdentity, queryTenant string) agentpolicy.TrustBundlePayload {
	t.Helper()
	path := "/bootstrap/trust-bundle"
	if queryTenant != "" {
		path += "?tenant=" + queryTenant
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if deviceIdentity != "" {
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: deviceIdentity}}
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust bundle: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var env agentpolicy.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	raw, derr := base64.StdEncoding.DecodeString(env.PayloadB64)
	if derr != nil {
		t.Fatalf("decode payload b64: %v", derr)
	}
	var payload agentpolicy.TrustBundlePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode payload: %v — %s", err, string(raw))
	}
	return payload
}

// ★ ONE BUNDLE WAS SERVED TO EVERY ORGANIZATION (2026-08-16). The trust bundle is the document that tells an
// agent which authorities to accept the Edge under and which interception roots to look for in its own trust
// store — and the tenant on it was always the organization that owns the Edge.
//
// That is invisible while every organization is intercepted by the same CA. It stops being invisible the
// moment each one signs under its own root: the bundle then names another organization's root, so a device
// looks for a certificate it will never have, reports that it does not hold it, and stays silent about the
// one it actually needs. The adoption measurement — the thing a CA replacement is gated on — reads exactly
// that report.
func TestEachOrganizationsTrustBundleNamesItsOwnInterceptionRoot(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	// northwind signs under its own root; the node's own organization keeps the node-wide anchor.
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := now.Format(time.RFC3339)
	if _, err := ledger.Enroll("nw-laptop-1", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("lab-laptop-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	signer := testAgentPolicySigner(t)
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	handler := newServerWithConfig(serverConfig{
		Evaluator:              testEvaluator(), // node tenant = tenant_lab_001
		EnrolledLedger:         ledger,
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      signer,
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      7,
		AdminAuth:              newAdminAuthStore(),
	})

	nw := trustBundleFor(t, handler, "nw-laptop-1", "")
	lab := trustBundleFor(t, handler, "lab-laptop-1", "")

	if nw.TenantID != "tenant_northwind" {
		t.Fatalf("northwind's device was handed the bundle of %q", nw.TenantID)
	}
	if len(nw.InterceptionRootSHA256) != 1 {
		t.Fatalf("northwind is told to look for %v — it should be told about exactly its own root", nw.InterceptionRootSHA256)
	}
	// Both halves. The other organization's fingerprint must be absent AND its own present, or this passes on
	// a bundle that names nothing at all — which is what a device that can never report looks like.
	for _, fp := range lab.InterceptionRootSHA256 {
		if strings.EqualFold(fp, nw.InterceptionRootSHA256[0]) {
			t.Fatal("both organizations are told to look for the same interception root")
		}
	}
	if len(lab.InterceptionRootSHA256) == 0 {
		t.Fatal("the node's own organization is told about no interception root at all")
	}
	// The transport anchors and the serial are the deployment's Edge identity and stay shared — a device that
	// received a different serial per organization could not tell a rotation from a mistake.
	if nw.Serial != lab.Serial || nw.TransportCAPEM != lab.TransportCAPEM {
		t.Fatalf("the transport half diverged: serial %d/%d", nw.Serial, lab.Serial)
	}
}

// ★★ AND THE NODE'S OWN ORGANIZATION WAS EXCLUDED FROM ALL OF THAT (2026-08-18).
//
// interceptionRootFingerprintsForTenant guarded the whole per-tenant branch on "this is not the node's
// organization", so the node's own tenant fell through to the node-wide answer no matter what it held. It has
// never fired because that tenant has never had an issuer of its own — and giving it one is the last step of
// making every tenant's PKI independent of the provider's, which is when it would have fired, silently, on the
// fleet that was working.
//
// With the interception-root pin armed, being announced a root the device does not hold takes every device of
// that organization from satisfied to mismatch at the same moment.
func TestTheNodesOwnOrganizationIsAlsoToldAboutItsOwnRoot(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	// The NODE's own organization acquires an issuer of its own — the state task #31 creates.
	labRoot, labInter, labKey := offlineTenantBundleForTest(t, "Lab Own Root", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_lab_001", labRoot, labInter, labKey); err != nil {
		t.Fatalf("load the node tenant issuer: %v", err)
	}
	nwRoot, nwInter, nwKey := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", nwRoot, nwInter, nwKey); err != nil {
		t.Fatalf("load northwind: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	stamp := now.Format(time.RFC3339)
	if _, err := ledger.Enroll("lab-laptop-1", "tenant_lab_001", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := ledger.Enroll("nw-laptop-1", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	handler := newServerWithConfig(serverConfig{
		Evaluator:              testEvaluator(), // node tenant = tenant_lab_001
		EnrolledLedger:         ledger,
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      testAgentPolicySigner(t),
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      9,
		AdminAuth:              newAdminAuthStore(),
	})

	lab := trustBundleFor(t, handler, "lab-laptop-1", "")
	nw := trustBundleFor(t, handler, "nw-laptop-1", "")

	labWant := fingerprintOfPEMForTest(t, labRoot)
	if len(lab.InterceptionRootSHA256) != 1 || !strings.EqualFold(lab.InterceptionRootSHA256[0], labWant) {
		t.Fatalf("the node's own organization is told to look for %v, not its own root %s — its devices would "+
			"report they do not hold what they were told about, and stay silent about the root actually in use",
			lab.InterceptionRootSHA256, labWant)
	}
	// ★ THE CONTROL: the other organization is unaffected, so this is not "everybody gets the node tenant's
	// root" — which would pass the assertion above and be a worse bug than the one being fixed.
	nwWant := fingerprintOfPEMForTest(t, nwRoot)
	if len(nw.InterceptionRootSHA256) != 1 || !strings.EqualFold(nw.InterceptionRootSHA256[0], nwWant) {
		t.Fatalf("northwind is told to look for %v, want its own %s", nw.InterceptionRootSHA256, nwWant)
	}
}

// A device that cannot prove who it is — the case this endpoint exists for, an expired certificate — may name
// its organization. The contents are public certificates and fingerprints, so serving them to a caller that
// already knows the name costs nothing, and it is the only way that device can be told what to trust.
func TestAnUnauthenticatedCallerMayNameItsOrganization(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	signer := testAgentPolicySigner(t)
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	handler := newServerWithConfig(serverConfig{
		Evaluator:              testEvaluator(),
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      signer,
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      3,
		AdminAuth:              newAdminAuthStore(),
	})

	named := trustBundleFor(t, handler, "", "tenant_northwind")
	if named.TenantID != "tenant_northwind" {
		t.Fatalf("naming the organization returned the bundle of %q", named.TenantID)
	}
	// And no name at all is still the deployment's own answer, which is what every caller received before.
	anonymous := trustBundleFor(t, handler, "", "")
	if anonymous.TenantID != "tenant_lab_001" {
		t.Fatalf("an unnamed caller received %q rather than this deployment's own bundle", anonymous.TenantID)
	}
}

// offlineTenantBundleForTest mints one organization's own interception root and an intermediate under it —
// the out-of-band ceremony a customer's PKI performs. The root key is discarded: the Edge must never hold it.
func offlineTenantBundleForTest(t *testing.T, org string, now time.Time) (rootPEM, interPEM, keyPEM []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Interception Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano() + 1),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Interception Issuing CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(12 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(interKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// ★ WHAT AN AGENT IS INSTALLED WITH (2026-08-16). agentTrustedCABundle is the function main wires into the
// configuration publisher, so this exercises the real thing rather than a stand-in: an organization with its
// own interception issuer must be installed pinned to ITS root, flagged as its own, with the fingerprint an
// operator compares by hand computed once here rather than three times in three places.
//
// Note the deployment fallback is not a defect to remove: an organization with no issuer of its own really is
// served by the node-wide anchor, and installing it is correct. What would be a defect is being unable to
// tell the two apart, which is what interception_root_is_own exists for.
func TestTheAgentConfigCarriesTheOrganizationsOwnAnchor(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}

	own := agentTrustedCABundle(interception, "tenant_northwind", "tenant_lab_001")
	shared := agentTrustedCABundle(interception, "tenant_lab_001", "tenant_lab_001")

	if own["interception_root_is_own"] != true {
		t.Fatalf("northwind's agent would be installed pinned to somebody else's root: %v", own)
	}
	if !strings.Contains(own["interception_root_common_name"].(string), "Northwind") {
		t.Fatalf("pinned to %v", own["interception_root_common_name"])
	}
	if own["interception_root_pem"] != string(rootPEM) {
		t.Fatal("the certificate installed is not the one this organization's traffic is signed under")
	}
	if own["interception_root_sha256"] == "" || own["interception_root_sha256"] == shared["interception_root_sha256"] {
		t.Fatalf("the fingerprint an operator compares is missing or shared: %v", own["interception_root_sha256"])
	}
	// The other organization gets the deployment anchor, SAID to be the deployment's rather than passed off as
	// its own — an installer that could not tell would pin the operator's root into a customer's fleet.
	if shared["interception_root_is_own"] != false {
		t.Fatalf("the deployment's shared anchor was presented as this organization's own: %v", shared)
	}
}

// fingerprintOfPEMForTest is the fingerprint of the first certificate in a PEM block, the same way the bundle
// computes the ones it announces.
func fingerprintOfPEMForTest(t *testing.T, pemBytes []byte) string {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no certificate in the PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return certFingerprint(c)
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func findItem(t *testing.T, inv pkiCertificateInventory, role string) pkiCertificateItem {
	t.Helper()
	for _, it := range inv.Items {
		if it.Role == role {
			return it
		}
	}
	t.Fatalf("no item with role %q in %+v", role, inv.Items)
	return pkiCertificateItem{}
}

// The map must say, for each piece of material, where it is used and what may be done with it — from
// configuration alone, with no live listeners. That is the property the Console renders.
func TestPKICertificateInventoryRelationsAndCapabilities(t *testing.T) {
	transport := testCertPEM(t, "transport-leaf")
	anchorA := testCertPEM(t, "anchor-a")
	anchorB := testCertPEM(t, "anchor-b")
	clientCA := testCertPEM(t, "device-client-ca")

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                  time.Now(),
		TransportCertPEM:     transport,
		TransportListen:      "0.0.0.0:18543",
		RecoveryListen:       "0.0.0.0:18545",
		TransportClientCAPEM: clientCA,
		DeviceIssuingCAPEM:   testCertPEM(t, "device-issuing-ca"),
		TrustBundleCAPEM:     string(anchorA) + string(anchorB),
		TrustBundleSerial:    3,
		DeviceCertCount:      2,
	})

	ts := findItem(t, inv, "transport_server")
	if len(ts.PresentedAt) != 2 {
		t.Fatalf("transport server should be presented at (T) and recovery, got %v", ts.PresentedAt)
	}
	if len(ts.VerifiedBy) != 1 || ts.VerifiedBy[0] != "device_transport_anchors" {
		t.Fatalf("transport server must say devices verify it: %v", ts.VerifiedBy)
	}
	if ts.PEM == "" || strings.Contains(ts.PEM, "PRIVATE") {
		t.Fatalf("transport server carries its public PEM and never key material")
	}
	// Without a reload registration the transport cert is startup-fixed — replace would be a lying button.
	for _, cap := range ts.Capabilities {
		if cap == "replace" {
			t.Fatal("an unregistered transport cert must not offer replace")
		}
	}
	// Registered, it is replaceable — and the item names the registry entry PUT /admin/certs/{name} expects.
	inv2 := buildPKICertificateInventory(pkiCertInventoryInput{
		Now: time.Now(), TransportCertPEM: transport, TransportListen: "0.0.0.0:18543",
		TransportCertName: "transport",
	})
	ts2 := findItem(t, inv2, "transport_server")
	replaceable := false
	for _, cap := range ts2.Capabilities {
		if cap == "replace" {
			replaceable = true
		}
	}
	if !replaceable || ts2.CertName != "transport" {
		t.Fatalf("a registered transport cert is replaceable under its registry name, got %+v", ts2)
	}

	anchors := 0
	for _, it := range inv.Items {
		if it.Role == "transport_anchor" {
			anchors++
			if it.BundleSerial != 3 {
				t.Fatalf("anchor must carry the distributing bundle serial, got %d", it.BundleSerial)
			}
			if it.PEM == "" {
				t.Fatal("an anchor with no PEM cannot be installed anywhere")
			}
		}
	}
	if anchors != 2 {
		t.Fatalf("expected both anchors in the map, got %d", anchors)
	}

	cca := findItem(t, inv, "device_client_ca")
	if len(cca.Verifies) != 1 || cca.Verifies[0] != "device_certificates" {
		t.Fatalf("client CA must say what it verifies: %v", cca.Verifies)
	}

	// No contentless aggregate: the fleet count and the renew-all operation live on the ISSUER card — the
	// certificate the fleet's material comes from — and the per-device rows live on the Devices page.
	for _, it := range inv.Items {
		if it.Role == "device_fleet" {
			t.Fatal("the contentless fleet placeholder must not exist")
		}
	}
	issuer := findItem(t, inv, "device_issuing_ca")
	if issuer.Count != 2 {
		t.Fatalf("the issuer carries the observed-device count, got %d", issuer.Count)
	}
	renewable := false
	for _, c := range issuer.Capabilities {
		if c == "renew_all" {
			renewable = true
		}
	}
	if !renewable {
		t.Fatalf("the fleet-wide renew operation belongs on the issuer, got %v", issuer.Capabilities)
	}
}

// The retire verdict computed for a device client CA must REACH its map item — the operator learns whether a
// CA is safe to retire from the screen, never by attempting the retirement. Regression for the "gate computed
// but the value never appeared live" bug (pki_hierarchy_gap): a verdict keyed by the CA's fingerprint must
// land on the item, in both the blocked and the retirable direction.
func TestPKICertificateInventoryDeviceClientCARetireVerdictReachesItem(t *testing.T) {
	clientCA := testCertPEM(t, "old-device-client-ca")
	certs := parseAllCerts(clientCA)
	if len(certs) != 1 {
		t.Fatalf("expected 1 client CA, got %d", len(certs))
	}
	fp := certFingerprint(certs[0]) // the exact key the builder looks the verdict up by

	blocked := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                  time.Now(),
		TransportClientCAPEM: clientCA,
		DeviceIssuingCAPEM:   testCertPEM(t, "device-issuing-ca"), // distinct, so the client CA is NOT folded in
		DeviceCARetireGate: map[string]gateVerdictResult{
			fp: {OK: false, Code: "still_presented", Text: "still presented by mac-dev-1", Params: []string{"mac-dev-1"}},
		},
	})
	cca := findItem(t, blocked, "device_client_ca")
	if cca.CanRetire {
		t.Fatal("the verdict said not retirable; the item must not claim it can retire")
	}
	if cca.RetireBlockedReason != "still presented by mac-dev-1" || cca.RetireBlockedCode != "still_presented" {
		t.Fatalf("the retire verdict must reach the item, got reason=%q code=%q", cca.RetireBlockedReason, cca.RetireBlockedCode)
	}

	retirable := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                  time.Now(),
		TransportClientCAPEM: clientCA,
		DeviceIssuingCAPEM:   testCertPEM(t, "device-issuing-ca"),
		DeviceCARetireGate:   map[string]gateVerdictResult{fp: {OK: true}},
	})
	if !findItem(t, retirable, "device_client_ca").CanRetire {
		t.Fatal("an OK verdict must surface as CanRetire on the item — this is how the operator sees it is safe")
	}
}

// The working set is decided server-side: a client CA no observed device chains to is inactive; the same
// certificate doing both jobs (verifying and issuing) is ONE row; and during a rotation's overlap, every
// certificate that can still verify the presented chain stays active — the overlap is the point.
func TestPKICertificateInventoryActiveSet(t *testing.T) {
	sharedCA := testCertPEM(t, "Dsse Device CA")
	retiredCA := testCertPEM(t, "Old Device CA")
	anchorInUse := testCertPEM(t, "transport-ca")
	anchorStray := testCertPEM(t, "stray-ca")

	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                     time.Now(),
		TransportCertPEM:        anchorInUse, // self-signed: presented AND its own trust — verifies itself
		TransportClientCAPEM:    append(append([]byte{}, sharedCA...), retiredCA...),
		DeviceIssuingCAPEM:      sharedCA,
		TrustBundleCAPEM:        string(anchorInUse) + string(anchorStray),
		TrustBundleSerial:       2,
		ObservedDeviceIssuerCNs: []string{"Dsse Device CA"},
	})

	var issuing, retired *pkiCertificateItem
	anchorsActive := map[bool]int{}
	for i := range inv.Items {
		it := &inv.Items[i]
		switch it.Role {
		case "device_issuing_ca":
			issuing = it
		case "device_client_ca":
			retired = it
		case "transport_anchor":
			anchorsActive[it.Active]++
		}
	}
	if issuing == nil || len(issuing.Verifies) == 0 {
		t.Fatalf("the dual-role CA must be ONE row that also verifies device certificates: %+v", issuing)
	}
	if !issuing.Active {
		t.Fatal("the issuing CA signs today's certificates — it is active")
	}
	if retired == nil || retired.Active {
		t.Fatalf("a client CA no observed device chains to is residue, got %+v", retired)
	}
	if anchorsActive[true] != 1 || anchorsActive[false] != 1 {
		t.Fatalf("only the certificate that verifies the presented chain is active: %v", anchorsActive)
	}
}

// Material that is not configured contributes no rows — an empty section is visible as absence, never as an
// error that hides the rest of the map.
func TestPKICertificateInventoryAbsencesAreQuiet(t *testing.T) {
	inv := buildPKICertificateInventory(pkiCertInventoryInput{Now: time.Now()})
	if len(inv.Items) != 0 {
		t.Fatalf("nothing configured should yield an empty map, got %+v", inv.Items)
	}
	if inv.SchemaVersion != "admin_pki_certificates.v1" {
		t.Fatalf("schema version missing")
	}
}

// The signer cards carry their contents — name and validity — one per runtime intermediate. A card with no
// visible contents is meaningless (operator, 2026-07-31, twice in one day).
func TestPKICertificateInventorySignersHaveContents(t *testing.T) {
	inv := buildPKICertificateInventory(pkiCertInventoryInput{
		Now:                 time.Now(),
		InterceptionEnabled: true,
		InterceptionRootPEM: testCertPEM(t, "root"),
		IntermediateStatus: map[string]any{
			"mode": "runtime",
			"intermediates": []map[string]any{
				{"cache_tenant": "default", "common_name": "Issuing CA R2",
					"not_before": "2026-07-01T00:00:00Z", "not_after": "2026-10-01T00:00:00Z"},
			},
		},
	})
	signer := findItem(t, inv, "interception_intermediate")
	if signer.Subject != "Issuing CA R2" || signer.NotAfter == "" {
		t.Fatalf("signer must carry name and validity, got %+v", signer)
	}
	if len(signer.Capabilities) != 1 || signer.Capabilities[0] != "rotate_signer" {
		t.Fatalf("runtime signer is rotatable, got %v", signer.Capabilities)
	}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The four properties the handoff demands, verified end to end against real TLS listeners:
//  1. a healthy device does NOTHING (a self-heal that misfires is itself an outage),
//  2. a device whose anchors no longer validate the Edge adopts the signed bundle,
//  3. the same bundle fed twice is refused the second time (replay),
//  4. a bundle signed by an unpinned key changes nothing.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leafUnder issues a server leaf for 127.0.0.1 signed by the CA.
func leafUnder(t *testing.T, ca testCA) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTransportListener runs a minimal TLS listener presenting the given leaf — enough for the probe, which
// only reads the served chain.
func startTransportListener(t *testing.T, leaf tls.Certificate) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leaf}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Drive the handshake so the client gets the chain, then drop the connection.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}(conn)
		}
	}()
	return ln
}

// startBundleServer serves a signed trust-bundle envelope and counts fetches.
func startBundleServer(t *testing.T, envelope agentpolicy.Envelope, fetches *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bootstrap/trust-bundle" {
			http.NotFound(w, r)
			return
		}
		if fetches != nil {
			fetches.Add(1)
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testTransportConfig(t *testing.T, host string, anchors testCA) *transportConfig {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(anchors.cert)
	return &transportConfig{
		enabled:    true,
		host:       host,
		serverName: "127.0.0.1",
		rootCAs:    pool,
		pinnedCAs:  []*x509.Certificate{anchors.cert},
		liveTrust:  &atomic.Pointer[trustMaterial]{},
	}
}

func signedBundle(t *testing.T, signer *agentpolicy.Signer, serial int64, caPEM []byte, recovery string) agentpolicy.Envelope {
	t.Helper()
	env, err := signer.SignTrustBundle("lab", serial, string(caPEM), recovery, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func newTestSigner(t *testing.T) *agentpolicy.Signer {
	t.Helper()
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// 1a. Healthy AND already at the latest serial: the offered bundle does not advance, so nothing is re-adopted.
// This is the no-churn property under the proactive model — a device that is current stays put.
func TestTrustRecoveryHealthyAtLatestSerialDoesNotReadopt(t *testing.T) {
	ca := newTestCA(t, "current-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := testTransportConfig(t, ln.Addr().String(), ca)

	signer := newTestSigner(t)
	srv := startBundleServer(t, signedBundle(t, signer, 1, ca.pem, ""), nil)
	dir := t.TempDir()
	cfg := trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	}
	// First pass adopts serial 1 (the device was on the provisioned CA at serial 0).
	if out := runTrustAnchorRecoveryOnce(tc, cfg); out.code != "adopted_while_healthy" {
		t.Fatalf("first pass = %q (%s), want adopted_while_healthy", out.code, out.detail)
	}
	// Second pass: the same serial is on offer, so it must NOT advance — anchors_valid, no churn.
	if out := runTrustAnchorRecoveryOnce(tc, cfg); out.code != "anchors_valid" {
		t.Fatalf("second pass = %q (%s), want anchors_valid (serial did not advance)", out.code, out.detail)
	}
	if got := lastAcceptedTrustSerial(dir); got != 1 {
		t.Fatalf("serial = %d after a same-serial re-check, want 1 (no re-adopt)", got)
	}
}

// 1b. Healthy but BEHIND: a newer distribution whose anchors still validate the served chain is adopted while
// the device is fine — the routine catch-up that lets a rotation's overlap reach devices that are not broken.
func TestTrustRecoveryHealthyAdoptsNewerDistribution(t *testing.T) {
	ca1 := newTestCA(t, "current-ca")
	ca2 := newTestCA(t, "incoming-ca")
	ln := startTransportListener(t, leafUnder(t, ca1)) // the Edge still serves under ca1
	tc := testTransportConfig(t, ln.Addr().String(), ca1)

	signer := newTestSigner(t)
	// Serial 2 is the OVERLAP set [ca1, ca2]: it adds the incoming CA but keeps the one the Edge serves under,
	// so a device verifying the current chain can adopt it without stranding itself.
	overlap := append(append([]byte{}, ca1.pem...), ca2.pem...)
	srv := startBundleServer(t, signedBundle(t, signer, 2, overlap, ""), nil)
	dir := t.TempDir()
	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "adopted_while_healthy" {
		t.Fatalf("outcome = %q (%s), want adopted_while_healthy", out.code, out.detail)
	}
	if got := lastAcceptedTrustSerial(dir); got != 2 {
		t.Fatalf("serial = %d, want 2 (caught up to the newer distribution)", got)
	}
	// Both CAs are now in force — the device is ready for the Edge to switch to serving under ca2.
	if inForce := tc.currentTrustAnchors(); len(inForce) != 2 {
		t.Fatalf("anchors in force = %d, want 2 (the overlap set)", len(inForce))
	}
}

// 1c. Healthy: a newer distribution whose anchors do NOT validate the served chain is REFUSED — adopting it
// would strand this device, and only the device can tell. It stays on its working anchors.
func TestTrustRecoveryHealthyRefusesStrandingDistribution(t *testing.T) {
	ca1 := newTestCA(t, "current-ca")
	ca2 := newTestCA(t, "unrelated-ca")
	ln := startTransportListener(t, leafUnder(t, ca1)) // the Edge serves under ca1
	tc := testTransportConfig(t, ln.Addr().String(), ca1)

	signer := newTestSigner(t)
	// Serial 2 drops ca1 entirely — a premature retirement. This device would be cut off by it.
	srv := startBundleServer(t, signedBundle(t, signer, 2, ca2.pem, ""), nil)
	dir := t.TempDir()
	out := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if out.code != "refused_would_strand" {
		t.Fatalf("outcome = %q (%s), want refused_would_strand", out.code, out.detail)
	}
	// Nothing adopted; the device is still on ca1 and still verifies the Edge.
	if got := lastAcceptedTrustSerial(dir); got != 0 {
		t.Fatalf("serial = %d, want 0 (the stranding distribution must not be adopted)", got)
	}
	if inForce := tc.currentTrustAnchors(); len(inForce) != 1 || !inForce[0].Equal(ca1.cert) {
		t.Fatal("the device must stay on its working anchor (ca1)")
	}
}

// 2. Broken anchors: the Edge rotated past this device, and the signed bundle heals it — including the live
// swap, so the very next probe validates without a restart.
func TestTrustRecoveryAdoptsBundleAndHeals(t *testing.T) {
	rotatedCA := newTestCA(t, "rotated-ca")
	staleCA := newTestCA(t, "stale-provisioned-ca")
	ln := startTransportListener(t, leafUnder(t, rotatedCA))
	tc := testTransportConfig(t, ln.Addr().String(), staleCA)

	signer := newTestSigner(t)
	srv := startBundleServer(t, signedBundle(t, signer, 1, rotatedCA.pem, ":18545"), nil)

	dir := t.TempDir()
	liveRecovery := &atomic.Pointer[string]{}
	cfg := trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		liveRecovery: liveRecovery,
		client:       unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	}
	outcome := runTrustAnchorRecoveryOnce(tc, cfg)
	if outcome.code != "adopted" {
		t.Fatalf("outcome = %q (%s), want adopted", outcome.code, outcome.detail)
	}
	// The adopted set REPLACES the provisioned one — a union could never withdraw a CA.
	inForce := tc.currentTrustAnchors()
	if len(inForce) != 1 || !inForce[0].Equal(rotatedCA.cert) {
		t.Fatalf("anchors in force after adoption are not exactly the bundle's set")
	}
	// The bundle's port-only recovery endpoint was resolved against the transport host.
	host, _, _ := net.SplitHostPort(tc.host)
	if got, want := *liveRecovery.Load(), net.JoinHostPort(host, "18545"); got != want {
		t.Fatalf("resolved recovery endpoint = %q, want %q", got, want)
	}
	// Healed for real: the next probe validates the same listener with the adopted anchors.
	if next := runTrustAnchorRecoveryOnce(tc, cfg); next.code != "anchors_valid" {
		t.Fatalf("post-adoption outcome = %q (%s), want anchors_valid", next.code, next.detail)
	}
	// And the adoption survives a restart: a rebuilt config prefers the adopted store over the provisioned file.
	provisioned := filepath.Join(dir, "transport_ca.pem")
	if err := os.WriteFile(provisioned, staleCA.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := buildTransportConfig("https://127.0.0.1:18543", provisioned, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cas := rebuilt.currentTrustAnchors(); len(cas) != 1 || !cas[0].Equal(rotatedCA.cert) {
		t.Fatalf("a restart forgot the adopted anchors and fell back to the provisioned file")
	}
}

// 3. Replay: the highest accepted serial persists, so feeding the SAME bundle again is refused — an attacker
// who can serve this device anything cannot walk it back onto a withdrawn CA.
func TestTrustRecoveryRefusesReplayedBundle(t *testing.T) {
	rotatedCA := newTestCA(t, "rotated-ca")
	otherCA := newTestCA(t, "second-rotation-ca")
	staleCA := newTestCA(t, "stale-provisioned-ca")
	// The listener presents a chain the ADOPTED anchors will not validate either, so the second run re-fetches.
	ln := startTransportListener(t, leafUnder(t, otherCA))
	tc := testTransportConfig(t, ln.Addr().String(), staleCA)

	signer := newTestSigner(t)
	replayed := signedBundle(t, signer, 1, rotatedCA.pem, "")
	srv := startBundleServer(t, replayed, nil)

	dir := t.TempDir()
	cfg := trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	}
	if first := runTrustAnchorRecoveryOnce(tc, cfg); first.code != "adopted" {
		t.Fatalf("first feed: outcome = %q (%s), want adopted", first.code, first.detail)
	}
	second := runTrustAnchorRecoveryOnce(tc, cfg)
	if second.code != "unrecovered" {
		t.Fatalf("second feed of the same bundle: outcome = %q, want unrecovered (replay must be refused)", second.code)
	}
	// The serial must survive even losing the anchors file — otherwise deleting one file re-opens the replay.
	if err := os.Remove(filepath.Join(dir, adoptedAnchorsFile)); err != nil {
		t.Fatal(err)
	}
	if got := lastAcceptedTrustSerial(dir); got != 1 {
		t.Fatalf("serial after losing the anchors file = %d, want 1 (replay window re-opened)", got)
	}
	// A bundle that ADVANCES is accepted from the same position.
	srv2 := startBundleServer(t, signedBundle(t, signer, 2, otherCA.pem, ""), nil)
	cfg.bundleURL = srv2.URL
	if third := runTrustAnchorRecoveryOnce(tc, cfg); third.code != "adopted" {
		t.Fatalf("advancing bundle: outcome = %q (%s), want adopted", third.code, third.detail)
	}
}

// 4. A bundle signed by an unpinned key changes nothing, however plausible its contents.
func TestTrustRecoveryIgnoresUnpinnedSignature(t *testing.T) {
	rotatedCA := newTestCA(t, "rotated-ca")
	staleCA := newTestCA(t, "stale-provisioned-ca")
	ln := startTransportListener(t, leafUnder(t, rotatedCA))
	tc := testTransportConfig(t, ln.Addr().String(), staleCA)

	attacker := newTestSigner(t)
	pinned := newTestSigner(t)
	srv := startBundleServer(t, signedBundle(t, attacker, 1, rotatedCA.pem, ""), nil)

	dir := t.TempDir()
	outcome := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: dir, pinHex: pinned.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	})
	if outcome.code != "unrecovered" {
		t.Fatalf("outcome = %q, want unrecovered", outcome.code)
	}
	if cas := tc.currentTrustAnchors(); len(cas) != 1 || !cas[0].Equal(staleCA.cert) {
		t.Fatalf("an unverified bundle changed the anchors in force")
	}
	if _, err := os.Stat(filepath.Join(dir, adoptedPointerFile)); !os.IsNotExist(err) {
		t.Fatalf("an unverified bundle was persisted")
	}
}

// Unreachable is UNDETERMINED, never "stale": nothing is fetched on a network blip.
func TestTrustRecoveryUnreachableIsUndetermined(t *testing.T) {
	ca := newTestCA(t, "current-ca")
	// A listener that is closed immediately: the port is known-dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()
	tc := testTransportConfig(t, deadAddr, ca)

	signer := newTestSigner(t)
	var fetches atomic.Int64
	srv := startBundleServer(t, signedBundle(t, signer, 1, ca.pem, ""), &fetches)

	outcome := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: t.TempDir(), pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(2 * time.Second), timeout: 2 * time.Second,
	})
	if outcome.code != "undetermined" {
		t.Fatalf("outcome = %q (%s), want undetermined", outcome.code, outcome.detail)
	}
	if fetches.Load() != 0 {
		t.Fatalf("an unreachable Edge triggered a bundle fetch")
	}
}

// But holding NO anchors at all is decided WITHOUT asking the network: the device that lost its anchor file
// must not wait for a human just because the probe cannot run.
func TestTrustRecoveryNoAnchorsRecoversWithoutProbe(t *testing.T) {
	rotatedCA := newTestCA(t, "rotated-ca")
	// The transport address is dead — and must not matter.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()
	tc := &transportConfig{enabled: true, host: deadAddr, serverName: "127.0.0.1",
		liveTrust: &atomic.Pointer[trustMaterial]{}}

	signer := newTestSigner(t)
	srv := startBundleServer(t, signedBundle(t, signer, 1, rotatedCA.pem, ""), nil)

	outcome := runTrustAnchorRecoveryOnce(tc, trustRecoveryConfig{
		stateDir: t.TempDir(), pinHex: signer.PublicKeyHex(), bundleURL: srv.URL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 2 * time.Second,
	})
	if outcome.code != "adopted" {
		t.Fatalf("outcome = %q (%s), want adopted (no anchors must not wait on reachability)", outcome.code, outcome.detail)
	}
}

// A pointer whose anchors file is missing means "nothing adopted" — the caller falls back to the provisioned
// anchors — and never an empty set, which would read as "trust nothing" and fail the transport closed forever.
func TestAdoptedStoreMissingAnchorsFallsBack(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(adoptedTrustPointer{Serial: 7, AdoptedAt: "2026-07-30T00:00:00Z"})
	if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := adoptedTrustAnchors(dir); ok {
		t.Fatalf("a pointer with no anchors file yielded an adopted set")
	}
	// The serial still counts — replay protection does not reset with the anchors.
	if got := lastAcceptedTrustSerial(dir); got != 7 {
		t.Fatalf("lastAcceptedTrustSerial = %d, want 7", got)
	}
	// And the provisioned file is what a rebuilt config uses.
	provisionedCA := newTestCA(t, "provisioned-ca")
	provisioned := filepath.Join(dir, "transport_ca.pem")
	if err := os.WriteFile(provisioned, provisionedCA.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	tc, err := buildTransportConfig("https://127.0.0.1:18543", provisioned, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cas := tc.currentTrustAnchors(); len(cas) != 1 || !cas[0].Equal(provisionedCA.cert) {
		t.Fatalf("fallback did not use the provisioned anchors")
	}
}

func TestResolveRecoveryEndpoint(t *testing.T) {
	cases := []struct {
		raw, transport, want string
	}{
		{"18545", "203.0.113.10:18543", "203.0.113.10:18545"},
		{":18545", "203.0.113.10:18543", "203.0.113.10:18545"},
		{"edge.example:9999", "203.0.113.10:18543", "edge.example:9999"},
		{":18545", "[fd00::1]:18543", "[fd00::1]:18545"},
		{"", "203.0.113.10:18543", ""},
		{"not-a-port", "203.0.113.10:18543", ""},
	}
	for _, c := range cases {
		if got := resolveRecoveryEndpoint(c.raw, c.transport); got != c.want {
			t.Errorf("resolveRecoveryEndpoint(%q, %q) = %q, want %q", c.raw, c.transport, got, c.want)
		}
	}
}

// ★★★ THIS TEST USED TO PIN THE DEFECT. It asserted that a transport on :18543 derives a bundle URL on
// :8443 — a SECOND agent-facing port, which the architecture forbids appearing in a device's configuration at
// all, and which no deployment dsse-install generates exposes. It was measured on a real Windows box on
// 2026-08-26: connectex: actively refused, wanted=0, and every HTTPS request gone the moment steering armed
// while the deployment decrypted. The expectation was wrong, so the test was wrong with it.
//
// See TestTheTrustBundleIsFetchedFromTheTransportDoor for the full set.
func TestTrustBundleBaseURL(t *testing.T) {
	if got := trustBundleBaseURL("", "203.0.113.10:18543"); got != "https://203.0.113.10:18543" {
		t.Errorf("derived base URL = %q — the bundle lives on the transport door, not a port of its own", got)
	}
	if got := trustBundleBaseURL("https://edge.example:9443/", "203.0.113.10:18543"); got != "https://edge.example:9443" {
		t.Errorf("explicit base URL = %q", got)
	}
}

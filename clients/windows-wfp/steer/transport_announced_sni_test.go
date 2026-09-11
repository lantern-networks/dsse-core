package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The two names a trust bundle can announce, and the ordering that keeps announcing them safe.
//
// transport_server_name (roadmap D, S3) selects an ORGANIZATION's own transport certificate by SNI, because
// the server must choose before the client certificate arrives. It is both SENT and VERIFIED, so adopting one
// the Edge has no certificate for turns every later dial into a refusal — hence it is proved on the wire first.
//
// renewal_recovery_sni (step 1 of the one-port fold) selects the expired-certificate recovery path on the MAIN port so the
// second address can be retired. It is announced BEFORE anything serves it, so it is SENT ONLY: the served
// chain is still verified against the name this device has always verified.

// leafWithNames issues a server leaf carrying the given DNS names (and 127.0.0.1), signed by the CA.
func leafWithNames(t *testing.T, ca testCA, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// announcingTransport is testTransportConfig plus the holders the announced names live in.
func announcingTransport(t *testing.T, host string, anchors testCA) *transportConfig {
	t.Helper()
	tc := testTransportConfig(t, host, anchors)
	tc.announcedServerName = &atomic.Pointer[string]{}
	tc.announcedRecoverySNI = &atomic.Pointer[string]{}
	return tc
}

func bundleAnnouncing(t *testing.T, signer *agentpolicy.Signer, serial int64, caPEM []byte,
	transportName, recoverySNI string) agentpolicy.Envelope {
	t.Helper()
	env, err := signer.SignTrustBundlePayload(agentpolicy.TrustBundlePayload{
		SchemaVersion:       agentpolicy.TrustBundleSchema,
		TenantID:            "lab",
		Serial:              serial,
		TransportCAPEM:      string(caPEM),
		TransportServerName: transportName,
		RenewalRecoverySNI:  recoverySNI,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func recoveryConfigFor(t *testing.T, dir string, signer *agentpolicy.Signer, bundleURL string) trustRecoveryConfig {
	t.Helper()
	return trustRecoveryConfig{
		stateDir: dir, pinHex: signer.PublicKeyHex(), bundleURL: bundleURL,
		client: unverifiedChannelClient(5 * time.Second), timeout: 5 * time.Second,
	}
}

// An announced transport name the Edge actually serves is adopted, persisted, and sent from then on.
func TestAnnouncedTransportNameIsAdoptedOnceItIsProvedOnTheWire(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafWithNames(t, ca, "northwind.dsse.invalid"))
	tc := announcingTransport(t, ln.Addr().String(), ca)

	signer := newTestSigner(t)
	srv := startBundleServer(t, bundleAnnouncing(t, signer, 1, ca.pem, "northwind.dsse.invalid", ""), nil)
	dir := t.TempDir()

	out := runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))
	if out.code != "adopted_while_healthy" && out.code != "" {
		t.Fatalf("adoption = %q (%s)", out.code, out.detail)
	}
	if got := tc.activeServerName(); got != "northwind.dsse.invalid" {
		t.Fatalf("activeServerName = %q, want the announced name", got)
	}
	if got := adoptedTransportServerName(dir); got != "northwind.dsse.invalid" {
		t.Fatalf("persisted transport_server_name = %q, want the announced name", got)
	}
}

// ★ The property that keeps the announcement from being a lockout: a name nothing serves is REFUSED, the
// device keeps the name it has, and it says so. The Edge is then free to be ahead without either side breaking.
func TestAnnouncedTransportNameIsRefusedWhenNothingServesIt(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafUnder(t, ca)) // 127.0.0.1 only — no organization name in the SAN
	tc := announcingTransport(t, ln.Addr().String(), ca)

	signer := newTestSigner(t)
	srv := startBundleServer(t, bundleAnnouncing(t, signer, 1, ca.pem, "northwind.dsse.invalid", ""), nil)
	dir := t.TempDir()

	out := runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))
	if got := tc.activeServerName(); got != "127.0.0.1" {
		t.Fatalf("activeServerName = %q, want the working name kept", got)
	}
	if got := adoptedTransportServerName(dir); got != "" {
		t.Fatalf("persisted transport_server_name = %q, want nothing (it was never proved)", got)
	}
	// The anchors themselves still adopt: the refusal is scoped to the name, not to the distribution.
	if got := lastAcceptedTrustSerial(dir); got != 1 {
		t.Fatalf("serial = %d, want 1 — the anchors adopt even when the name does not", got)
	}
	if !strings.Contains(out.detail, "transport_server_name=refused") {
		t.Fatalf("outcome detail = %q, want it to name the refusal", out.detail)
	}
}

// A deployment that STOPS announcing a name means "the shared certificate again". Keeping the old name would
// leave the device asking for a certificate that has been withdrawn from service.
func TestAnnouncedTransportNameIsClearedWhenTheAnnouncementStops(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafWithNames(t, ca, "northwind.dsse.invalid"))
	tc := announcingTransport(t, ln.Addr().String(), ca)
	signer := newTestSigner(t)
	dir := t.TempDir()

	srv1 := startBundleServer(t, bundleAnnouncing(t, signer, 1, ca.pem, "northwind.dsse.invalid", ""), nil)
	runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv1.URL))
	if tc.activeServerName() != "northwind.dsse.invalid" {
		t.Fatalf("precondition: the name was not adopted")
	}

	srv2 := startBundleServer(t, bundleAnnouncing(t, signer, 2, ca.pem, "", ""), nil)
	runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv2.URL))
	if got := tc.activeServerName(); got != "127.0.0.1" {
		t.Fatalf("activeServerName = %q, want the provisioned name back", got)
	}
	if got := adoptedTransportServerName(dir); got != "" {
		t.Fatalf("persisted transport_server_name = %q, want it cleared", got)
	}
}

// ★ The recovery SNI is SENT and NOT verified, which is what makes announcing it before anything serves it
// harmless. The listener here has no certificate for the recovery name at all: the handshake must still
// succeed, because verification is against the name this device has always verified.
func TestRecoverySNIIsSentWithoutBecomingTheVerifiedName(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafUnder(t, ca)) // 127.0.0.1 only
	tc := announcingTransport(t, ln.Addr().String(), ca)
	tc.setAnnouncedNames("", "recovery.dsse.invalid")

	recovery := recoveryTransport(tc, ln.Addr().String())
	if got := recovery.tlsConfig().ServerName; got != "recovery.dsse.invalid" {
		t.Fatalf("ClientHello SNI = %q, want the announced recovery name", got)
	}
	if got := recovery.activeServerName(); got != "127.0.0.1" {
		t.Fatalf("verified name = %q, want the name this device has always verified", got)
	}
	conn, err := recovery.dial(5 * time.Second)
	if err != nil {
		t.Fatalf("recovery dial failed: %v — sending the name must not change what is verified", err)
	}
	conn.Close()
}

// With no recovery name announced, the recovery dial is byte-for-byte what it was before.
func TestRecoveryDialIsUnchangedWithoutAnAnnouncedName(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := announcingTransport(t, ln.Addr().String(), ca)

	recovery := recoveryTransport(tc, ln.Addr().String())
	if got := recovery.tlsConfig().ServerName; got != "127.0.0.1" {
		t.Fatalf("ClientHello SNI = %q, want the unchanged name", got)
	}
}

// ★ Region failover outranks the announced name, and the reason is a lockout: a region that has no
// certificate for this organization serves the shared one, and a device verifying THAT against the
// organization's name would refuse the region it just failed over to.
func TestRegionFailoverNameOutranksTheAnnouncedName(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "127.0.0.1:1", ca)
	tc.setAnnouncedNames("northwind.dsse.invalid", "")
	if got := tc.activeServerName(); got != "northwind.dsse.invalid" {
		t.Fatalf("precondition: announced name not in force (%q)", got)
	}
	tc.active = &atomic.Pointer[activeEndpoint]{}
	tc.active.Store(&activeEndpoint{host: "10.0.0.1:18543", serverName: "edge-region-b.example"})
	if got := tc.activeServerName(); got != "edge-region-b.example" {
		t.Fatalf("activeServerName = %q, want the region's own name", got)
	}
}

// The recovery SNI is persisted UNPROVED and restored across a restart — the device that needs it is by
// definition one that was switched off.
func TestRecoverySNISurvivesARestart(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafUnder(t, ca))
	tc := announcingTransport(t, ln.Addr().String(), ca)
	signer := newTestSigner(t)
	dir := t.TempDir()

	srv := startBundleServer(t, bundleAnnouncing(t, signer, 1, ca.pem, "", "recovery.dsse.invalid"), nil)
	runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))

	if got := adoptedRecoverySNI(dir); got != "recovery.dsse.invalid" {
		t.Fatalf("persisted renewal_recovery_sni = %q, want the announced name", got)
	}
	// A fresh process reads the pointer and puts the name back in force without waiting for a bundle.
	restarted := announcingTransport(t, ln.Addr().String(), ca)
	restarted.setAnnouncedNames(adoptedTransportServerName(dir), adoptedRecoverySNI(dir))
	if got := restarted.currentRecoverySNI(); got != "recovery.dsse.invalid" {
		t.Fatalf("after restart the recovery SNI = %q, want it restored", got)
	}
}

// The Edge cannot gate a switch on the adopted SERIAL alone: an older agent adopts the bundle and ignores the
// field while reporting a current serial. The report therefore carries what this agent would actually SEND.
func TestReportCarriesTheNamesThisAgentWouldSend(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "127.0.0.1:1", ca)
	tc.setAnnouncedNames("northwind.dsse.invalid", "recovery.dsse.invalid")

	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, localBaseline: []string{"example-app"},
		apply: func([]string) {},
		sentServerNames: func() (string, string) {
			return tc.activeServerName(), tc.currentRecoverySNI()
		},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if got := body["transport_server_name_sent"]; got != "northwind.dsse.invalid" {
		t.Fatalf("transport_server_name_sent = %v, want the name in force", got)
	}
	if got := body["renewal_recovery_sni_sent"]; got != "recovery.dsse.invalid" {
		t.Fatalf("renewal_recovery_sni_sent = %v, want the announced recovery name", got)
	}
}

// An agent that has adopted nothing reports NOTHING for these two, so the Edge reads UNKNOWN rather than
// "sends nothing" — the two lead to opposite decisions about retiring a port.
func TestReportOmitsTheNamesWhenThereAreNone(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, localBaseline: []string{"example-app"},
		apply: func([]string) {},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	if _, present := body["transport_server_name_sent"]; present {
		t.Fatalf("transport_server_name_sent present on an agent that has none")
	}
	if _, present := body["renewal_recovery_sni_sent"]; present {
		t.Fatalf("renewal_recovery_sni_sent present on an agent that has none")
	}
}

// ★ A refusal must be a DELAY, not a verdict. The proof is one probe; if it fails while the Edge is briefly
// unreachable, the name has to be retried — the bundle fetch refuses a serial that does not advance, so on a
// deployment that is not rotating there would otherwise never be another chance.
func TestARefusedNameIsRetriedOnTheNextTick(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	// Round one: the Edge serves NOTHING under the organization's name, so the proof fails.
	ln1 := startTransportListener(t, leafUnder(t, ca))
	tc := announcingTransport(t, ln1.Addr().String(), ca)
	signer := newTestSigner(t)
	dir := t.TempDir()

	srv := startBundleServer(t, bundleAnnouncing(t, signer, 1, ca.pem, "northwind.dsse.invalid", ""), nil)
	runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))
	if got := adoptedTransportServerName(dir); got != "" {
		t.Fatalf("precondition: the name was adopted unproved (%q)", got)
	}

	// Round two: the same serial — the fetch will refuse it — but now the Edge does serve the name. The retry
	// on the healthy path is the only thing that can promote it, and it must.
	ln2 := startTransportListener(t, leafWithNames(t, ca, "northwind.dsse.invalid"))
	tc.host = ln2.Addr().String()
	out := runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))
	if got := tc.activeServerName(); got != "northwind.dsse.invalid" {
		t.Fatalf("activeServerName = %q after the retry, want the announced name (%s)", got, out.detail)
	}
	if got := adoptedTransportServerName(dir); got != "northwind.dsse.invalid" {
		t.Fatalf("persisted transport_server_name = %q after the retry, want the announced name", got)
	}
	if got := lastAcceptedTrustSerial(dir); got != 1 {
		t.Fatalf("serial = %d — the retry must not disturb the adopted distribution", got)
	}
}

// ★ An agent is upgraded AFTER a bundle is adopted, not before. A device whose pointer was written by an
// agent that did not know these fields has no record of what was announced, and the ordinary fetch refuses a
// serial that does not advance — so without re-reading the CURRENT distribution the new agent would wait for
// a rotation that may never come. Every device in a fleet passes through this state once, at upgrade.
func TestAnUpgradedAgentLearnsTheNameAnnouncedBeforeItWasInstalled(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	ln := startTransportListener(t, leafWithNames(t, ca, "lab.dsse.invalid"))
	signer := newTestSigner(t)
	dir := t.TempDir()
	srv := startBundleServer(t, bundleAnnouncing(t, signer, 7, ca.pem, "lab.dsse.invalid", "recovery.dsse.invalid"), nil)

	// The state an OLD agent leaves behind: adopted at the current serial, with neither name recorded.
	old := announcingTransport(t, ln.Addr().String(), ca)
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 7, TransportCAPEM: string(ca.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	_ = old
	if adoptedTransportServerName(dir) != "" || adoptedRecoverySNI(dir) != "" {
		t.Fatalf("precondition: the old agent's pointer already carries a name")
	}

	// The NEW agent starts on that state. One healthy tick must be enough.
	tc := announcingTransport(t, ln.Addr().String(), ca)
	tc.setAnnouncedNames(adoptedTransportServerName(dir), adoptedRecoverySNI(dir))
	runTrustAnchorRecoveryOnce(tc, recoveryConfigFor(t, dir, signer, srv.URL))

	if got := tc.activeServerName(); got != "lab.dsse.invalid" {
		t.Fatalf("activeServerName = %q, want the name announced before this agent existed", got)
	}
	if got := adoptedRecoverySNI(dir); got != "recovery.dsse.invalid" {
		t.Fatalf("persisted renewal_recovery_sni = %q, want it picked up at the same time", got)
	}
	if got := lastAcceptedTrustSerial(dir); got != 7 {
		t.Fatalf("serial = %d — re-reading the announcement must not re-adopt anything", got)
	}
}

// ★ Once the deployment folds recovery onto the transport port it stops announcing an endpoint at all, and
// closes the dedicated one. A device that reports the recovery name but still dials the closed port has told
// the fleet it is ready for a fold it cannot follow — and the devices that discover that are the ones already
// locked out.
func TestRecoveryFollowsTheAnnouncedNameToTheTransportPort(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)
	tc.setAnnouncedNames("", "recovery.dsse.invalid")

	// No endpoint at all — the deployment withdrew it when it closed the port.
	dial, where, ok := recoveryDial(tc, "")
	if !ok {
		t.Fatalf("recoveryDial refused with a name announced; a recovering device would have nowhere to go")
	}
	if dial.dialTarget() != "10.0.0.9:18543" {
		t.Fatalf("recovery dial target = %q, want the transport address", dial.dialTarget())
	}
	if got := dial.tlsConfig().ServerName; got != "recovery.dsse.invalid" {
		t.Fatalf("recovery ClientHello SNI = %q, want the announced name (that is what selects the path)", got)
	}
	if !strings.Contains(where, "recovery.dsse.invalid") {
		t.Fatalf("the log destination %q does not name where it went", where)
	}
}

// With no name announced, recovery is byte-for-byte the separate-port dial it always was.
func TestRecoveryFallsBackToTheEndpointWhenNoNameIsAnnounced(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)

	dial, where, ok := recoveryDial(tc, "10.0.0.9:18545")
	if !ok || where != "10.0.0.9:18545" {
		t.Fatalf("recoveryDial = (%v, %q), want the configured endpoint", ok, where)
	}
	if dial.dialTarget() != "10.0.0.9:18545" {
		t.Fatalf("recovery dial target = %q, want the recovery endpoint", dial.dialTarget())
	}
}

// Neither one: the device says it cannot get back on its own, which is the only honest answer.
func TestRecoveryReportsHavingNowhereToGo(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)
	if _, _, ok := recoveryDial(tc, ""); ok {
		t.Fatalf("recoveryDial claimed a destination with neither an endpoint nor a name")
	}
}

// ★ The gate that closed the dedicated recovery listener read "reports the name" as "can reach the folded
// path". This agent reported the name and still dialled the endpoint being retired, so the report now carries
// the address recovery would ACTUALLY use, resolved by the same function recovery uses.
func TestReportCarriesWhereRecoveryWouldActuallyGo(t *testing.T) {
	var reportFails atomic.Bool
	var cap capturedReport
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "10.0.0.9:18543", ca)
	tc.setAnnouncedNames("", "recovery.dsse.invalid")

	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, localBaseline: []string{"example-app"},
		apply: func([]string) {},
		renewalRecoveryTarget: func() string {
			dial, _, ok := recoveryDial(tc, "10.0.0.9:18545")
			if !ok {
				return ""
			}
			return dial.dialTarget()
		},
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	// The announced name wins over the configured endpoint, so the reported target is the TRANSPORT port —
	// which is the fact the gate needs, and the opposite of what the name alone would have implied.
	if got := body["renewal_recovery_target"]; got != "10.0.0.9:18543" {
		t.Fatalf("renewal_recovery_target = %v, want the transport address recovery would dial", got)
	}
}

// ★ THE CONTRACT IS "host:port|sni", NOT "host:port" (2026-08-20, found by the Edge classifying this device
// as "does NOT hold" while it was in fact correct). Both halves are needed to express the accident the gate
// exists to catch: a device that holds the recovery name and still dials the retired dedicated port. The
// address alone cannot say which name it would send, and the name alone cannot say where it would go.
func TestTheReportedRecoveryTargetCarriesBothHalves(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "100.72.135.18:18543", ca)
	tc.setAnnouncedNames("", "recovery.dsse.invalid")

	dial, _, ok := recoveryDial(tc, "")
	if !ok {
		t.Fatalf("recoveryDial refused with a name announced")
	}
	target := dial.dialTarget()
	if sni := strings.TrimSpace(dial.sendSNI); sni != "" {
		target += "|" + sni
	}
	if target != "100.72.135.18:18543|recovery.dsse.invalid" {
		t.Fatalf("reported target = %q, want host:port|sni", target)
	}
}

// With no recovery name announced there is no second half, and the field stays the bare address - the same
// string the macOS agent produces in that case.
func TestTheReportedRecoveryTargetIsBareWithoutAName(t *testing.T) {
	ca := newTestCA(t, "shared-ca")
	tc := announcingTransport(t, "100.72.135.18:18543", ca)

	dial, _, ok := recoveryDial(tc, "100.72.135.18:18545")
	if !ok {
		t.Fatalf("recoveryDial refused with an endpoint configured")
	}
	target := dial.dialTarget()
	if sni := strings.TrimSpace(dial.sendSNI); sni != "" {
		target += "|" + sni
	}
	if target != "100.72.135.18:18545" {
		t.Fatalf("reported target = %q, want the bare endpoint", target)
	}
}

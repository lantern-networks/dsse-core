//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"

	"github.com/lantern-networks/dsse-core/installprofile"
	"time"
)

// transport_trust_anchors_test.go — what an enrolled device verifies the EDGE against, and what it must never
// accept instead.
//
// ★ TWO WAYS TO GET THIS WRONG, AND THE PREVIOUS ROUND FOUND BOTH (2026-08-12, seventeenth review). Widening
// the set — pin UNION adopted — makes a withdrawal impossible: a CA revoked for being compromised stays
// trusted, and the device reports the new anchors while still accepting the old. Substituting a different
// trust domain when there is nothing — the enrolled device-issuing CA — grants server authority to a CA whose
// job is signing CLIENT certificates.

func writePin(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "transport-ca.pem")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A device with only the provisioned pin verifies against it, at serial 0.
func TestWithNothingAdoptedTheProvisionedPinIsTheAnchorSet(t *testing.T) {
	ca := newTestCA(t, "Lantern DSSE Transport CA (test)")
	pin := writePin(t, t.TempDir(), string(ca.pem))

	pool, pinned, serial, source, err := transportTrustAnchors(pin, nil)

	if err != nil {
		t.Fatal(err)
	}
	if pool == nil || len(pinned) == 0 {
		t.Fatalf("the provisioned pin produced no anchors (%d parsed)", len(pinned))
	}
	if serial != 0 {
		t.Fatalf("serial %d for a device that has adopted nothing", serial)
	}
	if !strings.Contains(source, "provisioned") {
		t.Fatalf("the source was not named for the operator: %q", source)
	}
}

// ★ THE ONE THAT MAKES WITHDRAWAL POSSIBLE. With nothing usable to read, the answer is an error the caller
// must decide about — never a set assembled from somewhere else.
func TestAnUnreadablePinIsAnErrorRatherThanASubstitute(t *testing.T) {
	_, pinned, serial, _, err := transportTrustAnchors(filepath.Join(t.TempDir(), "absent.pem"), nil)

	if err == nil {
		t.Fatal("a device with no readable transport pin was handed an anchor set anyway; the caller can no " +
			"longer tell that it has nothing to verify the Edge with")
	}
	if len(pinned) != 0 || serial != 0 {
		t.Fatalf("an error path still produced anchors (%d, serial %d)", len(pinned), serial)
	}
}

// An empty pool is a usable transport that accepts nothing — the honest expression of "I cannot verify the
// Edge", and what the enrolled path falls back to instead of the device-issuing CA.
func TestATransportWithAnEmptyRootSetStillBuildsAndVerifiesNothing(t *testing.T) {
	tc, err := buildTransportConfigFromAnchors("https://203.0.113.10:18543", nil, nil, 0, "", nil, nil)
	if err != nil {
		t.Fatalf("a transport with no anchors refused to build (%v) — the service would not start, which takes "+
			"the box off the network as surely as a wrong root does", err)
	}
	if !tc.enabled {
		t.Fatal("the transport is not enabled")
	}
	// ★ NOT tlsConfig().RootCAs — this transport never sets it (2026-08-12, Windows). Verification happens in
	// VerifyConnection, with InsecureSkipVerify turning off only the stdlib's own check so the SAME pin can be
	// run where the served chain is visible; the pool lives in the closure. So RootCAs is nil here on every
	// platform and asserting on it fails everywhere, which is what the local gate reported.
	//
	// The property being pinned is real and unchanged, so it is asserted through the mechanism that provides
	// it: an empty pool must REFUSE, and a nil one must never reach x509.Verify, where nil Roots means the
	// SYSTEM roots — the fail-open this whole branch exists to avoid.
	if tc.rootCAs == nil {
		t.Fatal("a nil root pool would reach x509.Verify as nil Roots, which falls back to the SYSTEM roots")
	}
	if len(tc.rootCAs.Subjects()) != 0 { //nolint:staticcheck // Subjects is the only way to assert emptiness
		t.Fatal("the root set is not empty, so something was substituted for the anchors this device lacks")
	}
	cfg := tc.tlsConfig()
	if cfg.VerifyConnection == nil {
		t.Fatal("no VerifyConnection: with InsecureSkipVerify set, nothing would check the Edge at all")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{selfSignedLeaf(t)},
	}); err == nil {
		t.Fatal("a transport with an empty root set ACCEPTED a certificate; the fallback is fail-open")
	}
}

// selfSignedLeaf is something for the empty pool to refuse. Generated rather than a literal, so the refusal is
// about the ROOTS being empty and not about the bytes being unparseable.
func selfSignedLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "203.0.113.10"},
		DNSNames:     []string{"203.0.113.10"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// ★ A DEVICE THAT HAS ROTATED DOES NOT NEED THE FILE IT WAS BORN WITH (2026-08-12, eighteenth review). The
// first version of this selection read the provisioned pin and returned its error BEFORE looking at the
// adopted store — so on the day somebody removed or truncated that file, a restart took the box off the
// network entirely while a perfectly good adopted bundle sat in the same directory. The order is the fix, and
// it is the order the rule already implied: adopted supersedes provisioned, so adopted is consulted first.
func TestAMissingPinDoesNotHideTheAdoptedAnchors(t *testing.T) {
	dir := t.TempDir()
	adopted := newTestCA(t, "Lantern DSSE Transport CA v2 (adopted)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 3, TransportCAPEM: string(adopted.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	// The provisioned file is GONE — retired after the rotation, or removed by hand.
	pinPath := filepath.Join(dir, "transport-ca.pem")

	pool, pinned, serial, source, err := transportTrustAnchors(pinPath, nil)

	if err != nil {
		t.Fatalf("a device holding an adopted bundle at serial 3 refused to build an anchor set because the "+
			"superseded pin file was missing (%v). That box is off the network, and the anchors it actually "+
			"uses were in the same directory.", err)
	}
	if pool == nil || len(pinned) != 1 || !pinned[0].Equal(adopted.cert) {
		t.Fatalf("the anchor set is not the adopted one (%d anchors)", len(pinned))
	}
	if serial != 3 {
		t.Fatalf("serial %d — the adopted serial must come with the anchors, or a restart reports 0 and "+
			"nothing re-adopts", serial)
	}
	if !strings.Contains(source, "SUPERSEDE") {
		t.Fatalf("the source does not say the adopted set superseded the pin: %q", source)
	}
}

// And a corrupt pin is the same case: unusable is not different from absent when the device has moved on.
func TestACorruptPinDoesNotHideTheAdoptedAnchors(t *testing.T) {
	dir := t.TempDir()
	adopted := newTestCA(t, "Lantern DSSE Transport CA v2 (adopted)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 4, TransportCAPEM: string(adopted.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	pin := writePin(t, dir, "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")

	_, pinned, serial, _, err := transportTrustAnchors(pin, nil)

	if err != nil {
		t.Fatalf("a truncated pin file stopped a device that had adopted past it: %v", err)
	}
	if len(pinned) != 1 || serial != 4 {
		t.Fatalf("got %d anchors at serial %d, want the adopted one at 4", len(pinned), serial)
	}
}

// ★ A ROTATION MUST NOT COST THE FIRST CONNECTION AFTER IT (2026-08-12, eighteenth review). A resumed TLS
// session restores the peer certificate cached with its ticket, and VerifyConnection runs on resumption — so
// with a stale cache the first dial after a withdrawal verifies the OLD certificate against the NEW roots and
// fails. setClientCert has flushed for the mirror-image reason since it was written; replacing the ROOTS did
// not.
func TestReplacingTheTrustAnchorsDropsTheSessionCache(t *testing.T) {
	ca := newTestCA(t, "Lantern DSSE Transport CA (test)")
	pin := writePin(t, t.TempDir(), string(ca.pem))
	pool, pinned, serial, _, err := transportTrustAnchors(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := buildTransportConfigFromAnchors("https://203.0.113.10:18543", pool, pinned, serial, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := tc.currentSessionCache()
	if before == nil {
		t.Fatal("the transport has no session cache to flush")
	}

	next := newTestCA(t, "Lantern DSSE Transport CA v2 (test)")
	tc.setTrustAnchors(next.pem, 5)

	if tc.currentSessionCache() == before {
		t.Fatal("the session cache survived a trust-anchor replacement: the next dial can resume a session " +
			"whose cached peer certificate was issued by the CA that was just withdrawn, and VerifyConnection " +
			"runs on resumption — so the first connection after the rotation fails")
	}
	if tc.currentTrustSerial() != 5 {
		t.Fatalf("the new anchors did not take effect (serial %d)", tc.currentTrustSerial())
	}
}

// ★ NO DIAL MAY OBSERVE THE NEW CACHE WITH THE OLD ROOTS (2026-08-12, nineteenth review). That pairing is the
// one that outlives the swap: a handshake completed against the withdrawn CA is SAVED into the cache
// everything afterwards uses, so the failure survives the function that was supposed to end it. The reverse
// pairing — new roots, old cache — costs at most one resumed session, which fails and is discarded.
//
// The sequential test above only proves the cache pointer changed; this one runs dials across the swap.
func TestNoDialSeesTheNewCacheWithTheWithdrawnRoots(t *testing.T) {
	ca := newTestCA(t, "Lantern DSSE Transport CA (test)")
	pin := writePin(t, t.TempDir(), string(ca.pem))
	pool, pinned, serial, _, err := transportTrustAnchors(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := newTestCA(t, "Lantern DSSE Transport CA v2 (test)")

	for attempt := 0; attempt < 500; attempt++ {
		tc, berr := buildTransportConfigFromAnchors("https://203.0.113.10:18543", pool, pinned, serial, "", nil, nil)
		if berr != nil {
			t.Fatal(berr)
		}
		firstCache, withdrawnPool := tc.trustSnapshot()

		var wg sync.WaitGroup
		bad := make(chan string, 8)
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// ★ THROUGH THE SAME HELPER THE PRODUCT USES (2026-08-12, twentieth review). The first version
				// of this test read the cache and then the anchors while tlsConfig read the roots and THEN the
				// cache — so it exercised an interleaving the product never performs and passed while the
				// pairing that matters stayed reachable. A concurrency test whose read order differs from the
				// code's is testing a different program.
				cache, roots := tc.trustSnapshot()
				if cache != firstCache && roots != nil && roots.Equal(withdrawnPool) {
					bad <- "a dial had the replacement cache and the WITHDRAWN roots"
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; tc.setTrustAnchors(next.pem, 9) }()
		close(start)
		wg.Wait()
		close(bad)
		if msg := <-bad; msg != "" {
			t.Fatalf("attempt %d: %s — that handshake completes against the CA just withdrawn and its session "+
				"is saved into the cache everything uses afterwards, so the failure outlives the swap", attempt, msg)
		}
	}
}

// ★★★ AN ADOPTED SET THAT DOES NOT COVER THE PROFILE'S DOORS DOES NOT SUPERSEDE (2026-08-29, win-dev-1 against
// the hikari.lab two-site deployment).
//
// Measured: a brand-new device of one organization fetched its trust bundle without naming an organization —
// the only name it has before adopting anything comes from the profile, and the fetch did not use it — so the
// Edge answered with the DEPLOYMENT's own organization. The device adopted those anchors, they superseded the
// correct provisioned ones, and from then on every dial to its own door failed. The log line said ADOPTED.
//
// The rule this asserts: supersession is conditional on the adopted set still verifying the doors the CURRENT
// signed profile names. Coverage holds -> supersede, unchanged. Coverage does not hold -> both sets are in
// force and the source says so, because a device that cannot reach its own organization is worse than a device
// carrying one anchor longer than a rotation intended.
func TestAnAdoptedSetThatDropsTheProfilesOwnAuthorityDoesNotSupersedeIt(t *testing.T) {
	dir := t.TempDir()
	deploymentRoot := newTestCA(t, "Hikari Networks Root CA (test)")
	orgCA := newTestCA(t, "acme.example Transport CA (test)")
	strangerCA := newTestCA(t, "Some Other Organization Transport CA (test)")

	// What the profile provisioned: the deployment root AND this organization's own transport CA.
	provisioned := append(append([]byte{}, deploymentRoot.pem...), orgCA.pem...)
	pin := writePin(t, dir, string(provisioned))
	required := installprofile.Fingerprints([]*x509.Certificate{deploymentRoot.cert, orgCA.cert})

	// What arrived: another organization's distribution, which carries neither of them.
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 3, TransportCAPEM: string(strangerCA.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}

	pool, pinned, serial, source, err := transportTrustAnchors(pin, required)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("no pool")
	}
	if serial != 3 {
		t.Fatalf("serial %d — the adopted serial must still be reported, or nothing re-adopts", serial)
	}
	have := installprofile.Fingerprints(pinned)
	if missing := installprofile.MissingAnchors(have, required); len(missing) != 0 {
		t.Fatalf("the anchor set still drops %v — this device cannot verify its own organization's door, "+
			"which is the defect measured on win-dev-1", missing)
	}
	if len(installprofile.MissingAnchors(have, installprofile.Fingerprints([]*x509.Certificate{strangerCA.cert}))) != 0 {
		t.Fatal("the adopted anchor was discarded — coverage must ADD the provisioned set, not replace the adopted one")
	}
	if strings.Contains(source, "SUPERSEDE") || !strings.Contains(source, "does not carry") {
		t.Fatalf("the source must say the adopted set did not cover what the profile names, got %q", source)
	}
}

// And the ordinary rotation is untouched: an adopted set that DOES carry what the profile names supersedes it,
// which is what makes retiring a compromised authority possible at all.
func TestARotationThatKeepsTheProfilesAuthoritiesStillSupersedes(t *testing.T) {
	dir := t.TempDir()
	orgCA := newTestCA(t, "acme.example Transport CA (test)")
	retired := newTestCA(t, "Retired Transport CA (test)")

	// The device was born with a retired authority beside the one the profile still names.
	pin := writePin(t, dir, string(append(append([]byte{}, retired.pem...), orgCA.pem...)))
	required := installprofile.Fingerprints([]*x509.Certificate{orgCA.cert})

	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 9, TransportCAPEM: string(orgCA.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}

	_, pinned, serial, source, err := transportTrustAnchors(pin, required)
	if err != nil {
		t.Fatal(err)
	}
	if serial != 9 || len(pinned) != 1 || !pinned[0].Equal(orgCA.cert) {
		t.Fatalf("got %d anchors at serial %d — a covering distribution must still supersede, or the retired "+
			"authority stays trusted for ever", len(pinned), serial)
	}
	if !strings.Contains(source, "SUPERSEDE") {
		t.Fatalf("source %q — the ordinary rotation must read the same as it always did", source)
	}
}

// ★★★ A SERIAL FROM ANOTHER ORGANIZATION DOES NOT GATE THIS ONE'S (2026-08-29, win-dev-1). Serials are
// per-organization. This box held tenant_default at serial 3 while its own organization published serial 3, so
// "does it advance" answered no to the correct distribution and the device could never leave the stranger's
// authority. Replay protection compares against a PREDECESSOR; a stranger is not one.
func TestAStrangersSerialDoesNotGateThisOrganizationsDistribution(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Some Other Organization Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 3, TenantID: "tenant_default", TransportCAPEM: string(ca.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := trustSerialFloor(dir, "tenant_sakura"); got != 0 {
		t.Fatalf("floor = %d for a distribution belonging to another organization — the correct one at the same "+
			"serial can never be adopted", got)
	}
	if got := trustSerialFloor(dir, "tenant_default"); got != 3 {
		t.Fatalf("floor = %d for this device's OWN previous distribution — replay protection must be unchanged", got)
	}
	if got := trustSerialFloor(dir, "TENANT_DEFAULT"); got != 3 {
		t.Fatalf("floor = %d — the organization id is an identifier, not a case-sensitive secret", got)
	}
}

// A pointer written before the field existed names nobody. It must NOT be silently discarded: forgetting a
// replay floor on a suspicion is adopting a new authority on a guess, and this product does not do that.
func TestAPointerThatNamesNoOrganizationStillGates(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Legacy Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 7, TransportCAPEM: string(ca.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	// installTrustBundle records what the payload named — nothing — so this is the legacy shape.
	if p, ok := readAdoptedPointer(dir); !ok || strings.TrimSpace(p.TenantID) != "" {
		t.Fatalf("expected a pointer naming no organization, got %+v", p)
	}
	if got := trustSerialFloor(dir, "tenant_sakura"); got != 7 {
		t.Fatalf("floor = %d — an unnamed distribution must keep gating; the ambiguity is reported, not acted on", got)
	}
}

// And the tenant is recorded going forward, or the check above has nothing to read next time.
func TestAdoptionRecordsWhichOrganizationTheDistributionBelongsTo(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Sakura Transport CA (test)")
	if _, err := installTrustBundle(dir, agentpolicy.TrustBundlePayload{
		Serial: 2, TenantID: " tenant_sakura ", TransportCAPEM: string(ca.pem)}, "", ""); err != nil {
		t.Fatal(err)
	}
	p, ok := readAdoptedPointer(dir)
	if !ok || p.TenantID != "tenant_sakura" {
		t.Fatalf("pointer tenant = %q, want %q (trimmed)", p.TenantID, "tenant_sakura")
	}
}

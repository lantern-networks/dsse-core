package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// End-to-end renewal against a REAL Edge. No stubs.
//
// The unit tests cover the arithmetic and the rejection rules. What decides whether this is safe to ship is
// the part they cannot reach: does the Edge accept the CSR this code builds, does the issued certificate load
// back as a usable pair, does the probe actually complete an mTLS handshake with it, and does the pointer make
// the renewed identity the one that gets presented afterwards. A fake Edge would answer yes to all of it.
//
// OFF by default — it needs the reference lab and real device key material. Enable it explicitly:
//
//	DSSE_LIVE_RENEWAL_EDGE=https://203.0.113.10:18543 \
//	DSSE_LIVE_RENEWAL_CA=.../transport.pem \
//	DSSE_LIVE_RENEWAL_CERT=.../win-device.pem \
//	DSSE_LIVE_RENEWAL_KEY=.../win-device.key \
//	go test ./ -run TestLiveRenewal -v
//
// It works entirely inside a temporary directory, so the lab's own device files are copied, never modified.
func liveRenewalFixture(t *testing.T) (transportConfig, string, string) {
	t.Helper()
	url := os.Getenv("DSSE_LIVE_RENEWAL_EDGE")
	caPath := os.Getenv("DSSE_LIVE_RENEWAL_CA")
	certPath := os.Getenv("DSSE_LIVE_RENEWAL_CERT")
	keyPath := os.Getenv("DSSE_LIVE_RENEWAL_KEY")
	if url == "" || caPath == "" || certPath == "" || keyPath == "" {
		t.Skip("live renewal check not configured — set DSSE_LIVE_RENEWAL_* to run it")
	}

	// Copy the identity into a scratch directory: renewAndInstall writes new material beside the certificate
	// it is given, and the lab's real files must not gain stray siblings or a pointer file.
	dir := t.TempDir()
	copyInto := func(src, name string) string {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		dst := filepath.Join(dir, name)
		if err := os.WriteFile(dst, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return dst
	}
	localCert := copyInto(certPath, "device.crt")
	localKey := copyInto(keyPath, "device.key")

	tc, err := buildTransportConfig(url, caPath, localCert, localKey)
	if err != nil {
		t.Fatalf("build transport config: %v", err)
	}
	return tc, localCert, localKey
}

// The whole chain in one run: CSR built here, signed by the real Edge, validated, written, probed over real
// mTLS, committed, and then actually preferred on the next load.
func TestLiveRenewalRoundTripAgainstRealEdge(t *testing.T) {
	tc, certPath, keyPath := liveRenewalFixture(t)

	before, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLeaf, err := x509.ParseCertificate(before.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if err := renewAndInstall(&tc, &tc, filepath.Dir(certPath), beforeLeaf.Subject.CommonName); err != nil {
		t.Fatalf("renewal failed: %v", err)
	}

	dir := filepath.Dir(certPath)
	pointer, err := readIdentityPointer(dir)
	if err != nil {
		t.Fatalf("no pointer was committed, so nothing puts the renewed identity in force: %v", err)
	}
	if pointer.CommonName != beforeLeaf.Subject.CommonName {
		t.Fatalf("the renewed identity names %q, not %q", pointer.CommonName, beforeLeaf.Subject.CommonName)
	}
	if !pointer.NotAfter.After(time.Now()) {
		t.Fatal("the committed identity is already expired")
	}

	// The renewed pair must load, and must be what a subsequent start would present.
	renewed, source, err := loadDeviceIdentity(certPath, keyPath)
	if err != nil {
		t.Fatalf("the committed identity does not load: %v", err)
	}
	if source != "renewed" {
		t.Fatalf("after a successful renewal the agent would still present the bootstrap identity (source=%q)", source)
	}
	renewedLeaf, err := x509.ParseCertificate(renewed.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if renewedLeaf.SerialNumber.Cmp(beforeLeaf.SerialNumber) == 0 {
		t.Fatal("the certificate did not actually change")
	}

	// The live config must present it without a restart.
	live := tc.currentClientCert()
	if live == nil || len(live.Certificate) == 0 {
		t.Fatal("no live certificate after renewal")
	}
	liveLeaf, err := x509.ParseCertificate(live.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if liveLeaf.SerialNumber.Cmp(renewedLeaf.SerialNumber) != 0 {
		t.Fatal("the renewed certificate was committed to disk but the running transport still presents the old " +
			"one — a live swap that does not take effect means the device keeps using a certificate it has " +
			"already replaced, right up to expiry")
	}

	// And it really works on the wire, presented the way a steered flow would present it.
	conn, err := tc.dial(20 * time.Second)
	if err != nil {
		t.Fatalf("the (T) tunnel does not come up with the renewed identity: %v", err)
	}
	conn.Close()
}

// A renewal that cannot be proven must cost nothing. This is the property the whole prove-then-commit shape
// exists for: the dangerous failure is not "renewal did not happen" but "renewal happened and the device can
// no longer connect".
func TestLiveRenewalWithAnUnusableEdgeLeavesTheIdentityAlone(t *testing.T) {
	tc, certPath, keyPath := liveRenewalFixture(t)
	dir := filepath.Dir(certPath)

	// Point the probe and the request at a port nothing is listening on. The request itself will fail, which
	// is the common real-world case — a renewal attempt while the Edge is unreachable.
	broken := tc
	broken.host = "127.0.0.1:1"
	broken.active = nil
	broken.pins = nil

	if err := renewAndInstall(&broken, &broken, filepath.Dir(certPath), "win-dev-1"); err == nil {
		t.Fatal("renewal against an unreachable Edge reported success")
	}

	if _, err := readIdentityPointer(dir); err == nil {
		t.Fatal("a failed renewal committed a pointer — the device would now be pointed at material that was " +
			"never proven")
	}
	if _, source, err := loadDeviceIdentity(certPath, keyPath); err != nil || source != "bootstrap" {
		t.Fatalf("the working identity did not survive a failed renewal: source=%q err=%v", source, err)
	}

	// No stray material left behind on the failure path.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "device.crt", "device.key":
		default:
			t.Fatalf("a failed renewal left %q behind", e.Name())
		}
	}
}

// The holiday case, end to end against the real Edge: a device whose certificate expired while it was switched
// off recovers by itself through the recovery listener.
//
// Needs DSSE_LIVE_RECOVERY_ENDPOINT (host:port) in addition to the usual DSSE_LIVE_RENEWAL_* variables, and an
// expired certificate at DSSE_LIVE_EXPIRED_CERT / DSSE_LIVE_EXPIRED_KEY.
func TestLiveRecoveryOfADeviceThatExpiredWhileSwitchedOff(t *testing.T) {
	recovery := os.Getenv("DSSE_LIVE_RECOVERY_ENDPOINT")
	expiredCert := os.Getenv("DSSE_LIVE_EXPIRED_CERT")
	expiredKey := os.Getenv("DSSE_LIVE_EXPIRED_KEY")
	if recovery == "" || expiredCert == "" || expiredKey == "" {
		t.Skip("live recovery check not configured — set DSSE_LIVE_RECOVERY_ENDPOINT and DSSE_LIVE_EXPIRED_*")
	}
	tc, certPath, keyPath := liveRenewalFixture(t)

	// Replace the fixture's identity with the EXPIRED one, as if this device had been off for weeks.
	for _, f := range []struct{ src, dst string }{{expiredCert, certPath}, {expiredKey, keyPath}} {
		raw, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatalf("read %s: %v", f.src, err)
		}
		if err := os.WriteFile(f.dst, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expired, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(expired.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().After(leaf.NotAfter) {
		t.Fatalf("the fixture certificate has not expired (notAfter=%s); this test would prove nothing", leaf.NotAfter)
	}
	tc.clientCert = &expired

	// The normal transport must NOT be able to carry this — that is the whole premise.
	//
	// Checked with a full round-trip, not a handshake: under TLS 1.3 the client's Handshake() succeeds even
	// when the server rejects the certificate, and the refusal only appears on the first read. Asserting on the
	// handshake alone reported that the Edge had ACCEPTED an expired certificate, which was untrue.
	if err := roundTripFails(&tc); err == nil {
		t.Fatal("the (T) transport carried a request with an EXPIRED client certificate; the recovery path " +
			"would be pointless and the main listener is not enforcing expiry")
	}

	// Now the recovery path, exercised through the same function the scheduler calls. No operator declaration.
	if next := runRenewalCheck(&tc, filepath.Dir(certPath), recovery, time.Time{}); next <= 0 {
		t.Fatalf("renewal check returned a non-positive next interval (%s)", next)
	}

	pointer, err := readIdentityPointer(filepath.Dir(certPath))
	if err != nil {
		t.Fatalf("the device did not recover: no pointer was committed (%v)", err)
	}
	if !pointer.NotAfter.After(time.Now()) {
		t.Fatal("the recovered certificate is not valid")
	}

	// And the recovered identity must work on the NORMAL transport again — recovery is only worth anything if
	// the device can steer afterwards.
	tc.setClientCert(nil)
	recovered, source, err := loadDeviceIdentity(certPath, keyPath)
	if err != nil || source != "renewed" {
		t.Fatalf("the recovered identity is not the one that would be presented: source=%q err=%v", source, err)
	}
	tc.clientCert = &recovered
	if err := roundTripFails(&tc); err != nil {
		t.Fatalf("the device recovered a certificate but still cannot use the (T) transport: %v", err)
	}
}

// roundTripFails returns nil when a request completes over the (T) tunnel, and an error otherwise. Named for
// what it is used to assert; a handshake alone would not answer the question under TLS 1.3.
func roundTripFails(tc *transportConfig) error {
	conn, err := tc.dial(15 * time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: dsse\r\nConnection: close\r\n\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	return err
}

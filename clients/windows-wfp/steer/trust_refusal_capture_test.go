package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The whole point: a device that REFUSES the Edge's certificate records WHY, at the verification decision point,
// naming the served certificate — even though the handshake it just failed cannot carry that report. A dial
// against a server whose leaf does not chain to the pinned CA must fail closed AND leave a refusal behind.
func TestTransportRecordsRefusalOnPinMismatch(t *testing.T) {
	pinned := newTestCA(t, "pinned transport CA")
	rogue := newTestCA(t, "some other CA")
	// The Edge (here, the listener) serves a leaf under a CA the device does NOT pin.
	roguedLeaf := leafUnder(t, rogue)
	ln := startTransportListener(t, roguedLeaf)

	pool := x509.NewCertPool()
	pool.AddCert(pinned.cert)
	j := newTrustRefusalJournal(t.TempDir())
	tc := transportConfig{
		enabled: true, host: ln.Addr().String(), serverName: "127.0.0.1",
		rootCAs: pool, sessionCache: newSessionCachePointer(4), refusals: j,
	}

	conn, err := tc.dial(5 * time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("dial SUCCEEDED against a certificate that does not chain to the pinned CA — fail-open")
	}

	p := j.pending()
	if len(p) != 1 {
		t.Fatalf("expected exactly one recorded refusal, got %d", len(p))
	}
	// It names the certificate the server actually served (the rogue leaf), so an operator can correlate.
	servedDER := roguedLeaf.Certificate[0]
	sum := sha256.Sum256(servedDER)
	if p[0].ServedSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("recorded served_sha256 is not the served leaf")
	}
	// And the verifier's own words are carried, not a code.
	if p[0].Reason == "" || !strings.Contains(strings.ToLower(p[0].Reason), "x509") {
		t.Fatalf("reason should be the verifier string, got %q", p[0].Reason)
	}
}

// The verification must still ACCEPT a certificate that chains to the pinned CA — the refusal path is an
// addition, not a change to who is trusted — and record NOTHING on success.
func TestTransportAcceptsPinnedCertAndRecordsNothing(t *testing.T) {
	pinned := newTestCA(t, "pinned transport CA")
	goodLeaf := leafUnder(t, pinned)
	ln := startTransportListener(t, goodLeaf)

	pool := x509.NewCertPool()
	pool.AddCert(pinned.cert)
	j := newTrustRefusalJournal(t.TempDir())
	tc := transportConfig{
		enabled: true, host: ln.Addr().String(), serverName: "127.0.0.1",
		rootCAs: pool, sessionCache: newSessionCachePointer(4), refusals: j,
	}

	conn, err := tc.dial(5 * time.Second)
	if err != nil {
		t.Fatalf("a certificate chaining to the pinned CA was refused: %v", err)
	}
	conn.Close()
	if len(j.pending()) != 0 {
		t.Fatal("a successful verification must record no refusal")
	}
}

// A wrong SNI is still a refusal the operator should see: the pin chains but the name does not match.
func TestTransportRecordsRefusalOnNameMismatch(t *testing.T) {
	pinned := newTestCA(t, "pinned transport CA")
	leaf := leafUnder(t, pinned) // valid for 127.0.0.1 (see leafUnder)
	ln := startTransportListener(t, leaf)

	pool := x509.NewCertPool()
	pool.AddCert(pinned.cert)
	j := newTrustRefusalJournal(t.TempDir())
	tc := transportConfig{
		enabled: true, host: ln.Addr().String(), serverName: "wrong.example", // name the leaf is NOT valid for
		rootCAs: pool, sessionCache: newSessionCachePointer(4), refusals: j,
	}
	if conn, err := tc.dial(5 * time.Second); err == nil {
		conn.Close()
		t.Fatal("dial accepted a certificate not valid for the requested name")
	}
	if len(j.pending()) != 1 {
		t.Fatal("a name mismatch should be recorded as a refusal")
	}
}

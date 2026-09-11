package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func aCertificateEndingAt(t *testing.T, end time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dsse-edge-fleet"},
		NotBefore:    end.AddDate(-1, 0, 0),
		NotAfter:     end,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}}
}

// ★★★ A NODE THAT HAS BEEN UP FOR A YEAR MUST NOT REACH ITS OWN END IN SILENCE (2026-09-08).
//
// The certificate this node presents to the control plane is minted by the installer for ONE YEAR and
// renewed by nothing. The warning about it fires inside the last fourteen days — and it used to be evaluated
// once, when the TLS config was built. A node running continuously therefore never looked during the only
// fortnight the warning exists for, and everything riding that channel — audit shipping, per-organization
// material refresh, rotations included, revocation sync — would have stopped without a line.
func TestTheNodeSaysItsOwnIdentityIsEndingWhileItIsStillRunning(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	said := []string{}
	warn := func(format string, a ...any) { said = append(said, sprintf(format, a...)) }

	// Far from the end: silence, because a line every hour for a year is a line nobody reads.
	var quiet atomic.Int64
	far := aCertificateEndingAt(t, now.Add(90*24*time.Hour))
	if warnIfNodeIdentityIsEnding(far, &quiet, now, warn) {
		t.Fatalf("a node ninety days from its end warned: %v", said)
	}

	// Inside the fortnight: it says so, and says that nothing will renew it — because "expires in 3 days"
	// reads as "something will handle it" to anyone who has not read the installer.
	var counter atomic.Int64
	ending := aCertificateEndingAt(t, now.Add(3*24*time.Hour))
	if !warnIfNodeIdentityIsEnding(ending, &counter, now, warn) {
		t.Fatal("a node three days from the end of the certificate it presents to the control plane said nothing")
	}
	if len(said) != 1 || !strings.Contains(said[0], "NOTHING IN THIS DEPLOYMENT RENEWS IT") {
		t.Fatalf("the warning does not say that nothing renews it: %v", said)
	}
	if !strings.Contains(said[0], "rotations included") {
		t.Fatalf("the warning does not name what stops with it: %v", said)
	}

	// ★ AND IT IS THROTTLED, because this is evaluated per handshake on a pooled channel. A minute later,
	// nothing more.
	if warnIfNodeIdentityIsEnding(ending, &counter, now.Add(time.Minute), warn) {
		t.Fatalf("the warning repeated on the next handshake: %v", said)
	}
	if len(said) != 1 {
		t.Fatalf("expected one line, got: %v", said)
	}

	// An hour on, it says it again — this must keep being visible for the whole fortnight, not once.
	if !warnIfNodeIdentityIsEnding(ending, &counter, now.Add(61*time.Minute), warn) {
		t.Fatalf("the warning was said once and never again: %v", said)
	}
	if len(said) != 2 {
		t.Fatalf("expected two lines an hour apart, got: %v", said)
	}

	// Past the end it still says so: a node presenting an expired identity is the loudest case, not the
	// quietest.
	var late atomic.Int64
	if !warnIfNodeIdentityIsEnding(aCertificateEndingAt(t, now.Add(-time.Hour)), &late, now, warn) {
		t.Fatal("a node whose control-plane identity had already expired said nothing")
	}
}

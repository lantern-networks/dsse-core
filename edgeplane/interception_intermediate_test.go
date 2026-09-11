package edgeplane

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

// TestInterceptionIntermediateChainsLeafThroughRotatableIntermediate proves Slice 3: with the intermediate ON
// the leaf is signed by a name-constrained intermediate (chain [leaf, intermediate, root]) that the root issued,
// the path validates to the same root, and the name constraint BITES — a leaf minted for a host outside the
// permitted space does not validate. Default OFF keeps the [leaf, root] chain (today's behavior).
func TestInterceptionIntermediateChainsLeafThroughRotatableIntermediate(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}

	// Default OFF: the chain is [leaf, root].
	off, err := interception.leafCertificate("", "plain.example.com")
	if err != nil {
		t.Fatalf("leaf (off): %v", err)
	}
	if len(off.Certificate) != 2 {
		t.Fatalf("intermediate off: chain len=%d want 2 [leaf,root]", len(off.Certificate))
	}

	interception.EnableInterceptionIntermediate([]string{"example.com"})

	leaf, err := interception.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("leaf (on): %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("intermediate on: chain len=%d want 2 [leaf,intermediate]", len(leaf.Certificate))
	}
	leafX, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	interX, err := x509.ParseCertificate(leaf.Certificate[1])
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	// ★ THE ROOT COMES FROM THE ENGINE, NOT FROM THE WIRE (2026-08-21). It is a trust anchor: a device holds
	// it in its own store and the server does not present it. Taking it from interception.rootCert is what a
	// device does — it looks in the store it was installed with.
	rootX := interception.rootCert

	if !interX.IsCA {
		t.Fatal("intermediate is not a CA")
	}
	if len(interX.PermittedDNSDomains) == 0 || interX.PermittedDNSDomains[0] != "example.com" {
		t.Fatalf("intermediate missing the name constraint: %v", interX.PermittedDNSDomains)
	}
	if !bytes.Equal(rootX.Raw, interception.rootCert.Raw) {
		t.Fatal("chain root is not the engine's root (the trust anchor must be unchanged)")
	}
	if err := leafX.CheckSignatureFrom(interX); err != nil {
		t.Fatalf("leaf is not signed by the intermediate: %v", err)
	}
	if err := interX.CheckSignatureFrom(rootX); err != nil {
		t.Fatalf("intermediate is not signed by the root: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootX)
	inters := x509.NewCertPool()
	inters.AddCert(interX)
	opts := func(dns string) x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: dns, CurrentTime: now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	}
	if _, err := leafX.Verify(opts("host.example.com")); err != nil {
		t.Fatalf("leaf does not validate to root via the intermediate: %v", err)
	}

	// The name constraint must BITE: a leaf the engine minted for a host outside example.com must NOT validate.
	evil, err := interception.leafCertificate("", "evil.com")
	if err != nil {
		t.Fatalf("leaf evil: %v", err)
	}
	evilX, err := x509.ParseCertificate(evil.Certificate[0])
	if err != nil {
		t.Fatalf("parse evil leaf: %v", err)
	}
	if _, err := evilX.Verify(opts("evil.com")); err == nil {
		t.Fatal("name constraint did not bite: an evil.com leaf validated through the example.com-constrained intermediate")
	}
}

// TestInterceptionIntermediateRotationKeepsRoot proves rotation has NO flag day: a rotate issues a fresh
// intermediate (the exposed online signer changes) while the ROOT — the device trust anchor — is unchanged, and
// post-rotation leaves still validate to that same root.
func TestInterceptionIntermediateRotationKeepsRoot(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC) }
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, now)
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.EnableInterceptionIntermediate(nil) // unconstrained (decrypt-all)

	before, err := interception.leafCertificate("", "a.example.com")
	if err != nil {
		t.Fatalf("leaf before: %v", err)
	}
	// The anchor is not on the wire; it is what the engine holds. See the note above.
	rootBefore, interBefore := interception.rootCert.Raw, before.Certificate[1]

	interception.RotateInterceptionIntermediate()

	after, err := interception.leafCertificate("", "a.example.com") // the rotate cleared the leaf cache
	if err != nil {
		t.Fatalf("leaf after: %v", err)
	}
	rootAfter, interAfter := interception.rootCert.Raw, after.Certificate[1]

	if !bytes.Equal(rootBefore, rootAfter) {
		t.Fatal("rotation changed the ROOT (it must stay stable so devices need no re-trust)")
	}
	if bytes.Equal(interBefore, interAfter) {
		t.Fatal("rotation did not change the intermediate (the exposed signing key did not actually rotate)")
	}

	leafX, _ := x509.ParseCertificate(after.Certificate[0])
	interX, _ := x509.ParseCertificate(after.Certificate[1])
	rootX := interception.rootCert
	roots := x509.NewCertPool()
	roots.AddCert(rootX)
	inters := x509.NewCertPool()
	inters.AddCert(interX)
	if _, err := leafX.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "a.example.com", CurrentTime: now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("post-rotation leaf does not validate to the same root: %v", err)
	}
}

// A client whose clock runs ahead must still accept the chain.
//
// The intermediate used to be backdated by one minute while the root and the leaves used an hour. That is the
// worst place to be stingy: EVERY interception leaf chains through this intermediate, so a client a couple of
// minutes fast rejects the entire chain and loses interception for every site at once — and it presents as
// "certificate is not yet valid" everywhere, which looks like a CA fault rather than a clock one. A machine
// that has just booted and not yet reached NTP is off by more than a minute as a matter of course.
func TestIntermediateToleratesAClientClockRunningAhead(t *testing.T) {
	issuedAt := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return issuedAt })
	if err != nil {
		t.Fatalf("new interception: %v", err)
	}
	interception.EnableInterceptionIntermediate([]string{"example.com"})

	chain, err := interception.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	// See the note in loadOfflineInterceptionIssuer: a server presents the intermediates, never the anchor.
	if len(chain.Certificate) != 2 {
		t.Fatalf("chain len=%d, want [leaf, intermediate]", len(chain.Certificate))
	}
	intermediate, err := x509.ParseCertificate(chain.Certificate[1])
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}

	// A machine that has just booted and not yet reached NTP is routinely off by more than a minute. Each of
	// these is a client that believes it is EARLIER than the Edge does.
	for _, skew := range []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute} {
		clientNow := issuedAt.Add(-skew)
		if clientNow.Before(intermediate.NotBefore) {
			t.Fatalf("a client %s behind rejects the intermediate as not yet valid (notBefore=%s) — every "+
				"interception leaf chains through it, so that client loses interception for EVERY site at "+
				"once, and it presents as a CA fault rather than a clock one",
				skew, intermediate.NotBefore.Format(time.RFC3339))
		}
	}
}

package edgeplane

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

// ★★★ EIGHTEEN MINUTES OF BROKEN HTTPS, AND NOTHING ON EITHER SIDE NOTICED (2026-08-21, reported from
// win-dev-1 after an operator said "the other terminal cannot connect").
//
// Interception material was accepted whose issuing authority sat under a parent carrying
// pathLenConstraint:0. The chain it produced reaches the right root by a route no correct verifier accepts.
// The Edge served it; Chrome accepted it; 230 handshakes got a certificate and were dropped by the client over
// eighteen minutes while the agent reported enforcement=healthy every fifteen seconds. The first person to
// find out was a human who could not reach a website.
//
// Nobody asked the question a device asks. It is asked here now, on the material, before a connection is
// served with it.
func TestInterceptionMaterialIsTriedBeforeItIsTrusted(t *testing.T) {
	now := time.Now().UTC()
	root, rootKey := selfSignedProbeCA(t, "Probe Interception Root", nil, now)

	// An issuing authority with NO room beneath it — the careful way to issue one, and the shape that produced
	// the outage once the control plane minted a per-node tier under it.
	noRoom, noRoomKey := probeSubCA(t, "Probe Issuing CA (pathlen 0)", root, rootKey, 0, true, now)
	perNode, perNodeKey := probeSubCA(t, "Probe Per-Edge Tier", noRoom, noRoomKey, 0, true, now)

	err := interceptionMaterialMintsAVerifiableLeaf(perNode, perNodeKey,
		[][]byte{perNode.Raw, noRoom.Raw}, root, now)
	if err == nil {
		t.Fatal("★ material that cannot mint a verifiable leaf was accepted. Serving it breaks every HTTPS " +
			"request from every device of that organization while the node reports itself healthy — which is " +
			"exactly what happened, for eighteen minutes, on somebody's laptop.")
	}
	// ★ THE VERIFIER'S OWN WORDS. "Implementations disagree" is what this failure looked like in the field —
	// Chrome accepted the chain, openssl and git did not — so the reason must not be flattened into a summary.
	if !strings.Contains(err.Error(), "path length") {
		t.Fatalf("the refusal does not carry what the verifier actually said: %v", err)
	}

	// ★ THE CONTROL: material with room IS accepted, or this gate refuses everything and proves nothing.
	room, roomKey := probeSubCA(t, "Probe Issuing CA (pathlen 1)", root, rootKey, 1, false, now)
	tier, tierKey := probeSubCA(t, "Probe Per-Edge Tier", room, roomKey, 0, true, now)
	if err := interceptionMaterialMintsAVerifiableLeaf(tier, tierKey,
		[][]byte{tier.Raw, room.Raw}, root, now); err != nil {
		t.Fatalf("material that verifies correctly was refused: %v", err)
	}

	// ★ AND A NAME-CONSTRAINED AUTHORITY IS NOT MISREAD AS BROKEN. Constraining an interception authority to
	// the domains it may sign is the careful thing to do; a fixed probe name would fail every one of them.
	constrained, constrainedKey := probeSubCA(t, "Probe Constrained CA", root, rootKey, 1, false, now)
	constrained.PermittedDNSDomains = []string{"example.com"}
	reissued, reissuedKey := probeSubCAWithConstraint(t, "Probe Constrained CA", root, rootKey, now, "example.com")
	_ = constrained
	_ = constrainedKey
	inner, innerKey := probeSubCA(t, "Probe Tier Under Constraint", reissued, reissuedKey, 0, true, now)
	if err := interceptionMaterialMintsAVerifiableLeaf(inner, innerKey,
		[][]byte{inner.Raw, reissued.Raw}, root, now); err != nil {
		t.Fatalf("a name-constrained authority was reported as unable to sign: %v", err)
	}
}

func selfSignedProbeCA(t *testing.T, cn string, _ []string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed: %v", err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func probeSubCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	maxPathLen int, zero bool, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: maxPathLen, MaxPathLenZero: zero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("sub CA: %v", err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func probeSubCAWithConstraint(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	now time.Time, permitted string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 1, PermittedDNSDomains: []string{permitted},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("constrained CA: %v", err)
	}
	c, _ := x509.ParseCertificate(der)
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return c, key
}

package transportca

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"encoding/pem"
)

// writeKeyPEM writes an EC private key in the PKCS#8 PEM form the Edge's loader accepts.
func writeKeyPEM(t *testing.T, path string, key crypto.Signer) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// handshakeAs performs a REAL TLS handshake against a server configured the way the Edge configures its
// transport listener, with the client trusting exactly one anchor. Unit-level chain verification can pass while
// the served chain is still wrong, because what the server actually puts on the wire is decided by the TLS
// stack — so the migration is only proven once a handshake completes.
func handshakeAs(t *testing.T, serverCert tls.Certificate, anchor *x509.Certificate, serverName string) error {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(anchor)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	// BOTH ends need a deadline. net.Pipe is unbuffered and synchronous, so when the client rejects the chain
	// and stops reading, a server still writing handshake records blocks forever — the failure case would hang
	// instead of failing, which is the opposite of what a test asserting rejection should do.
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	serverErr := make(chan error, 1)
	go func() {
		s := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
		serverErr <- s.Handshake()
	}()

	c := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	err := c.Handshake()
	select {
	case <-serverErr:
	case <-time.After(5 * time.Second):
	}
	return err
}

// End-to-end proof of the migration, over a real handshake and through the SAME loader the Edge uses
// (tls.LoadX509KeyPair on a PEM containing leaf + cross-certificate). This is what says the Edge needs no code
// change to serve the chain — a claim about Go's loader that is worth verifying rather than assuming.
func TestEdgeLoaderServesTheChainSoOldAnchorsStillHandshake(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()

	// What is deployed today: a self-signed transport certificate that every device pins.
	oldKey := testKey(t)
	oldAnchor := legacySelfSignedTransportCert(t, oldKey, now.Add(2*365*24*time.Hour))

	// The migration artefacts.
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSign(oldAnchor, oldKey, newCA.Cert, now.Add(-time.Hour), now.Add(400*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leafKey := testKey(t)
	leaf, err := newCA.IssueServerLeaf(leafKey, LeafRequest{
		Subject:   pkix.Name{CommonName: "dsse-transport"},
		DNSNames:  []string{"localhost"},
		IPs:       []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Exactly what an operator would write to disk: transport.pem holds the chain, transport.key the leaf key.
	chainPEM, err := ChainPEM(leaf, cross)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "transport.pem")
	keyPath := filepath.Join(dir, "transport.key")
	if err := os.WriteFile(certPath, chainPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	writeKeyPEM(t, keyPath, leafKey)

	// The Edge's own loader.
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("the Edge's loader rejected the chain file: %v", err)
	}
	if len(serverCert.Certificate) != 2 {
		t.Fatalf("loader kept %d certificates, want 2 (leaf + cross) — the cross-certificate would never reach the wire", len(serverCert.Certificate))
	}

	// A device that has never been updated, still pinned to the old self-signed certificate.
	if err := handshakeAs(t, serverCert, oldAnchor, "localhost"); err != nil {
		t.Fatalf("a device pinned to the OLD anchor failed the handshake — the migration would strand it: %v", err)
	}
	// A device that has adopted the new CA.
	if err := handshakeAs(t, serverCert, newCA.Cert, "localhost"); err != nil {
		t.Fatalf("a device pinned to the NEW CA failed the handshake: %v", err)
	}
}

// The failure mode that would go unnoticed: serving only the leaf keeps every up-to-date device working while
// silently locking out the ones that have not moved. Proven at the handshake, not just at chain verification.
func TestHandshakeFailsForOldAnchorsWhenTheChainOmitsTheCrossCertificate(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()

	oldKey := testKey(t)
	oldAnchor := legacySelfSignedTransportCert(t, oldKey, now.Add(2*365*24*time.Hour))
	newCA, err := NewCA(pkix.Name{CommonName: "DSSE Transport CA"}, testKey(t), now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CrossSign(oldAnchor, oldKey, newCA.Cert, now.Add(-time.Hour), now.Add(400*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	leafKey := testKey(t)
	leaf, err := newCA.IssueServerLeaf(leafKey, LeafRequest{
		Subject: pkix.Name{CommonName: "dsse-transport"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	leafOnly, err := ChainPEM(leaf) // the cross-certificate exists but was not deployed
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "transport.pem")
	keyPath := filepath.Join(dir, "transport.key")
	if err := os.WriteFile(certPath, leafOnly, 0o600); err != nil {
		t.Fatal(err)
	}
	writeKeyPEM(t, keyPath, leafKey)
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := handshakeAs(t, serverCert, oldAnchor, "localhost"); err == nil {
		t.Fatal("an old-anchor device completed the handshake without the cross-certificate — this test cannot catch the stranding it exists for")
	}
	if err := handshakeAs(t, serverCert, newCA.Cert, "localhost"); err != nil {
		t.Fatalf("a new-anchor device must still work — that is exactly why this mistake is invisible: %v", err)
	}
}

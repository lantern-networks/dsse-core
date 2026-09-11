package edgeplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// End-to-end proof of the property the fleet ticket key exists for: a client that the load balancer moves from
// one Edge to another completes a RESUMED handshake instead of a full one.
//
// The unit tests next door only prove two nodes derive equal bytes. Equal bytes are not the goal — a resumed
// handshake is. This drives real tls.Server/tls.Dial so the claim is checked against Go's actual resumption
// rules rather than against my reading of them.
//
// It also settles a question that decides how much further work needs: the two Edges here mint DIFFERENT
// leaves for the same host (own key, own serial), exactly as independent Edges do today. If resumption still
// happens, then making leaves fleet-identical is not required for the performance goal.

// interceptionTestRoot mints a CA standing in for the shared interception root.
func interceptionTestRoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test interception root"},
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
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// interceptionTestLeaf mints a leaf under the shared root with its OWN key and serial — what each Edge does
// independently today, so two Edges never present byte-identical certificates for the same host.
func interceptionTestLeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key, Leaf: leaf}
}

// startInterceptionTestEdge serves one TLS endpoint standing in for an Edge's interception listener.
func startInterceptionTestEdge(t *testing.T, leaf tls.Certificate, ticketKeys [][32]byte, version uint16) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: version, MaxVersion: version}
	if len(ticketKeys) > 0 {
		cfg.SetSessionTicketKeys(ticketKeys)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			go func() {
				defer conn.Close()
				buf := make([]byte, 1)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				// Reply so the client has something to read. In TLS 1.3 the NewSessionTicket is sent
				// AFTER the handshake, and a client only processes it during a read — without this
				// exchange the client never receives a ticket and "did not resume" would be an
				// artefact of the test rather than a fact about the code.
				conn.Write([]byte("y"))
				time.Sleep(100 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().String()
}

// dialInterceptionTestEdge connects, exchanges a byte, and reports whether the handshake was resumed.
func dialInterceptionTestEdge(t *testing.T, addr string, pool *x509.CertPool, cache tls.ClientSessionCache, version uint16) bool {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:            pool,
		ServerName:         "resume.example.com",
		ClientSessionCache: cache,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	return conn.ConnectionState().DidResume
}

// A client moved between two Edges resumes — and does so even though the two Edges present different leaves.
func TestClientResumesAfterMovingBetweenEdges(t *testing.T) {
	const secret = "fleet-secret-for-resumption-test"

	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{"TLS1.3", tls.VersionTLS13},
		{"TLS1.2", tls.VersionTLS12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, rootKey, pool := interceptionTestRoot(t)

			// Each Edge derives its keys independently, from the same secret, on its own clock.
			keysA, okA := fleetSessionTicketKeys(secret, time.Now())
			keysB, okB := fleetSessionTicketKeys(secret, time.Now().Add(11*time.Minute))
			if !okA || !okB {
				t.Fatal("a configured secret must produce keys")
			}

			edgeA := startInterceptionTestEdge(t, interceptionTestLeaf(t, root, rootKey, "resume.example.com"), keysA, tc.version)
			edgeB := startInterceptionTestEdge(t, interceptionTestLeaf(t, root, rootKey, "resume.example.com"), keysB, tc.version)

			cache := tls.NewLRUClientSessionCache(8)
			if resumed := dialInterceptionTestEdge(t, edgeA, pool, cache, tc.version); resumed {
				t.Fatal("the very first connection reported resumption; the test is not measuring what it claims")
			}
			if !dialInterceptionTestEdge(t, edgeB, pool, cache, tc.version) {
				t.Fatal("a client moved to another Edge did NOT resume — every load-balancer rebalance would " +
					"cost a full handshake, which is the cost the fleet ticket key exists to remove")
			}
		})
	}
}

// The negative control. Without the shared secret each Edge keeps a per-process random key, and the same client
// movement costs a full handshake. Without this, the test above could pass for reasons unrelated to the fix.
func TestClientMovedBetweenEdgesWithoutFleetSecretDoesNotResume(t *testing.T) {
	root, rootKey, pool := interceptionTestRoot(t)

	var keyA, keyB [32]byte
	if _, err := rand.Read(keyA[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(keyB[:]); err != nil {
		t.Fatal(err)
	}

	edgeA := startInterceptionTestEdge(t, interceptionTestLeaf(t, root, rootKey, "resume.example.com"), [][32]byte{keyA}, tls.VersionTLS13)
	edgeB := startInterceptionTestEdge(t, interceptionTestLeaf(t, root, rootKey, "resume.example.com"), [][32]byte{keyB}, tls.VersionTLS13)

	cache := tls.NewLRUClientSessionCache(8)
	dialInterceptionTestEdge(t, edgeA, pool, cache, tls.VersionTLS13)
	if dialInterceptionTestEdge(t, edgeB, pool, cache, tls.VersionTLS13) {
		t.Fatal("resumption happened across Edges with UNRELATED ticket keys — then the positive test above " +
			"proves nothing about the shared key")
	}
}

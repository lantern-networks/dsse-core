package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTransportTLSConfigResumesAndKeepsClientIdentity proves the perf fix is real AND safe:
//   - with the process-shared ClientSessionCache, the SECOND (T) tunnel connection RESUMES (no full handshake),
//   - and the server still sees the device client cert on the resumed connection (so the Edge's VerifyConnection
//     admission + revocation kill-switch keep working — only the handshake is cheaper).
//
// Without resumption the Windows agent paid a full mTLS handshake per steered flow, which is the gap vs the
// macOS NE (Apple's TLS resumes automatically).
func TestTransportTLSConfigResumesAndKeepsClientIdentity(t *testing.T) {
	caCert, caKey := mustSelfSignedCA(t)
	serverCert := mustLeaf(t, caCert, caKey, "edge-transport")
	clientCert := mustLeaf(t, caCert, caKey, "mac-dev-1")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Server mimics the Edge (T) transport listener: mTLS required, tickets enabled (default), and a
	// VerifyConnection that records the peer identity it sees on EACH connection (full or resumed).
	var mu sync.Mutex
	var sawIdentities []string
	var resumed []bool
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: caKey, Leaf: serverCert}},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			mu.Lock()
			defer mu.Unlock()
			id := ""
			if len(cs.PeerCertificates) > 0 {
				id = cs.PeerCertificates[0].Subject.CommonName
			}
			sawIdentities = append(sawIdentities, id)
			resumed = append(resumed, cs.DidResume)
			return nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc := c.(*tls.Conn)
				_ = tc.Handshake()
				// Write first so the TLS 1.3 NewSessionTicket (sent post-handshake) is flushed to the client,
				// then read the client's byte before closing.
				_, _ = tc.Write([]byte("ok"))
				buf := make([]byte, 8)
				_, _ = tc.Read(buf)
				c.Close()
			}(c)
		}
	}()

	cc := tls.Certificate{Certificate: [][]byte{clientCert.Raw}, PrivateKey: caKey, Leaf: clientCert}
	// sessionCache is per-config now (a global shared cache let a different pin resume another pin's session
	// and skip the chain check); a directly-built transportConfig must set it, exactly as buildTransportConfig does.
	tc := transportConfig{enabled: true, host: ln.Addr().String(), serverName: "edge-transport", rootCAs: pool, clientCert: &cc, sessionCache: newSessionCachePointer(256)}

	dialOnce := func() *tls.ConnectionState {
		raw, err := net.DialTimeout("tcp", tc.host, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn := tls.Client(raw, tc.tlsConfig())
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		// Read first: this processes the server's post-handshake NewSessionTicket (TLS 1.3) so the shared
		// ClientSessionCache stores a resumable session for the next dial.
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("x"))
		cs := conn.ConnectionState()
		time.Sleep(10 * time.Millisecond)
		conn.Close()
		return &cs
	}

	cs1 := dialOnce()
	if cs1.DidResume {
		t.Fatalf("first connection should NOT resume")
	}
	// Give the client time to store the session ticket the server issued.
	time.Sleep(50 * time.Millisecond)
	cs2 := dialOnce()
	if !cs2.DidResume {
		t.Fatalf("second connection should RESUME via the per-config ClientSessionCache, but it did a full handshake")
	}

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(sawIdentities) < 2 {
		t.Fatalf("server saw %d connections, want >=2", len(sawIdentities))
	}
	for i, id := range sawIdentities {
		if id != "mac-dev-1" {
			t.Fatalf("connection %d: server saw client identity %q, want mac-dev-1 (admission must hold on resumed sessions)", i, id)
		}
	}
	if !contains(resumed, true) {
		t.Fatalf("server never observed a resumed connection")
	}
}

// Adopting a renewed identity must FLUSH the session cache, so the next dial is a full handshake and the Edge
// actually sees the new certificate.
//
// This is the 2026-08-02 defect: TLS 1.3 resumption skips the client-certificate exchange and Go's server keeps
// showing the ORIGINAL session's certificate (tickets last up to 7 days). Without the flush a device renews,
// believes it renewed, and the Edge goes on observing the superseded certificate — which is how a device blocks
// the retirement of a CA it has already moved off. The endpoint and the Edge are each right about what they can
// see, and nothing in either view reveals the disagreement.
func TestAdoptingRenewedIdentityFlushesSessionCache(t *testing.T) {
	tc := transportConfig{
		sessionCache:   newSessionCachePointer(256),
		liveClientCert: &atomic.Pointer[tls.Certificate]{},
	}
	before := tc.currentSessionCache()
	if before == nil {
		t.Fatal("a freshly built config must have a session cache")
	}
	// Put something in the cache so "replaced" is observable: a cache that still answers for this key would
	// let the next dial resume with the OLD identity.
	before.Put("edge-transport", &tls.ClientSessionState{})
	if _, ok := before.Get("edge-transport"); !ok {
		t.Fatal("test setup: the entry was not stored")
	}

	tc.setClientCert(&tls.Certificate{})

	after := tc.currentSessionCache()
	if after == nil {
		t.Fatal("the cache must be replaced, not removed — resumption stays enabled after the flush")
	}
	if after == before {
		t.Fatal("adopting a renewed identity did not replace the session cache; the next dial could resume and present the OLD certificate")
	}
	if _, ok := after.Get("edge-transport"); ok {
		t.Fatal("the flushed cache still holds the pre-renewal session")
	}
	// The renewed certificate is in force for every copy of the config (the flush must not disturb that).
	if tc.currentClientCert() == nil {
		t.Fatal("the renewed certificate is not in force after adoption")
	}
}

func contains(bs []bool, v bool) bool {
	for _, b := range bs {
		if b == v {
			return true
		}
	}
	return false
}

func mustSelfSignedCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func mustLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// self-signed cert+key PAIR on disk (unlike testCertPEM, which returns cert bytes only).
func writeCertKeyPair(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cp := filepath.Join(dir, name+".pem")
	kp := filepath.Join(dir, name+".key")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cp, kp
}

// Reproduces the 2026-07-31 outage: after the per-connection ClientCAs override landed, the (T) handshake
// stopped answering ClientHello at all.
//
// Through the REAL accept path, and judged from the SERVER. Both matter (review V10). The previous version
// dialled the built config directly, skipping attachConnRegistryTracking — which is where the per-connection
// ClientCAs are installed, and therefore where the outage lived. And it asserted only that the CLIENT's
// Handshake returned nil, which in TLS 1.3 happens before the server has looked at the client certificate
// at all: a server rejecting every device would have passed this test unchanged. What proves mTLS works is
// the server completing its own handshake with the peer certificate in hand, and what proves it is enforced
// is an unrelated certificate being turned away.
func TestSecureTransportHandshakeCompletes(t *testing.T) {
	dir := t.TempDir()
	srvCert, srvKey := writeCertKeyPair(t, dir, "transport")
	caCert, caKey := writeCertKeyPair(t, dir, "device-ca")
	strangerCert, strangerKey := writeCertKeyPair(t, dir, "not-our-ca")

	cfg := secureTransportConfig{
		ListenAddr:        "127.0.0.1:0",
		CertFile:          srvCert,
		KeyFile:           srvKey,
		ClientCAFile:      caCert,
		RequireClientCert: true,
		LabMode:           true,
	}
	tlsCfg, err := buildSecureTransportTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The real path: the registry wrapper is what serves the per-connection ClientCAs, so a test that skips
	// it cannot see the defect it was written for.
	reg := newTransportConnRegistry()
	tlsCfg = attachConnRegistryTracking(tlsCfg, reg)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type serverOutcome struct {
		err       error
		peerCount int
		peerCN    string
	}
	outcomes := make(chan serverOutcome, 4)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				tc := conn.(*tls.Conn)
				herr := tc.Handshake()
				out := serverOutcome{err: herr}
				if herr == nil {
					st := tc.ConnectionState()
					out.peerCount = len(st.PeerCertificates)
					if out.peerCount > 0 {
						out.peerCN = st.PeerCertificates[0].Subject.CommonName
					}
					// Say something, so the client's own read has an answer to wait for.
					_, _ = tc.Write([]byte("ok"))
				}
				outcomes <- out
			}(c)
		}
	}()

	dial := func(t *testing.T, certPath, keyPath string) (*tls.Conn, serverOutcome) {
		t.Helper()
		pair, perr := tls.LoadX509KeyPair(certPath, keyPath)
		if perr != nil {
			t.Fatal(perr)
		}
		raw, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if derr != nil {
			t.Fatal(derr)
		}
		tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{pair}})
		tconn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tconn.Handshake() // TLS 1.3: this returns before the server has judged us. Not the verdict.
		select {
		case out := <-outcomes:
			return tconn, out
		case <-time.After(4 * time.Second):
			t.Fatal("the server never reached a verdict — the handshake hung, which is the 2026-07-31 symptom")
			return nil, serverOutcome{}
		}
	}

	// A device whose certificate comes from the configured CA is admitted, and the server can name it.
	conn, got := dial(t, caCert, caKey)
	defer conn.Close()
	if got.err != nil {
		t.Fatalf("a device from the configured CA must be admitted: %v", got.err)
	}
	if got.peerCount == 0 {
		t.Fatal("the server completed a handshake without a client certificate — mTLS is not being enforced")
	}
	if got.peerCN != "device-ca" {
		t.Fatalf("the server must see the certificate the device presented, got %q", got.peerCN)
	}
	buf := make([]byte, 2)
	if _, rerr := conn.Read(buf); rerr != nil {
		t.Fatalf("an admitted connection must carry data: %v", rerr)
	}

	// And one from anywhere else is turned away. Checked on the SERVER, because the client is not told at
	// handshake time — the previous test's only assertion would have passed for this case too.
	stranger, refused := dial(t, strangerCert, strangerKey)
	defer stranger.Close()
	if refused.err == nil {
		t.Fatal("a certificate from an unknown CA was admitted — the client CA pool is not being applied")
	}
	if _, rerr := stranger.Read(make([]byte, 2)); rerr == nil {
		t.Fatal("a refused device must not be able to read from the transport")
	}
}

// Reproduces the 2026-08-02 outage: an Edge restart silently dropped every device CA an admin had added to
// the runtime-mutable store. main.go opens the store BEFORE the listener and commits its pool — and the
// listener's own seeding then overwrote it with the seed file's CAs, so a device presenting a certificate
// from a store-added CA (every renewed device) was refused with unknown_ca until the next store mutation
// happened to rebuild the pool.
//
// The startup order is replayed exactly (store commit, then listener build), and the verdict is taken from
// the server through the real accept path, like TestSecureTransportHandshakeCompletes above.
func TestSecureTransportListenerKeepsStoreCommittedDeviceCAs(t *testing.T) {
	dir := t.TempDir()
	srvCert, srvKey := writeCertKeyPair(t, dir, "transport")
	seedCACert, seedCAKey := writeCertKeyPair(t, dir, "seed-device-ca")
	addedCACert, addedCAKey := writeCertKeyPair(t, dir, "runtime-added-issuing-ca")

	// The store's commit, as main.go performs it before the listener starts: seed + runtime-added CA.
	storePool := x509.NewCertPool()
	for _, p := range []string{seedCACert, addedCACert} {
		pemBytes, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !storePool.AppendCertsFromPEM(pemBytes) {
			t.Fatalf("no usable certificate in %s", p)
		}
	}
	transportClientCAPool.Store(storePool)

	// The listener starting afterwards, seeing only the seed file — with the pool managed by the store.
	tlsCfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr:                    "127.0.0.1:0",
		CertFile:                      srvCert,
		KeyFile:                       srvKey,
		ClientCAFile:                  seedCACert,
		RequireClientCert:             true,
		LabMode:                       true,
		ClientCAPoolManagedExternally: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg = attachConnRegistryTracking(tlsCfg, newTransportConnRegistry())

	if got := transportClientCAPool.Load(); got != storePool {
		t.Fatal("building the listener replaced the store-committed device-CA pool — a restart erases runtime-added CAs")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	outcomes := make(chan error, 4)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				outcomes <- conn.(*tls.Conn).Handshake()
			}(c)
		}
	}()

	dial := func(t *testing.T, certPath, keyPath string) error {
		t.Helper()
		pair, perr := tls.LoadX509KeyPair(certPath, keyPath)
		if perr != nil {
			t.Fatal(perr)
		}
		raw, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if derr != nil {
			t.Fatal(derr)
		}
		defer raw.Close()
		tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{pair}})
		tconn.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tconn.Handshake()
		select {
		case out := <-outcomes:
			return out
		case <-time.After(4 * time.Second):
			t.Fatal("the server never reached a verdict")
			return nil
		}
	}

	if err := dial(t, addedCACert, addedCAKey); err != nil {
		t.Fatalf("a device from a store-added CA must survive a restart, got: %v", err)
	}
	if err := dial(t, seedCACert, seedCAKey); err != nil {
		t.Fatalf("a device from the seed CA must still be admitted: %v", err)
	}
}

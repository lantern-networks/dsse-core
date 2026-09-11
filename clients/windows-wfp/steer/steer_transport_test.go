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

// mkSelfSigned builds a self-signed cert (usable as its own root/CA) + key PEMs and a tls.Certificate.
func mkSelfSigned(t *testing.T, cn string, ips []net.IP) (certPEM, keyPEM []byte, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTransportDialPinAndMTLS verifies the (T) client: it pins the Edge transport CA fail-closed (wrong pin
// must fail, never the system store) and presents the device client cert when the server requires mTLS.
func TestTransportDialPinAndMTLS(t *testing.T) {
	srvCertPEM, _, srvCert := mkSelfSigned(t, "edge-transport", []net.IP{net.ParseIP("127.0.0.1")})
	cliCertPEM, cliKeyPEM, _ := mkSelfSigned(t, "device-001", nil)
	otherCertPEM, _, _ := mkSelfSigned(t, "imposter", []net.IP{net.ParseIP("127.0.0.1")})

	cliPool := x509.NewCertPool()
	cliPool.AppendCertsFromPEM(cliCertPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cliPool,
		// Pin TLS 1.2 for a deterministic test: under TLS 1.3 the client Handshake() returns before the
		// server validates the client cert (mTLS failure then surfaces on first I/O, not at dial) -- still
		// fail-closed in production (the CONNECT just fails), but not handshake-deterministic for the test.
		MaxVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	url := "https://" + ln.Addr().String()

	pinFile := writeTemp(t, "pin.pem", srvCertPEM)
	cliCertFile := writeTemp(t, "cli.pem", cliCertPEM)
	cliKeyFile := writeTemp(t, "cli.key", cliKeyPEM)
	wrongPin := writeTemp(t, "wrong.pem", otherCertPEM)

	// 1. correct pin + device client cert -> handshake succeeds.
	tc, err := buildTransportConfig(url, pinFile, cliCertFile, cliKeyFile)
	if err != nil {
		t.Fatalf("buildTransportConfig: %v", err)
	}
	if !tc.enabled {
		t.Fatal("transport should be enabled")
	}
	c, err := tc.dial(3 * time.Second)
	if err != nil {
		t.Fatalf("dial with correct pin + mTLS should succeed: %v", err)
	}
	c.Close()

	// 2. wrong pin -> fail (fail-closed; must NOT fall back to system trust).
	tcBad, err := buildTransportConfig(url, wrongPin, cliCertFile, cliKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcBad.dial(3 * time.Second); err == nil {
		t.Fatal("dial with WRONG pinned CA must fail (fail-closed) but it succeeded")
	}

	// 3. no client cert while server requires mTLS -> fail.
	tcNoCli, err := buildTransportConfig(url, pinFile, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcNoCli.dial(3 * time.Second); err == nil {
		t.Fatal("dial without device client cert must fail when server requires mTLS but it succeeded")
	}
}

// TestBuildTransportConfigValidation covers the opt-in/fail-closed contract of buildTransportConfig.
func TestBuildTransportConfigValidation(t *testing.T) {
	if tc, err := buildTransportConfig("", "", "", ""); err != nil || tc.enabled {
		t.Fatalf("empty url => disabled, no error; got enabled=%v err=%v", tc.enabled, err)
	}
	if _, err := buildTransportConfig("http://h:18543", "ca.pem", "", ""); err == nil {
		t.Fatal("non-https transport url must error")
	}
	if _, err := buildTransportConfig("https://h:18543", "", "", ""); err == nil {
		t.Fatal("https transport without pinned CA must error (fail-closed)")
	}
}

// Both transport builders must report the pinned CAs. Only one of them is used by the installed service, and
// wiring the other alone would mean the readiness view silently never hears from real devices — the failure
// mode being that everything looks fine until a CA rotation strands a fleet.
func TestBothTransportBuildersExposePinnedCAFingerprints(t *testing.T) {
	caPEM, _, _ := mkSelfSigned(t, "pin test CA", nil)

	fromPEM, err := buildTransportConfigFromPEM("https://edge.example.com:18543", caPEM, nil, nil)
	if err != nil {
		t.Fatalf("buildTransportConfigFromPEM: %v", err)
	}
	if got := fromPEM.pinnedCAFingerprints(); len(got) != 1 || len(got[0]) != 64 {
		t.Fatalf("in-memory builder reported %v, want one 64-char SHA-256", got)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := buildTransportConfig("https://edge.example.com:18543", caPath, "", "")
	if err != nil {
		t.Fatalf("buildTransportConfig: %v", err)
	}
	if got := fromFile.pinnedCAFingerprints(); len(got) != 1 || got[0] != fromPEM.pinnedCAFingerprints()[0] {
		t.Fatalf("the flag-based builder — the one the installed service uses — reported %v, want the same "+
			"fingerprint as the in-memory builder", got)
	}
}

// A bundle is the normal state mid-rotation: both the outgoing and incoming CA are pinned, and both must be
// reported or the readiness view cannot tell that this device is ready.
func TestPinnedCAFingerprintsCoverAWholeBundle(t *testing.T) {
	first, _, _ := mkSelfSigned(t, "outgoing CA", nil)
	second, _, _ := mkSelfSigned(t, "incoming CA", nil)
	bundle := append(append([]byte{}, first...), second...)

	tc, err := buildTransportConfigFromPEM("https://edge.example.com:18543", bundle, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got := tc.pinnedCAFingerprints()
	if len(got) != 2 {
		t.Fatalf("reported %d fingerprint(s) for a two-CA bundle (%v) — a device mid-rotation would look like "+
			"it had not picked up the new CA", len(got), got)
	}
	if got[0] == got[1] {
		t.Fatal("the two CAs produced the same fingerprint")
	}
}

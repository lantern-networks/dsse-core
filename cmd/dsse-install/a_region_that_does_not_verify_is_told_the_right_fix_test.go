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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 2026-11-07, three-region acceptance rerun: -verify run a minute after the last region started failed with EOF,
// and told the operator to re-issue that region's certificates with -add-host. A minute later it passed with
// nothing changed. Each failure gets the fix for that failure, from errors a real handshake produces.
func dialAsADevice(t *testing.T, addr, name string, pool *x509.CertPool) error {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr,
		&tls.Config{ServerName: name, RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err == nil {
		conn.Close()
	}
	return err
}

func TestARegionThatDoesNotVerifyIsToldTheFixForWhatHappened(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	addr := server.Listener.Addr().String()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	// A name the certificate does not carry: -add-host is the fix.
	err := dialAsADevice(t, addr, "agents.region-c.example.test", pool)
	if err == nil {
		t.Fatal("a certificate without that name verified")
	}
	if hint := whatToDoWhenARegionDoesNotVerify(err, "agents.region-c.example.test"); !strings.Contains(hint, "-add-host agents.region-c.example.test") {
		t.Errorf("a name the certificate does not carry was not sent to -add-host: %s", hint)
	}

	// A certificate from another authority: not a name problem.
	err = dialAsADevice(t, addr, "example.com", x509.NewCertPool())
	if err == nil {
		t.Fatal("a certificate from another authority verified")
	}
	if hint := whatToDoWhenARegionDoesNotVerify(err, "example.com"); strings.Contains(hint, "-add-host") || !strings.Contains(hint, "anchor") {
		t.Errorf("a certificate from another authority was given the wrong fix: %s", hint)
	}

	// A door that accepts and closes before any handshake — a region that has not finished starting.
	closing, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer closing.Close()
	go func() {
		for {
			c, aerr := closing.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()
	err = dialAsADevice(t, closing.Addr().String(), "agents.region-c.example.test", pool)
	if err == nil {
		t.Fatal("a door that closes at once completed a handshake")
	}
	if hint := whatToDoWhenARegionDoesNotVerify(err, "agents.region-c.example.test"); strings.Contains(hint, "-add-host") || !strings.Contains(hint, "run -verify again") {
		t.Errorf("a door that is not answering yet was sent to re-issue certificates (%v): %s", err, hint)
	}
}

// Review of 2026-11-07, R5: a certificate from this deployment's own authority, carrying the right name, that is
// expired or not yet valid was sent to check the anchor. It is a date problem, and the hint says so.
func TestAnExpiredCertificateIsNotCalledAnotherAuthority(t *testing.T) {
	for _, c := range []struct {
		name             string
		notBefore, after time.Time
	}{
		{"expired", time.Now().Add(-48 * time.Hour), time.Now().Add(-24 * time.Hour)},
		{"not yet valid", time.Now().Add(24 * time.Hour), time.Now().Add(48 * time.Hour)},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agents.region-c.example.test"},
				DNSNames: []string{"agents.region-c.example.test"}, NotBefore: c.notBefore, NotAfter: c.after,
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true, IsCA: true,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(der)
			pool := x509.NewCertPool()
			pool.AddCert(leaf)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, aerr := listener.Accept()
					if aerr != nil {
						return
					}
					go func() { _ = conn.(*tls.Conn).Handshake(); conn.Close() }()
				}
			}()
			err = dialAsADevice(t, listener.Addr().String(), "agents.region-c.example.test", pool)
			if err == nil {
				t.Fatal("a certificate outside its dates verified")
			}
			hint := whatToDoWhenARegionDoesNotVerify(err, "agents.region-c.example.test")
			if strings.Contains(hint, "anchor") || strings.Contains(hint, "-add-host") || !strings.Contains(hint, "clock") {
				t.Errorf("a %s certificate was given the wrong fix (%v): %s", c.name, err, hint)
			}
		})
	}
}

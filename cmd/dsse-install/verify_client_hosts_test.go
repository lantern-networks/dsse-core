package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

type clientProbeConn struct {
	net.Conn
	peer net.Addr
}

func (c clientProbeConn) RemoteAddr() net.Addr { return c.peer }

func clientProbeCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, roots
}

func TestClientProbeMeasuresPresentedCertificateAndRefusesWrongNamesOrRoots(t *testing.T) {
	for _, tc := range []struct {
		name, certName string
		trust, want    bool
	}{
		{"correct", "portal-b.example.test", true, true},
		{"wrong presented name", "portal-a.example.test", true, false},
		{"unknown issuer", "portal-b.example.test", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := clientProbeCertificate(t, tc.certName)
			if !tc.trust {
				roots = x509.NewCertPool()
			}
			entry := clientHostEntry{Name: "portal-b.example.test", IP: net.ParseIP("203.0.113.42")}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var dialed string
			var served = make(chan struct{})
			dial := func(_ context.Context, network, address string) (net.Conn, error) {
				dialed = address
				a, b := net.Pipe() // Real TLS exchange, without forbidden listener sockets.
				_ = b.SetDeadline(time.Now().Add(3 * time.Second))
				go func() {
					defer close(served)
					defer b.Close()
					server := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true})
					_ = server.Handshake()
				}()
				return clientProbeConn{Conn: a, peer: &net.TCPAddr{IP: entry.IP, Port: 443}}, nil
			}
			resolve := func(_ context.Context, name string) ([]net.IPAddr, error) {
				if name != entry.Name {
					t.Errorf("lookup substituted a different name")
				}
				return []net.IPAddr{{IP: entry.IP}}, nil
			}
			result := probeClientHost(ctx, entry, roots, resolve, dial)
			<-served
			if dialed != "portal-b.example.test:443" {
				t.Fatalf("probe bypassed actual name resolution: %s", dialed)
			}
			if result.OK != tc.want {
				t.Fatalf("unexpected TLS result: %+v", result)
			}
			if tc.want && (result.CertificateSHA256 == "" || len(result.CertificateDNSNames) != 1 || result.CertificateDNSNames[0] != tc.certName) {
				t.Fatalf("probe did not record the actual presented certificate: %+v", result)
			}
		})
	}
}

func TestClientProbeRejectsStaleHostsBeforeConnecting(t *testing.T) {
	entry := clientHostEntry{Name: "admin.example.test", IP: net.ParseIP("203.0.113.42")}
	resolve := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.99")}}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("stale name reached a server")
		return nil, nil
	}
	result := probeClientHost(context.Background(), entry, x509.NewCertPool(), resolve, dial)
	if result.OK || result.Error == "" {
		t.Fatal("stale hosts mapping accepted")
	}
}

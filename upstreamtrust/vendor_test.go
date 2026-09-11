package upstreamtrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func issue(t *testing.T, template, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestScopedTransportFullTLSVerification(t *testing.T) {
	now := time.Now()
	root, key := issue(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Vendor test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	for _, kind := range []string{"valid", "wrong-name", "expired-leaf", "expired-issuer", "foreign-root", "client-only", "callback-refusal"} {
		t.Run(kind, func(t *testing.T) {
			parent, signer := root, key
			if kind == "expired-issuer" || kind == "foreign-root" {
				tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: kind}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
				if kind == "expired-issuer" {
					tmpl.NotAfter = now.Add(-time.Minute)
					parent, signer = issue(t, tmpl, root, key)
				} else {
					parent, signer = issue(t, tmpl, nil, nil)
				}
			}
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"service.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if kind == "wrong-name" {
				tmpl.DNSNames = []string{"other.example"}
			}
			if kind == "expired-leaf" {
				tmpl.NotAfter = now.Add(-time.Minute)
			}
			if kind == "client-only" {
				tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			leaf, leafKey := issue(t, tmpl, parent, signer)
			var calls atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, parent.Raw}, PrivateKey: leafKey}}}
			server.StartTLS()
			defer server.Close()
			base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}
			if kind == "callback-refusal" {
				base.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error { return errors.New("additional operator check refused") }
			}
			rt, err := scopedTransport(base, "service.example", root)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.transport.CloseIdleConnections()
			if base.TLSClientConfig.RootCAs.Equal(rt.transport.TLSClientConfig.RootCAs) {
				t.Fatal("base pool was mutated")
			}
			if rt.transport.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("standard verification disabled")
			}
			client := &http.Client{Transport: rt, Timeout: 3 * time.Second}
			resp, err := client.Get("https://service.example/")
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 204 || calls.Load() != 1 {
					t.Fatal("no real HTTP success")
				}
			} else {
				if err == nil {
					resp.Body.Close()
					t.Fatal("invalid TLS was accepted")
				}
				if calls.Load() != 0 {
					t.Fatal("request reached unverified origin")
				}
			}
			// A transport selected for this service cannot be reused by a redirect or another caller.
			for _, url := range []string{"https://other.example/", "http://service.example/"} {
				if resp, err := client.Get(url); err == nil {
					resp.Body.Close()
					t.Fatal("scope escaped: " + url)
				}
			}
		})
	}
}

func TestVendorDestinationAndAnchorIsolation(t *testing.T) {
	base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}, ForceAttemptHTTP2: true}
	for host, rootName := range serviceRoots {
		rt, ok := ForHost(base, host).(*hostTransport)
		if !ok {
			t.Fatal(host)
		}
		defer rt.transport.CloseIdleConnections()
		if rt != ForHost(base, host) {
			t.Fatal("connection pool is not reused")
		}
		if !rt.transport.ForceAttemptHTTP2 {
			t.Fatal("HTTP/2 configuration lost")
		}
		for name, root := range roots {
			_, err := root.Verify(x509.VerifyOptions{Roots: rt.transport.TLSClientConfig.RootCAs, CurrentTime: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if (err == nil) != (name == rootName) {
				t.Fatalf("%s trusts wrong root %s: %v", host, name, err)
			}
		}
	}
	for _, host := range []string{"apple.com", "www.microsoft.com", "init.ess.apple.com.evil.example", "evilinit.ess.apple.com", "init.ess.apple.com.", "127.0.0.1", "api.anthropic.com"} {
		if ForHost(base, host) != base {
			t.Fatal("unexpected trust expansion: " + host)
		}
	}
	if len(base.TLSClientConfig.RootCAs.Subjects()) != 0 {
		t.Fatal("shared roots modified")
	}
	custom := base.Clone()
	custom.TLSClientConfig.ServerName = "other.example"
	if ForHost(custom, "init.ess.apple.com") != custom {
		t.Fatal("explicit verification name overridden")
	}
	custom = base.Clone()
	custom.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("custom") }
	if ForHost(custom, "init.ess.apple.com") != custom {
		t.Fatal("custom TLS dialer replaced")
	}
}

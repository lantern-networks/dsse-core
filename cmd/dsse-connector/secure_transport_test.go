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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSigned writes a self-signed EC cert + key PEM pair to dir and returns their paths.
func writeSelfSigned(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestBuildConnectorTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeSelfSigned(t, dir, "edge-ca")
	clientCert, clientKey := writeSelfSigned(t, dir, "connector-identity")

	t.Run("no CA outside lab is mandatory error", func(t *testing.T) {
		if _, err := buildConnectorTLSConfig(connectorTransportConfig{DevMode: false}); err == nil {
			t.Fatal("expected error: transport TLS is mandatory outside lab mode")
		}
	})

	t.Run("no CA in lab is plaintext (nil)", func(t *testing.T) {
		cfg, err := buildConnectorTLSConfig(connectorTransportConfig{DevMode: true})
		if err != nil || cfg != nil {
			t.Fatalf("expected (nil,nil) in lab without CA, got cfg=%v err=%v", cfg, err)
		}
	})

	t.Run("CA pinned + mTLS identity yields RootCAs + client cert", func(t *testing.T) {
		cfg, err := buildConnectorTLSConfig(connectorTransportConfig{
			EdgeCAFile: caPath, ClientCertFile: clientCert, ClientKeyFile: clientKey,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil || cfg.RootCAs == nil {
			t.Fatal("expected RootCAs pinned")
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("expected 1 client certificate (mTLS), got %d", len(cfg.Certificates))
		}
	})

	t.Run("CA pinned without client cert is mandatory error outside lab", func(t *testing.T) {
		if _, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: caPath, DevMode: false}); err == nil {
			t.Fatal("expected error: mTLS client cert mandatory outside lab")
		}
	})

	t.Run("CA pinned without client cert is allowed in lab (server-auth only)", func(t *testing.T) {
		cfg, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: caPath, DevMode: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil || cfg.RootCAs == nil || len(cfg.Certificates) != 0 {
			t.Fatalf("expected pinned RootCAs and no client cert in lab, got %+v", cfg)
		}
	})

	t.Run("half identity (cert only) is an error", func(t *testing.T) {
		if _, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: caPath, ClientCertFile: clientCert, DevMode: true}); err == nil {
			t.Fatal("expected error: both cert and key required")
		}
	})

	t.Run("unreadable CA is an error", func(t *testing.T) {
		if _, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: filepath.Join(dir, "missing.pem")}); err == nil {
			t.Fatal("expected error: unreadable CA")
		}
	})
}

// startEdgeTLSServer serves HTTPS with the given server certificate, standing in for the Edge's
// connector-facing listener during a rotation.
func startEdgeTLSServer(t *testing.T, certPath, keyPath string) *httptest.Server {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestAnchorOverlayRotation proves the property the whole rotation design rests on: an anchor file
// holding old+new verifies an Edge presenting EITHER certificate, so an operator can overlay the new
// anchor, switch the Edge's certificate, and withdraw the old anchor — in that order — with the tunnel
// never failing to verify. The control case shows the pin still pins: an anchor file without the new
// certificate rejects it.
func TestAnchorOverlayRotation(t *testing.T) {
	dir := t.TempDir()
	oldCert, oldKey := writeSelfSigned(t, dir, "edge-old")
	newCert, newKey := writeSelfSigned(t, dir, "edge-new")

	oldPEM, err := os.ReadFile(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	newPEM, err := os.ReadFile(newCert)
	if err != nil {
		t.Fatal(err)
	}
	anchorsPath := filepath.Join(dir, "anchors.pem")
	if err := os.WriteFile(anchorsPath, append(append([]byte{}, oldPEM...), newPEM...), 0o600); err != nil {
		t.Fatal(err)
	}

	overlayCfg, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: anchorsPath, DevMode: true})
	if err != nil {
		t.Fatalf("build overlay config: %v", err)
	}
	overlayClient := newConnectorEdgeHTTPClient(overlayCfg)

	for _, step := range []struct {
		phase             string
		certPath, keyPath string
	}{
		{"before the switch (Edge presents the old certificate)", oldCert, oldKey},
		{"after the switch (Edge presents the new certificate)", newCert, newKey},
	} {
		srv := startEdgeTLSServer(t, step.certPath, step.keyPath)
		resp, err := overlayClient.Get(srv.URL)
		if err != nil {
			t.Fatalf("overlay anchors must verify %s: %v", step.phase, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status %s: %d", step.phase, resp.StatusCode)
		}
	}

	// Control: a pin without the new certificate must REJECT it — the overlay widened trust to
	// exactly the staged anchors, not to anything else.
	oldOnlyCfg, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: oldCert, DevMode: true})
	if err != nil {
		t.Fatalf("build old-only config: %v", err)
	}
	srv := startEdgeTLSServer(t, newCert, newKey)
	if resp, err := newConnectorEdgeHTTPClient(oldOnlyCfg).Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("old-only anchors verified the new certificate: the pin is not pinning")
	}
}

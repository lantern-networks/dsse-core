package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestSecureTransportConfigEnabled(t *testing.T) {
	if (secureTransportConfig{}).enabled() {
		t.Fatalf("empty listen addr should be disabled")
	}
	if !(secureTransportConfig{ListenAddr: ":18443"}).enabled() {
		t.Fatalf("non-empty listen addr should be enabled")
	}
}

func TestGenerateSelfSignedTransportCertHasLoopbackSANs(t *testing.T) {
	cert, pemBytes, err := generateSelfSignedTransportCert(secureTransportCertHosts(":18443"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pemBytes) == 0 || len(cert.Certificate) == 0 {
		t.Fatalf("expected a non-empty cert + PEM")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	hasLoopbackIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.IsLoopback() {
			hasLoopbackIP = true
		}
	}
	if !hasLoopbackIP {
		t.Fatalf("expected a loopback IP SAN, got %v", leaf.IPAddresses)
	}
	hasLocalhost := false
	for _, n := range leaf.DNSNames {
		if n == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		t.Fatalf("expected localhost DNS SAN, got %v", leaf.DNSNames)
	}
}

func TestBuildSecureTransportTLSConfigRequiresCertSource(t *testing.T) {
	// No cert/key (lab, so the mTLS guard is relaxed) -> error (never silently serve without a cert).
	if _, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: ":1", LabMode: true}); err == nil {
		t.Fatalf("expected error when no cert source is available")
	}
	// require-client-cert without a client CA -> error.
	if _, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: ":1", LabAutoCert: true, LabMode: true, RequireClientCert: true}); err == nil {
		t.Fatalf("expected error: require-client-cert needs a client CA")
	}
	// Lab auto cert -> ok, mTLS off by default.
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: ":1", LabAutoCert: true, LabMode: true})
	if err != nil {
		t.Fatalf("lab auto cert should build: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("mTLS should be off by default, got %v", cfg.ClientAuth)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one server certificate")
	}
}

// mTLS is mandatory in production — a non-lab transport without a client CA + require-client-cert
// must fail to start (mTLS is not optional).
func TestProductionTransportRequiresMandatoryMTLS(t *testing.T) {
	// Non-lab, server cert provided, but no client CA / not requiring client cert -> error.
	if _, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: ":1", LabAutoCert: true}); err == nil {
		t.Fatalf("production transport without mTLS must be rejected")
	}
	// Non-lab, client CA present but require-client-cert false -> still error (mandatory, not opt-in).
	if _, err := buildSecureTransportTLSConfig(secureTransportConfig{ListenAddr: ":1", LabAutoCert: true, ClientCAFile: "/nonexistent-ca.pem"}); err == nil {
		t.Fatalf("production transport with optional (non-required) client cert must be rejected")
	}
}

func TestStartSecureTransportListenerDisabledReturnsNil(t *testing.T) {
	ln, err := startSecureTransportListener(secureTransportConfig{}, http.NewServeMux())
	if err != nil || ln != nil {
		t.Fatalf("disabled transport should return (nil,nil), got ln=%v err=%v", ln, err)
	}
}

func TestStartSecureTransportListenerServesOverTLS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	// Bind an ephemeral port via :0 by pre-listening to discover it, then close and reuse the addr.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ln, err := startSecureTransportListener(secureTransportConfig{ListenAddr: addr, LabAutoCert: true, LabMode: true}, mux)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if ln == nil {
		t.Fatalf("expected a listener")
	}
	defer ln.Close()

	// A plaintext HTTP client must NOT receive a valid 200 "ok" from the TLS listener (proves it is
	// encrypted, not plaintext). An error or a non-ok response both satisfy this.
	if presp, perr := (&http.Client{}).Get("http://" + addr + "/healthz"); perr == nil {
		pbody, _ := io.ReadAll(presp.Body)
		presp.Body.Close()
		if presp.StatusCode == http.StatusOK && strings.TrimSpace(string(pbody)) == "ok" {
			t.Fatalf("plaintext request was served by the TLS transport listener (not encrypted)")
		}
	}

	// A TLS client (skipping verification for the lab self-signed cert) succeeds.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("TLS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("unexpected TLS response: status=%d body=%q", resp.StatusCode, string(body))
	}
}

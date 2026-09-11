package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// These are real HTTP/TLS failures against the production fetcher, followed by
// new handshakes against the production SNI selector. No clock is advanced and
// no running deployment is touched. OS adoption and expiry remain separate gates.
func TestPKIMaterialFaultKeepsVerifiedDoorAndRecovers(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	const tenant, name = "tenant_fault_recovery", "fault-recovery.dsse.invalid"
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, time.Now)
	if _, err := authority.EnsureCA(tenant, name); err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	var mode atomic.Value
	mode.Store("healthy")
	generation := uint64(0)
	var material tenantTransportMaterial
	publish := func(t *testing.T) {
		t.Helper()
		var err error
		material, err = authority.IssueFor(tenant, "fault-test", 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		generation++
		encoded, err := json.Marshal(map[string]any{"materials": []tenantTransportMaterial{material}, "generation": generation})
		if err != nil {
			t.Fatal(err)
		}
		body.Store(encoded)
	}
	publish(t)
	bad := material
	bad.CertPEM = "not a certificate"
	badBody, err := json.Marshal(map[string]any{"materials": []tenantTransportMaterial{bad}, "generation": 999})
	if err != nil {
		t.Fatal(err)
	}
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-edge-material" || r.Header.Get("Authorization") != "Bearer fault-test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch mode.Load().(string) {
		case "eof":
			panic(http.ErrAbortHandler)
		case "timeout":
			select {
			case <-r.Context().Done():
			case <-time.After(1500 * time.Millisecond):
			}
			return
		case "503":
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		case "malformed200":
			_, _ = w.Write([]byte(`{"materials":`))
			return
		case "unanswered200":
			_ = json.NewEncoder(w).Encode(map[string]any{"generation": 999, "refused": []string{tenant + ": " + authorityNotAskedPhrase}})
			return
		case "invalid_material200":
			_, _ = w.Write(badBody)
			return
		}
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer cp.Close()
	config := cp.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	fetcher := newTenantTransportMaterialFetcher(cp.URL, "fault-test-token", config, func() []string { return []string{tenant} })
	fetcher.dataURL = func() string { return "" }
	fetcher.log = t.Logf
	fetcher.client.Timeout = 500 * time.Millisecond
	defer fetcher.client.CloseIdleConnections()
	if _, err := fetcher.FetchOnce(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(material.AnchorPEM)) {
		t.Fatal("missing tenant anchor")
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		GetCertificate: transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, fmt.Errorf("no shared fallback") })})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), ReadHeaderTimeout: time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	probe := func(t *testing.T) string {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: name})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	for _, fault := range []string{"eof", "timeout", "503", "malformed200", "unanswered200", "invalid_material200"} {
		t.Run(fault, func(t *testing.T) {
			before := probe(t)
			heldGeneration, heldExpiry := fetcher.generation, fetcher.expiry
			mode.Store(fault)
			if _, err := fetcher.FetchOnce(); err == nil {
				t.Fatal("fault was reported as a successful fetch")
			}
			if fetcher.generation != heldGeneration || !fetcher.expiry.Equal(heldExpiry) {
				t.Fatal("failed fetch advanced the adopted generation or changed its deadline")
			}
			if got := probe(t); got != before {
				t.Fatal("failed fetch replaced the still-valid certificate")
			}
			publish(t)
			mode.Store("healthy")
			if _, err := fetcher.FetchOnce(); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if fetcher.generation != generation {
				t.Fatal("successful recovery did not adopt the new generation")
			}
			if got := probe(t); got == before {
				t.Fatal("recovery did not put fresh material onto a real TLS connection")
			}
		})
	}
}

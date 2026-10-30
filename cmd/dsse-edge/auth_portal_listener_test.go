package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestBrowserPortalDoesNotRequestPrivateKeyAndCannotReachAgentRoutes(t *testing.T) {
	previous := stepUpPortalCert.Load()
	previousPool, previousAdmission := edgeClientCAs.Load(), agentDoorAdmission
	t.Cleanup(func() {
		stepUpPortalCert.Store(previous)
		edgeClientCAs.Store(previousPool)
		agentDoorAdmission = previousAdmission
	})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "portal.crt"), filepath.Join(dir, "portal.key")
	writeSelfSignedFor(t, "portal.test", certPath, keyPath)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	stepUpPortalCert.Store(&stepUpPortalCertificate{host: "portal.test", cert: &pair})
	edgeClientCAs.Store(pool)
	agentDoorAdmission = func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 {
			return fmt.Errorf("endpoint identity required")
		}
		return nil
	}
	for _, listener := range []string{"main", "transport"} {
		t.Run(listener, func(t *testing.T) {
			base := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
				ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: agentDoorAdmission}
			config := mainEdgeListenerClientTLSConfig(base, "agent-plane")
			if listener == "transport" {
				config = attachConnRegistryTracking(base, newTransportConnRegistry())
			}
			called := 0
			srv := httptest.NewUnstartedServer(renewalRecoveryAwareHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called++
				w.WriteHeader(http.StatusNoContent)
			})))
			srv.TLS = config
			srv.StartTLS()
			defer srv.Close()
			certificateRequests := 0
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "portal.test",
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					certificateRequests++
					return &tls.Certificate{}, fmt.Errorf("browser keychain must not be opened")
				}}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			for _, tc := range []struct {
				method, path, host string
				want               int
			}{
				{"GET", "/clientless/auth/start", "portal.test", 204},
				{"POST", "/clientless/auth/start", "portal.test", 204},
				{"GET", "/clientless/auth/callback", "portal.test:443", 204},
				{"POST", "/clientless/auth/retry", "portal.test", 204},
				{"GET", "/clientless/auth/whoami", "portal.test", 204},
				{"GET", "/admin/grants", "portal.test", 404},
				{"GET", "/admin/authentication-grants", "portal.test", 404},
				{"POST", "/steer/mux", "portal.test", 404},
				{"GET", "/clientless/auth/../admin/grants", "portal.test", 404},
				{"GET", "/clientless/auth/%73tart", "portal.test", 404},
				{"GET", "/clientless/auth/start", "agents.test", 421},
			} {
				req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
				req.Host = tc.host
				res, err := client.Do(req)
				if err != nil {
					t.Fatalf("browser TLS request failed: %v", err)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode != tc.want {
					t.Errorf("%s %s: got %d want %d", tc.method, tc.path, res.StatusCode, tc.want)
				}
			}
			if certificateRequests != 0 || called != 5 {
				t.Fatalf("keychain requests=%d allowed dispatches=%d", certificateRequests, called)
			}
			// Asking for another SNI must keep the endpoint admission checks.
			other, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "agents.test"})
			if err != nil || other.ClientAuth == tls.NoClientCert || other.VerifyConnection == nil {
				t.Fatal("browser lane changed the agent TLS admission")
			}
		})
	}
}

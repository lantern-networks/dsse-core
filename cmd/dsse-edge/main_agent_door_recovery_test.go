package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/lantern-networks/dsse-core/revocation"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMainAgentDoorRecoveryHandshakeAndDispatch(t *testing.T) {
	ca, caKey, pool := graceTestCA(t)
	issue := func(cn string, expiry time.Time, server bool, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"agent.test", "recovery.test", "enrol.test"}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverCert := issue("agent.test", time.Now().Add(time.Hour), true, ca, caKey)
	expired := issue("holiday-laptop", time.Now().Add(-time.Minute), false, ca, caKey)
	live := issue("holiday-laptop", time.Now().Add(time.Hour), false, ca, caKey)
	foreignCA, foreignKey, _ := graceTestCA(t)
	foreign := issue("holiday-laptop", time.Now().Add(-time.Minute), false, foreignCA, foreignKey)
	cfg, ledger := graceTestConfig(t, 24*time.Hour)
	if _, err := ledger.Enroll("revoked-laptop", "tenant_test", "test", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cfg.Revocations = revocation.NewAdmissionRevocations()
	cfg.Revocations.Revoke("revoked-laptop", "test revocation")
	revoked := issue("revoked-laptop", time.Now().Add(-time.Minute), false, ca, caKey)
	unknown := issue("unknown-laptop", time.Now().Add(-time.Minute), false, ca, caKey)
	previousTransportPool := transportClientCAPool.Load()
	transportClientCAPool.Store(pool)
	t.Cleanup(func() { transportClientCAPool.Store(previousTransportPool) })
	previousRecovery, previousEnrol, previousPool, previousAdmission := renewalRecoveryMainPort.Load(), enrolmentTransportPort.Load(), edgeClientCAs.Load(), agentDoorAdmission
	t.Cleanup(func() {
		renewalRecoveryMainPort.Store(previousRecovery)
		enrolmentTransportPort.Store(previousEnrol)
		edgeClientCAs.Store(previousPool)
		agentDoorAdmission = previousAdmission
	})
	recovery := http.NewServeMux()
	recovery.HandleFunc("POST /enroll/renew", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	renewalRecoveryMainPort.Store(&renewalRecoveryOnMainPort{sni: "recovery.test", mux: recovery, verify: enrollRenewGraceVerify(cfg, pool)})
	enrolmentTransportPort.Store(&enrolmentOnTransportPort{sni: "enrol.test"})
	edgeClientCAs.Store(pool)
	agentDoorAdmission = nil
	normal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/enroll" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if _, ok := transportDeviceIdentityFromRequest(r); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	for _, door := range []string{"agent-plane", "admin"} {
		t.Run(door, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(mainEdgeListenerHandlerForDoor(door, normal))
			srv.TLS = mainEdgeListenerClientTLSConfig(&tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}, door)
			srv.StartTLS()
			defer srv.Close()
			cases := []struct {
				name, sni, path string
				cert            *tls.Certificate
				want            int
			}{
				{"expired_recovery", "recovery.test", "/enroll/renew", &expired, 204},
				{"expired_normal", "agent.test", "/steer", &expired, 0},
				{"live_normal", "agent.test", "/steer", &live, 200},
				{"foreign_recovery", "recovery.test", "/enroll/renew", &foreign, 0},
				{"revoked_recovery", "recovery.test", "/enroll/renew", &revoked, 0},
				{"unknown_recovery", "recovery.test", "/enroll/renew", &unknown, 0},
				{"anonymous_recovery", "recovery.test", "/enroll/renew", nil, 0},
				{"recovery_cannot_steer", "recovery.test", "/steer", &expired, 404},
				{"enroll_without_identity", "enrol.test", "/enroll", nil, 201},
				{"enroll_cannot_steer", "enrol.test", "/steer", nil, 404},
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					tc := &tls.Config{RootCAs: pool, ServerName: tt.sni, MinVersion: tls.VersionTLS12}
					if tt.cert != nil {
						tc.Certificates = []tls.Certificate{*tt.cert}
						tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return tt.cert, nil }
					}
					tr := &http.Transport{TLSClientConfig: tc}
					defer tr.CloseIdleConnections()
					client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
					resp, err := client.Post(srv.URL+tt.path, "application/json", nil)
					want := tt.want
					if door == "admin" {
						if tt.cert == &expired || tt.cert == &foreign {
							want = 0
						}
						if tt.name == "anonymous_recovery" || tt.name == "enroll_cannot_steer" {
							want = 401
						}
					}
					if want == 0 {
						if err == nil {
							resp.Body.Close()
							t.Fatalf("unverifiable certificate was accepted: %d", resp.StatusCode)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != want {
						t.Fatalf("status=%d want=%d", resp.StatusCode, want)
					}
				})
			}
		})
	}
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
)

func TestAuthRolloutRealMTLSAllCPAndEdgeMembers(t *testing.T) {
	oldSelector, oldData := controlChannelSelector.Load(), cpDataEndpoints.Load()
	controlChannelSelector.Store(nil)
	t.Cleanup(func() { controlChannelSelector.Store(oldSelector); cpDataEndpoints.Store(oldData) })
	runtime, m := rolloutFixture(t)
	m.Members = nil
	ca, caKey, _ := testAdmissionCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pairs := []tls.Certificate{}
	for i := 0; i < 9; i++ {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(10 + i)), Subject: pkix.Name{CommonName: fmt.Sprint("member-", i)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		pair := tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
		pairs = append(pairs, pair)
		sum := sha256.Sum256(der)
		role := "edge"
		if i < 3 {
			role = "cp"
		}
		m.Members = append(m.Members, authrollout.Member{ID: fmt.Sprint(i), Role: role, Version: "awaiting-first-report", CertificateSHA256: hex.EncodeToString(sum[:])})
	}
	if e := runtime.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	registerAuthRolloutRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, runtime)
	server := httptest.NewUnstartedServer(dataPlaneOnlyMiddleware(mux))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	trust := server.Client().Transport.(*http.Transport).TLSClientConfig
	for i, n := range m.Members {
		tc := trust.Clone()
		tc.Certificates = []tls.Certificate{pairs[i]}
		reporter, e := authRolloutReporterFor(m, authRolloutEndpoint(server.URL), tc, n.Role)
		if e != nil {
			t.Fatal(e)
		}
		reporter.ceremonyRecoveryReady = i == 3
		if e = reporter.report(context.Background()); e != nil {
			t.Fatal(e)
		}
		reporter.client.CloseIdleConnections()
		state, e := runtime.authority.Read()
		if e != nil {
			t.Fatal(e)
		}
		if state.Complete != (i == 8) {
			t.Fatalf("completion after %d of 9 members: %t", i+1, state.Complete)
		}
		advertised := false
		for _, feature := range state.Observed[n.ID].Features {
			advertised = advertised || feature == authrollout.CeremonyRecoveryFeature
		}
		if advertised != (i == 3) {
			t.Fatal("ceremony recovery advertised without its shared-key capability")
		}
	}
	if runtime.authority.Activate(context.Background(), m.Generation, []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.CeremonyRecoveryFeature}, time.Now()) == nil {
		t.Fatal("one capable Edge incorrectly enabled fleet ceremony recovery")
	}
	// The same verified CA is insufficient: another member's leaf cannot submit
	// this member's report, even after every member supports the feature.
	tc := trust.Clone()
	tc.Certificates = []tls.Certificate{pairs[0]}
	reporter, e := authRolloutReporterFor(m, authRolloutEndpoint(server.URL), tc, "cp")
	if e != nil {
		t.Fatal(e)
	}
	// Losing the original CP address must use the existing leader selector,
	// preserving this reporter's individual TLS identity at the new target.
	reporter.url = "https://127.0.0.1:1/fleet-capabilities/report"
	endpoints := map[string]string{"promoted": server.URL}
	cpDataEndpoints.Store(&endpoints)
	controlChannelSelector.Store(&cpEndpointSelector{currentRegion: "promoted"})
	if e = reporter.report(context.Background()); e != nil {
		t.Fatal("report did not follow CP promotion:", e)
	}
	reporter.member = m.Members[8]
	if reporter.report(context.Background()) == nil {
		t.Fatal("member certificate could impersonate a different node")
	}
	reporter.client.CloseIdleConnections()
}

func TestAuthRolloutReporterUsesHandshakeIdentity(t *testing.T) {
	_, manifest := rolloutFixture(t)
	pair := tls.Certificate{Certificate: [][]byte{[]byte("individual-test-leaf")}}
	pin := sha256.Sum256(pair.Certificate[0])
	manifest.Members[0].CertificateSHA256 = hex.EncodeToString(pin[:])
	dynamic := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }}
	reporter, err := authRolloutReporterFor(manifest, "https://cp.invalid/fleet-capabilities/report", dynamic, "cp")
	if err != nil {
		t.Fatal("production callback identity rejected:", err)
	}
	if reporter.member.ID != manifest.Members[0].ID || reporter.client.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("lost individual identity or live certificate reload")
	}
	for _, tc := range []*tls.Config{
		nil,
		{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }},
		{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, fmt.Errorf("fixture") }},
		{Certificates: []tls.Certificate{pair}, GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{Certificate: [][]byte{[]byte("other")}}, nil
		}},
	} {
		if _, err := authRolloutReporterFor(manifest, "https://cp.invalid", tc, "cp"); err == nil {
			t.Fatal("missing or mismatched handshake identity accepted")
		}
	}
	if _, err := authRolloutReporterFor(manifest, "https://cp.invalid", dynamic, "edge"); err == nil {
		t.Fatal("CP identity accepted as Edge")
	}
}

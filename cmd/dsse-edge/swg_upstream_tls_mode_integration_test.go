package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swg"
)

// Exercise the complete decrypted HTTP egress handler, rather than just a TLS
// client. A selected mode must reach the actual transport without bypassing the
// tenant policy, DLP or external-route authentication gates.
func TestSWGUpstreamTLSModePreservesInspection(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "origin.example"},
		DNSNames: []string{"origin.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	var mu sync.Mutex
	var bodies []string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	origin.StartTLS()
	defer origin.Close()
	transport := &http.Transport{
		ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	bundle, _ := testNetworkExtensionLabTLSSWGPolicyBundle()
	bundle.SWGTenantRestrictionRules = nil
	bundle.DLPRules = []model.DLPRule{{ID: "dlp-upstream-tls", TenantID: bundle.TenantID, Status: "active", Identifiers: []string{"my_number"}, OnMatch: "block"}}
	allow := model.Policy{ID: "upstream-compat-allow", TenantID: bundle.TenantID, Status: "active", Priority: 1, Conditions: map[string]any{"fqdn": "origin.example"}, Action: model.PolicyAction{Decision: "allow"}}
	bundle.PolicyIDs = []string{allow.ID}
	store := policy.NewStore([]model.Policy{allow})
	if err := store.SetRuntimeStatePath(t.TempDir() + "/policy.json"); err != nil {
		t.Fatal(err)
	}
	runtime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{PolicyBundle: bundle, RuntimeTLSDecryptionObserved: true, MacCATrustObserved: true})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := edgeSWGHTTPEgressHandlerConfig{
		Evaluator:   decision.Evaluator{Policies: []model.Policy{allow}, PolicyBundle: bundle, EdgeRegionID: "local", EdgeClusterID: "local-edge"},
		PolicyStore: store, ProxyClient: &http.Client{Transport: transport, Timeout: 3 * time.Second},
		Writer: writer, Registry: connector.NewRegistry(), SWGRuntime: runtime,
		DecisionStore: newAccessDecisionStore(), InspectionEvents: newInspectionEventStore(), DeviceAuthenticatedInProcess: true,
	}
	send := func(config edgeSWGHTTPEgressHandlerConfig, body string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(body))
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://origin.example/upload")
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressNERuntimeHeader, "true")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(config).ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("response=%d, want %d: %s", rec.Code, want, rec.Body.String())
		}
	}
	// No organization setting: the default is browser compatible, so a site that
	// accepts only RSA key exchange opens, exactly once.
	send(cfg, `{"note":"default opens"}`, http.StatusOK)
	mu.Lock()
	if len(bodies) != 1 || bodies[0] != `{"note":"default opens"}` {
		t.Errorf("unexpected forwarded requests: %q", bodies)
	}
	mu.Unlock()
	send(cfg, `{"my_number":"123456789018"}`, http.StatusForbidden)
	mu.Lock()
	for _, body := range bodies {
		if strings.Contains(body, "123456789018") {
			t.Error("compatibility leaked DLP-blocked content")
		}
	}
	mu.Unlock()
	external := cfg
	external.DeviceAuthenticatedInProcess = false
	send(external, `{"note":"unauthenticated"}`, http.StatusUnauthorized)
	deny := allow
	deny.Action.Decision = "deny"
	denied := cfg
	denied.PolicyStore = policy.NewStore([]model.Policy{deny})
	if err := denied.PolicyStore.(*policy.Store).SetRuntimeStatePath(t.TempDir() + "/policy.json"); err != nil {
		t.Fatal(err)
	}
	send(denied, `{"note":"policy denied"}`, http.StatusForbidden)
	// An organization that chose strict is refused, and nothing reaches the site.
	if err := store.SetUpstreamTLSModeConfirmed(bundle.TenantID, "strict"); err != nil {
		t.Fatal(err)
	}
	send(cfg, `{"note":"strict refuses"}`, http.StatusBadGateway)
	if err := store.SetUpstreamTLSModeConfirmed(bundle.TenantID, "browser_compatible"); err != nil {
		t.Fatal(err)
	}
	send(cfg, `{"note":"compatible again"}`, http.StatusOK)
	mu.Lock()
	// (The DLP-blocked upload above reaches the origin with its body cut, which
	// predates this setting; only its content is asserted absent.)
	if bodies[len(bodies)-1] != `{"note":"compatible again"}` || slices.Contains(bodies, `{"note":"strict refuses"}`) {
		t.Errorf("strict forwarded a request or compatibility did not return: %q", bodies)
	}
	mu.Unlock()
}

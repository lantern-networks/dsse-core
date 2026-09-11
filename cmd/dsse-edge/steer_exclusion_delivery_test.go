package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// leafWithCN builds a self-signed leaf whose CommonName is the device identity, to stand in for a verified
// (T) mTLS client cert.
func leafWithCN(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func steerDeliveryTestServer(t *testing.T, store *steerexclusion.Store) http.Handler {
	t.Helper()
	// ★ THE DEVICES ARE ENROLLED, BECAUSE REAL ONES ARE (2026-09-05). These tests used to reach the steering
	// routes with a device in no organization at all, and were served the NODE's — the fallback that made a
	// device belong to whoever owns the Edge. That fallback is gone, so the harness now says which
	// organization each device is in, which is what the control plane says on a real deployment.
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, id := range []string{"test-dev-1", "other-dev"} {
		if _, err := ledger.Enroll(id, "t1", "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	return newServerWithConfig(serverConfig{
		Evaluator:       decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "t1"}},
		Registry:        connector.NewRegistry(),
		AdminAuth:       newAdminAuthStore(),
		SteerExclusions: store,
		EnrolledLedger:  ledger,
	})
}

func TestAgentPolicyRequiresVerifiedIdentity(t *testing.T) {
	handler := steerDeliveryTestServer(t, steerexclusion.NewStore())
	// no TLS client cert -> must be rejected (the set is keyed to the verified identity, never leaked)
	req := httptest.NewRequest(http.MethodGet, "/steer/agent-policy", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a verified transport identity", rec.Code)
	}
}

func TestAgentPolicyReturnsResolvedExclusionsForVerifiedDevice(t *testing.T) {
	store := steerexclusion.NewStore()
	now := time.Now().UTC()
	if _, err := store.Upsert(steerexclusion.Policy{TenantID: "t1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.tenant.wide"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(steerexclusion.Policy{TenantID: "t1", ScopeType: "device", ScopeID: "test-dev-1", ExcludedAppSigningIDs: []string{"com.dev.only"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert(steerexclusion.Policy{TenantID: "t1", ScopeType: "device", ScopeID: "other-dev", ExcludedAppSigningIDs: []string{"com.someone.else"}}, now); err != nil {
		t.Fatal(err)
	}

	handler := steerDeliveryTestServer(t, store)
	cert := leafWithCN(t, "test-dev-1")
	req := httptest.NewRequest(http.MethodGet, "/steer/agent-policy", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DeviceIdentity        string   `json:"device_identity"`
		ExcludedAppSigningIDs []string `json:"excluded_app_signing_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DeviceIdentity != "test-dev-1" {
		t.Fatalf("device_identity = %q, want the cert CN", resp.DeviceIdentity)
	}
	got := map[string]bool{}
	for _, id := range resp.ExcludedAppSigningIDs {
		got[id] = true
	}
	if !got["com.tenant.wide"] || !got["com.dev.only"] {
		t.Fatalf("excluded set = %v, want tenant-wide + this device's exclusions", resp.ExcludedAppSigningIDs)
	}
	if got["com.someone.else"] {
		t.Fatalf("excluded set leaked another device's exclusion: %v", resp.ExcludedAppSigningIDs)
	}
}

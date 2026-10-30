package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

func rolloutPlanOverDeviceHTTP(t *testing.T, cache *agentRolloutCache, tenant string) bool {
	t.Helper()
	mux := http.NewServeMux()
	registerSteerAgentUpdatePlanRoutes(mux, serverConfig{
		AgentRolloutCache:  cache,
		RolloutControlPath: t.TempDir() + "/absent.json",
		PublishedUpdates:   &publishedUpdates{byTarget: map[string]publishedUpdate{}},
	}, agentUpdatePlanTenant{id: tenant})
	request := httptest.NewRequest(http.MethodGet, "/steer/agent-update-plan?platform=windows&arch=amd64", nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "device-for-" + tenant}}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	reply := httptest.NewRecorder()
	mux.ServeHTTP(reply, request)
	if reply.Code != http.StatusOK {
		t.Fatalf("plan HTTP %d for tenant %q", reply.Code, tenant)
	}
	var body struct {
		Frozen bool `json:"frozen"`
	}
	if err := json.Unmarshal(reply.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Frozen
}

func TestAgentRolloutCacheKeepsCaseDistinctTenantPlansOverDeviceHTTP(t *testing.T) {
	cache := &agentRolloutCache{}
	cache.setAll(map[string]agentrollout.AgentRolloutPlan{
		"Acme": {Frozen: true, Reason: "operator hold"},
		"acme": {Frozen: false},
	}, "Acme")
	if !rolloutPlanOverDeviceHTTP(t, cache, "Acme") {
		t.Fatal("Acme's frozen plan was replaced by case-distinct acme")
	}
	if rolloutPlanOverDeviceHTTP(t, cache, "acme") {
		t.Fatal("acme received case-distinct Acme's freeze")
	}
}

func TestAgentRolloutCompleteSnapshotRemovalHoldsDeviceOverHTTP(t *testing.T) {
	cache := &agentRolloutCache{}
	cache.setAll(map[string]agentrollout.AgentRolloutPlan{"tenant": {Frozen: false}}, "tenant")
	if rolloutPlanOverDeviceHTTP(t, cache, "tenant") {
		t.Fatal("initial explicit plan was not applied")
	}
	cache.setAll(map[string]agentrollout.AgentRolloutPlan{}, "tenant")
	if !rolloutPlanOverDeviceHTTP(t, cache, "tenant") {
		t.Fatal("a complete snapshot that no longer names the tenant reused its prior unfreeze")
	}
}

func TestFleetStatusHTTPDoesNotShowCaseDistinctTenantErasure(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	store := newFleetConfigStatusStore(time.Minute)
	store.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "cluster-a", NodeID: "node-a", HaveApplied: true,
		Erasures: []fleetTenantErasure{{TenantID: "acme", Clean: false, Remaining: 7}}}, time.Now().UTC())
	mux := http.NewServeMux()
	registerFleetConfigStatusRoutes(mux, func(_ string, handler http.HandlerFunc) http.HandlerFunc { return handler }, store,
		func() (uint64, string, error) { return 1, "epoch", nil })
	request := httptest.NewRequest(http.MethodGet, "/admin/fleet/config-status", nil)
	request = request.WithContext(context.WithValue(request.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "admin-acme", TenantID: "Acme", Roles: []string{"admin"}, AuthMethod: "admin_session"}))
	reply := httptest.NewRecorder()
	mux.ServeHTTP(reply, request)
	if reply.Code != http.StatusOK {
		t.Fatalf("fleet status HTTP %d", reply.Code)
	}
	var body struct {
		Edges []struct {
			Erasures []fleetTenantErasure `json:"erasures"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(reply.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Edges) != 1 || len(body.Edges[0].Erasures) != 0 {
		t.Fatalf("Acme saw case-distinct acme erasure: %+v", body.Edges)
	}
}

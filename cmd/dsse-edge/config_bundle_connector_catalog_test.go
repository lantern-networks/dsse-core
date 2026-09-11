package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func catalogConn(id, region string, routes []string) model.ConnectorRegistration {
	return model.ConnectorRegistration{
		ID: id, TenantID: "tenant_lab_001", Status: "active", PrivateBaseURL: "http://127.0.0.1:1",
		EdgeRegionID: region, ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: routes},
	}
}

// servedCatalogBundle mirrors the serve handler: strip secrets + fold the catalog generation.
func servedCatalogBundle(cp *connector.Registry) configBundlePayload {
	return configBundlePayload{
		Generation: cp.ConfigGeneration(),
		Connectors: &connectorCatalogBundle{Connectors: publicConnectorRegistrations(cp.List())},
	}
}

// TestConnectorCatalogFansOutToEdge proves a connector registered on the control plane appears in the served
// bundle and applies to a remote Edge's registry as a region-tagged catalog entry — the data B distributes so a
// steered flow can reach a connector that lives in another region.
func TestConnectorCatalogFansOutToEdge(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	cp := connector.NewRegistry()
	if _, err := cp.Register(catalogConn("conn-x", "region-a", []string{"app.corp"}), now); err != nil {
		t.Fatalf("cp register: %v", err)
	}

	edge := connector.NewRegistry()
	configBundleSource{tenantID: "tenant_lab_001"}.apply(servedCatalogBundle(cp), configApplyTargets{connectors: edge})

	got, ok := edge.Get("conn-x")
	if !ok {
		t.Fatal("edge registry is missing conn-x after catalog fan-out")
	}
	if got.EdgeRegionID != "region-a" {
		t.Fatalf("edge conn-x region = %q, want region-a", got.EdgeRegionID)
	}
	if len(got.ReachableRoutes.FQDNDomains) != 1 || got.ReachableRoutes.FQDNDomains[0] != "app.corp" {
		t.Fatalf("edge conn-x routes = %v, want [app.corp]", got.ReachableRoutes.FQDNDomains)
	}
	if _, leaked := got.Metadata["runtime_secret_hash"]; leaked {
		t.Fatal("runtime_secret_hash must be stripped before distribution")
	}
}

// TestConnectorCatalogApplyPreservesLocalRuntimeSecret proves the merge semantics: applying a catalog update for a
// connector that is LOCALLY connected (has a runtime secret) does not clobber that local runtime state.
func TestConnectorCatalogApplyPreservesLocalRuntimeSecret(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	edge := connector.NewRegistry()
	if _, err := edge.Register(catalogConn("conn-x", "region-a", []string{"app.corp"}), now); err != nil {
		t.Fatalf("edge register: %v", err)
	}
	if _, ok, err := edge.RotateRuntimeSecretHash("conn-x", "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"); err != nil || !ok {
		t.Fatalf("set local runtime secret: ok=%v err=%v", ok, err)
	}

	// CP distributes a catalog update (new route) — secret-stripped.
	cp := connector.NewRegistry()
	_, _ = cp.Register(catalogConn("conn-x", "region-a", []string{"app.corp", "db.corp"}), now)
	configBundleSource{tenantID: "tenant_lab_001"}.apply(servedCatalogBundle(cp), configApplyTargets{connectors: edge})

	got, _ := edge.Get("conn-x")
	if hash, _ := got.Metadata["runtime_secret_hash"].(string); hash != "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Fatalf("local runtime secret = %q, want it preserved through the catalog update", hash)
	}
	if len(got.ReachableRoutes.FQDNDomains) != 2 {
		t.Fatalf("catalog update did not apply: routes = %v", got.ReachableRoutes.FQDNDomains)
	}
}

// TestConnectorCatalogEmptyKeepsLocal proves lockout-safety: a present-but-EMPTY catalog never wipes a non-empty
// local registry.
func TestConnectorCatalogEmptyKeepsLocal(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	edge := connector.NewRegistry()
	_, _ = edge.Register(catalogConn("conn-x", "region-a", []string{"app.corp"}), now)

	empty := configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: nil}}
	configBundleSource{tenantID: "tenant_lab_001"}.apply(empty, configApplyTargets{connectors: edge})

	if _, ok := edge.Get("conn-x"); !ok {
		t.Fatal("an empty catalog must NOT wipe a non-empty local registry (lockout-safe)")
	}
}

// TestConnectorCatalogGenerationIsChurnFree proves the generation bumps on a real catalog change but NOT on a
// heartbeat — so the bundle does not re-fan (and force-reapply policies) every few seconds.
func TestConnectorCatalogGenerationIsChurnFree(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	reg := connector.NewRegistry()
	_, _ = reg.Register(catalogConn("conn-x", "region-a", []string{"app.corp"}), now)
	g1 := reg.ConfigGeneration()

	// A heartbeat must NOT bump the catalog generation.
	if _, err := reg.Heartbeat(model.ConnectorHeartbeat{ID: "conn-x"}, now.Add(time.Second)); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if reg.ConfigGeneration() != g1 {
		t.Fatalf("heartbeat bumped catalog generation %d -> %d (should be churn-free)", g1, reg.ConfigGeneration())
	}

	// Re-registering identical catalog data must NOT bump.
	_, _ = reg.Register(catalogConn("conn-x", "region-a", []string{"app.corp"}), now.Add(2*time.Second))
	if reg.ConfigGeneration() != g1 {
		t.Fatalf("no-op re-register bumped generation %d -> %d", g1, reg.ConfigGeneration())
	}

	// A real catalog change (new route) MUST bump.
	_, _ = reg.Register(catalogConn("conn-x", "region-a", []string{"app.corp", "db.corp"}), now.Add(3*time.Second))
	if reg.ConfigGeneration() <= g1 {
		t.Fatalf("catalog change did not bump generation (still %d)", reg.ConfigGeneration())
	}
}

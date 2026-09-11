package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// TestConnectorForDestinationRouteLayer verifies the edge wires the connector ROUTE layer end to end against a
// REAL ResolveConnector: connectorDestinationResolver(a) steered flow's destination resolves to the right LIVE connector by reachable_routes — FQDN
// and IP+namespace — with offline connectors excluded, tenant isolation honored, and fail-closed on no route.
func TestConnectorForDestinationRouteLayer(t *testing.T) {
	reg := connector.NewRegistry()
	now := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
	register := func(c model.ConnectorRegistration) {
		c.PrivateBaseURL = "https://internal.invalid" // required by the registry; unused by the route layer
		if _, err := reg.Register(c, now); err != nil {
			t.Fatalf("register %s: %v", c.ID, err)
		}
	}
	register(model.ConnectorRegistration{ID: "conn-tokyo", TenantID: "tenant-a", Status: "active",
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"tokyo.corp"}}})
	register(model.ConnectorRegistration{ID: "conn-tokyo-dead", TenantID: "tenant-a", Status: "offline",
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"tokyo.corp"}}}) // same route, OFFLINE
	register(model.ConnectorRegistration{ID: "conn-ip", TenantID: "tenant-a", Status: "active",
		ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/8"}, Namespace: "tokyo"}})
	register(model.ConnectorRegistration{ID: "conn-other-tenant", TenantID: "tenant-b", Status: "active",
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"secret.corp"}}})

	ctx := context.Background()

	// FQDN destination -> the LIVE tokyo connector (the offline one with the same route is excluded).
	if conn, ok, err := connectorForDestination(ctx, reg, "tenant-a", "host.tokyo.corp", ""); err != nil || !ok || conn.ID != "conn-tokyo" {
		t.Fatalf("fqdn route: (%q, ok=%v, err=%v), want conn-tokyo", conn.ID, ok, err)
	}
	// IP destination within the tokyo namespace -> the CIDR connector.
	if conn, ok, _ := connectorForDestination(ctx, reg, "tenant-a", "10.1.2.3", "tokyo"); !ok || conn.ID != "conn-ip" {
		t.Fatalf("ip route: (%q, ok=%v), want conn-ip", conn.ID, ok)
	}
	// IP in the WRONG namespace -> no route (fail-closed; overlap handled).
	if _, ok, _ := connectorForDestination(ctx, reg, "tenant-a", "10.1.2.3", "osaka"); ok {
		t.Fatal("ip route in the wrong namespace must fail-closed")
	}
	// tenant-b's route is NOT visible to tenant-a (tenant isolation).
	if _, ok, _ := connectorForDestination(ctx, reg, "tenant-a", "host.secret.corp", ""); ok {
		t.Fatal("tenant-a must not resolve tenant-b's connector route (isolation)")
	}
	// Unknown destination -> fail-closed (no implicit reach).
	if _, ok, _ := connectorForDestination(ctx, reg, "tenant-a", "nope.example.com", ""); ok {
		t.Fatal("unknown destination must fail-closed")
	}
}

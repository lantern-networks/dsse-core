package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func TestConnectorDNSUsesRequestTenantForPrivateRoute(t *testing.T) {
	const seed, other = "tenant_dns_seed", "tenant_dns_other"
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "other-dns-connector", TenantID: other, PrivateBaseURL: "https://private.example",
		Status: "healthy", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.45.0.0/16"}},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	resolver := &connectorDNSUpstream{registry: registry, tenantID: seed}
	// With no tunnel manager, reaching that error proves the route was selected.
	// A seed-tenant lookup must stop earlier because only the other tenant owns it.
	if _, err := resolver.ResolveViaConnectorForTenant(context.Background(), other, "10.45.0.10:53", []byte{1}); err == nil || !strings.Contains(err.Error(), "tunnel manager not configured") {
		t.Fatalf("other-tenant connector route not selected: %v", err)
	}
	if _, err := resolver.ResolveViaConnectorForTenant(context.Background(), seed, "10.45.0.10:53", []byte{1}); err == nil || !strings.Contains(err.Error(), "no connector reaches") {
		t.Fatalf("seed tenant incorrectly reached another tenant's connector: %v", err)
	}
	if _, err := resolver.ResolveViaConnectorForTenant(context.Background(), "", "10.45.0.10:53", []byte{1}); err == nil || !strings.Contains(err.Error(), "tenant is unavailable") {
		t.Fatalf("unattributed DNS query selected a connector: %v", err)
	}
}

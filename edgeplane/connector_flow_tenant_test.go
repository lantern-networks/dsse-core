package edgeplane

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestConnectorInterceptUsesFlowTenantForCandidatesAndResidency(t *testing.T) {
	var resolved, listed, bounded string
	conn := model.ConnectorRegistration{ID: "connector-b", TenantID: "tenant-b", EdgeRegionID: "region-c"}
	dial := ConnectorEgressDialContextWithCandidates(
		func(context.Context, string, string) (net.Conn, error) {
			t.Error("must not bypass connector route")
			return nil, errors.New("unexpected direct dial")
		},
		func(_ context.Context, tenant, _, _ string) (model.ConnectorRegistration, bool, error) {
			resolved = tenant
			return conn, true, nil
		},
		func(_ context.Context, tenant, _, _ string) ([]model.ConnectorRegistration, error) {
			listed = tenant
			return []model.ConnectorRegistration{conn}, nil
		},
		tunnel.NewManager(), "tenant-default", "region-a",
		func(tenant string) ([]string, error) {
			bounded = tenant
			if tenant == "tenant-b" {
				return []string{"region-a"}, nil
			}
			return nil, nil
		},
		nil, nil,
	)
	_, err := dial(WithFlowTenant(context.Background(), "tenant-b"), "tcp", "app.internal:443")
	if resolved != "tenant-b" || listed != "tenant-b" || bounded != "tenant-b" {
		t.Errorf("tenant context lost: resolve=%q candidates=%q residency=%q", resolved, listed, bounded)
	}
	if err == nil || !strings.Contains(err.Error(), "residency boundary") {
		t.Fatalf("must apply flow tenant's boundary, got %v", err)
	}
}

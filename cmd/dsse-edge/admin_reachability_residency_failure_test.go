package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type unavailableReachabilityTenantStore struct{}

func (unavailableReachabilityTenantStore) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, errors.New("tenant residency state unavailable")
}

func (unavailableReachabilityTenantStore) Update(context.Context, adminTenantModel, string, time.Time) (adminTenantModel, error) {
	return adminTenantModel{}, errors.New("tenant residency state unavailable")
}

func TestReachabilityRefusesWhenTenantResidencyCannotBeRead(t *testing.T) {
	const appID = "app_residency_unavailable"
	now := time.Now().UTC()
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_residency_unavailable", TenantID: "tenant_lab_001", ConnectorGroupID: "site",
		Name: "Site", EdgeRegionID: "jp", EdgeClusterID: "edge", ApplicationIDs: []string{appID},
		PrivateBaseURL: "http://connector.local", LastHeartbeatAt: now.Format(time.RFC3339), Status: "registered",
	}, now); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: registry,
		RouteProfiles: map[string]edgeplane.ApplicationRouteProfile{
			appID: {Destination: "app.internal.example", DestinationPort: 8443, Protocol: "tcp", ServiceFamily: "https", DestinationRole: "private_app"},
		},
		AdminAuth: newAdminAuthStore(), TenantModelStore: unavailableReachabilityTenantStore{},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/applications/"+appID+"/reachability", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable tenant residency returned HTTP %d; a diagnostic must not probe or report unrestricted reachability", rec.Code)
	}
}

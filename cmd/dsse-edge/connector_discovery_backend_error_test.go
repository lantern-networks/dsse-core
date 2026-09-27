package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

type unavailableDiscoveryRegistry struct{ *connector.Registry }

func (r unavailableDiscoveryRegistry) ListByTenant(context.Context, string) ([]model.ConnectorRegistration, error) {
	return nil, errors.New("private database connection detail")
}
func (r unavailableDiscoveryRegistry) GetByTenant(context.Context, string, string) (model.ConnectorRegistration, bool, error) {
	return model.ConnectorRegistration{}, false, errors.New("private database connection detail")
}

type unavailableDiscoveryCatalog struct{ *appcatalog.Store }

func (c unavailableDiscoveryCatalog) List(context.Context, string, appcatalog.ListOptions) (appcatalog.ListResponse, error) {
	return appcatalog.ListResponse{}, errors.New("private database connection detail")
}

func TestConnectorDiscoveryBackendFailureIsServerError(t *testing.T) {
	for _, backend := range []string{"registry", "catalog"} {
		t.Run(backend, func(t *testing.T) {
			cfg := serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), PolicyCandidateStore: policycandidate.NewStore(), ApplicationCatalogStore: appcatalog.NewStore()}
			if backend == "registry" {
				cfg.Registry = unavailableDiscoveryRegistry{connector.NewRegistry()}
			} else {
				cfg.ApplicationCatalogStore = unavailableDiscoveryCatalog{appcatalog.NewStore()}
			}
			rec := httptest.NewRecorder()
			newServerWithConfig(cfg).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/connector-discovery/refresh", nil))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "private database") {
				t.Fatal("backend detail disclosed")
			}
		})
	}
}

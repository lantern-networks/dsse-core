package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// Until redirects can bind the replacement request to the original, refuse
// zero-age HTTP authentication rather than mint a reusable grant or loop.
func TestAuthHTTPZeroAgeCannotRedirectOrForward(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{
			PolicyBundle: model.PolicyBundle{TenantID: "single-request-test"},
			Policies: []model.Policy{{ID: "fresh", TenantID: "single-request-test", Status: "active", Priority: 1,
				Conditions: map[string]any{"destination_port": 443},
				Action:     model.PolicyAction{Decision: "require_reauthentication"},
				Metadata:   map[string]any{"max_age_seconds": 0}}},
		},
		Writer: writer, DecisionStore: newAccessDecisionStore(),
		DeviceAuthenticatedInProcess: true,
	})
	req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://app.example/")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "max_age=0") {
		t.Fatalf("expected explicit unsupported single-request denial, got %d %s", rec.Code, rec.Body.String())
	}
}

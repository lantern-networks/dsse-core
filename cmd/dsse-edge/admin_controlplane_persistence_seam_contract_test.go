package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestControlPlanePersistenceSeamsServeDefaultAdminStores(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth, rawTokensByRole := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})

	routes := []string{
		"/admin/policies",
		"/admin/applications",
		"/admin/policy-candidates",
		"/admin/agent-tools",
		"/admin/delegated-grants",
		"/admin/human-approval-events",
		"/admin/endpoints",
		"/admin/tenant",
		"/admin/tool-call-events",
	}
	for _, target := range routes {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("authorization", "Bearer "+rawTokensByRole["admin"])
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d, body=%s", target, rec.Code, http.StatusOK, rec.Body.String())
			}
		})
	}
}

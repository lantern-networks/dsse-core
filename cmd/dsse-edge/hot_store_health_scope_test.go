package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// /admin/hot-store/health required only admin.logs.read, so an organization's
// administrator read the deployment-wide counters and the last store error,
// which names the internal ClickHouse host and port.
func TestHotStoreHealthShowsDetailOnlyToDeploymentAdministration(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	monitor := newHotStoreAppendMirrorMonitor()
	monitor.RecordIngestFailure("access", "access.log.jsonl",
		errors.New("hot store unavailable: clickhouse dsse-clickhouse:8123: connection refused"), time.Now())
	mux := http.NewServeMux()
	registerOutboxAdminRoutes(mux, func(permission string, h http.HandlerFunc) http.HandlerFunc {
		if permission == "" {
			t.Fatal("missing permission")
		}
		return h
	}, serverConfig{}, testEvaluator(), nil, nil, nil, nil, monitor, nil)
	for _, tc := range []struct {
		tenant, operate string
		roles           []string
		detail          bool
	}{
		{"tenant_operator_001", "", []string{"owner"}, true},
		{"tenant_other", "", []string{"admin"}, false},
		{"tenant_operator_001", "tenant_other", []string{"owner"}, false},
	} {
		req := scopeRequest(tc.tenant, tc.operate, tc.roles...)
		req.URL.Path = "/admin/hot-store/health"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("scope=%s/%s: %d %s", tc.tenant, tc.operate, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "degraded" {
			t.Fatalf("scope=%s/%s: status %v", tc.tenant, tc.operate, body["status"])
		}
		leaked := strings.Contains(rec.Body.String(), "dsse-clickhouse") || body["stats"] != nil || body["last_stream"] != nil
		if tc.detail != leaked {
			t.Fatalf("scope=%s/%s: detail shown=%v, want %v: %s", tc.tenant, tc.operate, leaked, tc.detail, rec.Body.String())
		}
		if !tc.detail && len(body) != 1 {
			t.Fatalf("scope=%s/%s: organization answer has extra fields: %s", tc.tenant, tc.operate, rec.Body.String())
		}
	}
}

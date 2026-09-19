package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAuditWriterHealthReportsPrimaryFailureWithoutTenantLeak(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "audit.log.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := appendAdminAudit(context.Background(), writer, nil, model.AuditLog{ID: "private-id", TenantID: "private-tenant", EventType: "private-event"}, time.Now()); err == nil {
		t.Fatal("expected disk failure")
	}
	// Direct appends (including export-domain audit paths) share the observation point.
	_ = writer.Append("audit.log.jsonl", map[string]any{"tenant_id": "private-tenant"})
	mux := http.NewServeMux()
	registerOutboxAdminRoutes(mux, func(permission string, h http.HandlerFunc) http.HandlerFunc {
		if permission == "" {
			t.Fatal("missing permission")
		}
		return h
	}, serverConfig{}, testEvaluator(), writer, nil, nil, nil, nil, nil)
	for _, tc := range []struct {
		tenant, operate string
		roles           []string
		status          int
	}{
		{"tenant_operator_001", "", []string{"owner"}, 200},
		{"tenant_other", "", []string{"admin"}, 403},
		{"tenant_operator_001", "tenant_other", []string{"owner"}, 403},
	} {
		req := scopeRequest(tc.tenant, tc.operate, tc.roles...)
		req.URL.Path = "/admin/audit-writer/health"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("scope=%s/%s: %d %s", tc.tenant, tc.operate, rec.Code, rec.Body.String())
		}
		if tc.status == 200 {
			var h logs.AuditWriteHealth
			if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
				t.Fatal(err)
			}
			if h.PrimaryFailures != 2 || h.Status != "degraded" {
				t.Fatalf("wrong health: %+v", h)
			}
			for _, secret := range []string{dir, "private-tenant", "private-event", "private-id"} {
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatal("private detail exposed")
				}
			}
		}
	}
	if writer.AuditHealth().Attempts != 2 {
		t.Fatal("health reads wrote audit records")
	}
}

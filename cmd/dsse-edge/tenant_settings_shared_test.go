package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two independently opened SQL-backed handlers must observe a completed edit
// before applying the next edit. This does not test simultaneous conflicting writes.
func TestTenantSettingsAcrossSharedPostgresHandlers(t *testing.T) {
	dsn := os.Getenv("DSSE_TENANT_SHARED_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.SetMaxOpenConns(1)
	schema := fmt.Sprintf("tenant_settings_%d", time.Now().UnixNano())
	if _, err = a.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer a.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if _, err = a.ExecContext(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	b, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetMaxOpenConns(1)
	if _, err = b.ExecContext(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	bundle := model.PolicyBundle{TenantID: "customer"}
	sa, err := setupPostgresAdminTenantModelStore(ctx, postgresAdminAuthStore{DB: a}, filepath.Join("..", "..", "migrations"), true, bundle, "operations", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sb, err := setupPostgresAdminTenantModelStore(ctx, postgresAdminAuthStore{DB: b}, filepath.Join("..", "..", "migrations"), true, bundle, "operations", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ha := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: tenantSettingsSyncAuth(), TenantModelStore: sa, OperatorTenantID: "operations"})
	hb := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: tenantSettingsSyncAuth(), TenantModelStore: sb, OperatorTenantID: "operations"})
	call := func(h http.Handler, who, path string, body any) {
		t.Helper()
		code, raw := operatorEnvelopeCall(t, h, "synthetic-tenant-sync-"+who, "POST", path, "", body)
		if code != 200 {
			t.Fatalf("POST %s: %d %s", path, code, raw)
		}
	}
	call(ha, "customer-admin", "/admin/tenant", map[string]any{"timezone": "Asia/Tokyo", "allowed_regions": []string{"region-a"}})
	call(hb, "operator", "/admin/tenants", map[string]any{"tenant_id": "customer", "display_name": "Edited on second CP"})
	for _, h := range []http.Handler{ha, hb} {
		code, raw := operatorEnvelopeCall(t, h, "synthetic-tenant-sync-customer-admin", "GET", "/admin/tenant", "", nil)
		var row adminTenantModel
		if code != 200 || json.Unmarshal([]byte(raw), &row) != nil || row.Timezone != "Asia/Tokyo" || row.DisplayName != "Edited on second CP" || len(row.AllowedRegions) != 1 || row.AllowedRegions[0] != "region-a" {
			t.Fatalf("shared tenant: %d %s", code, raw)
		}
		code, raw = operatorEnvelopeCall(t, h, "synthetic-tenant-sync-customer-admin", "GET", "/admin/session", "", nil)
		var session map[string]any
		if code != 200 || json.Unmarshal([]byte(raw), &session) != nil || session["timezone"] != "Asia/Tokyo" {
			t.Fatalf("shared session: %d %s", code, raw)
		}
	}
	call(hb, "customer-admin", "/admin/tenant", map[string]any{"allowed_regions": []string{}})
	row, err := sa.Get(ctx, "customer")
	if err != nil || len(row.AllowedRegions) != 0 || row.Timezone != "Asia/Tokyo" || row.DisplayName != "Edited on second CP" {
		t.Fatalf("clear did not preserve settings: %+v %v", row, err)
	}
}

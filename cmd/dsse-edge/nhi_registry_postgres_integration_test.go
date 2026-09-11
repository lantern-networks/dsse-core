package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestSetupEdgeNonHumanIdentityStorePostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeNonHumanIdentityStore(ctx, edgeNonHumanIdentityStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeNonHumanIdentityStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close NHI registry store: %v", err)
		}
	})

	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	if _, err := store.Upsert(ctx, model.NonHumanIdentity{
		ID:                    "nhi_pg_active_001",
		Name:                  "Postgres Active Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_dummy_https"},
		AllowedScopes:         []string{"ticket:create"},
		ExpiresAt:             &expiresAt,
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert active NHI returned error: %v", err)
	}
	if _, err := store.Upsert(ctx, model.NonHumanIdentity{
		ID:          "nhi_pg_suspended_001",
		Name:        "Postgres Suspended Agent",
		NHIType:     "service_account",
		OwnerUserID: "user_owner_001",
		Status:      "suspended",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert suspended NHI returned error: %v", err)
	}

	items, err := store.List(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI returned error: %v", err)
	}
	if got, want := len(items), 2; got != want {
		t.Fatalf("listed NHI = %d, want %d", got, want)
	}
	active, err := store.CountActive(ctx, "tenant_lab_001", now)
	if err != nil {
		t.Fatalf("count active NHI returned error: %v", err)
	}
	if active != 1 {
		t.Fatalf("active NHI = %d, want 1", active)
	}
	usedAt := now.Add(10 * time.Minute)
	updated, err := store.MarkUsed(ctx, "tenant_lab_001", "nhi_pg_active_001", usedAt)
	if err != nil {
		t.Fatalf("mark NHI used returned error: %v", err)
	}
	if !updated {
		t.Fatal("mark NHI used updated = false, want true")
	}
	items, err = store.List(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("list NHI after mark used returned error: %v", err)
	}
	var activeItem model.NonHumanIdentity
	for _, item := range items {
		if item.ID == "nhi_pg_active_001" {
			activeItem = item
			break
		}
	}
	if activeItem.LastUsedAt == nil || *activeItem.LastUsedAt != usedAt.Format(time.RFC3339) {
		t.Fatalf("last_used_at = %#v, want %s", activeItem.LastUsedAt, usedAt.Format(time.RFC3339))
	}

	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM non_human_identities WHERE tenant_id = $1", "tenant_lab_001").Scan(&rows); err != nil {
		t.Fatalf("query non_human_identities count: %v", err)
	}
	if rows != 2 {
		t.Fatalf("non_human_identities rows = %d, want 2", rows)
	}
}

func TestAdminNonHumanIdentityEndpointPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeNonHumanIdentityStore(ctx, edgeNonHumanIdentityStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeNonHumanIdentityStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close NHI registry store: %v", err)
		}
	})

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		NonHumanIdentities: store,
		LabMode:            boolPtr(true),
	})

	body := []byte(`{
		"id":"nhi_endpoint_pg_001",
		"name":"Endpoint Postgres Agent",
		"nhi_type":"ai_agent",
		"owner_user_id":"user_owner_001",
		"status":"active",
		"allowed_application_ids":["app_dummy_https"],
		"allowed_scopes":["ticket:create"]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/non-human-identities", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/non-human-identities", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var list nhi.ListResponse
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode NHI list response: %v", err)
	}
	if list.Count != 1 || list.ActiveCount != 1 || len(list.Identities) != 1 {
		t.Fatalf("list response = %#v, want one active NHI", list)
	}
	if list.Identities[0].ID != "nhi_endpoint_pg_001" {
		t.Fatalf("listed identity ID = %q", list.Identities[0].ID)
	}
}

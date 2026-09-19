package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresAPITokenSaveRefusalE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resetPostgresExportTaskQueueTables(t, ctx, db)
	applyPostgresExportTaskQueueMigration(t, ctx, db)
	defer resetPostgresExportTaskQueueTables(t, ctx, db)
	s := postgresAdminAuthStore{DB: db}
	now := time.Now().UTC()
	request := adminAPITokenCreateRequest{Name: "stored", Roles: []string{"admin"}}
	exec := func(q string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	fault := func(expr string) {
		exec("ALTER TABLE admin_api_tokens DROP CONSTRAINT IF EXISTS test_write_refusal")
		if expr != "" {
			exec("ALTER TABLE admin_api_tokens ADD CONSTRAINT test_write_refusal CHECK (" + expr + ") NOT VALID")
		}
	}
	checkErr := func(err error) {
		t.Helper()
		if !errors.Is(err, errAdminAPITokenStorage) {
			t.Fatalf("storage not classified: %v", err)
		}
		w := httptest.NewRecorder()
		writeAdminAPITokenMutationError(w, 400, err)
		if w.Code != 503 || strings.Contains(w.Body.String(), "test_write_refusal") {
			t.Fatal("unsafe acknowledgement")
		}
	}
	fault("false")
	_, raw, err := s.CreateAPITokenForTenant(ctx, request, "tenant_lab_001", "admin_lab_bypass", now)
	checkErr(err)
	if raw != "" {
		t.Fatal("failed create exposed secret")
	}
	rows, err := s.ListAPITokensForTenant(ctx, "tenant_lab_001")
	if err != nil || len(rows) != 0 {
		t.Fatal("failed create stored token")
	}
	fault("")
	first, raw, err := s.CreateAPITokenForTenant(ctx, request, "tenant_lab_001", "admin_lab_bypass", now)
	if err != nil {
		t.Fatal(err)
	}
	auth := func(secret string, want bool) {
		t.Helper()
		_, ok, err := s.LookupAPITokenAdminIdentity(ctx, secret, "tenant_lab_001", now)
		if err != nil || ok != want {
			t.Fatalf("token authentication=%v want %v: %v", ok, want, err)
		}
	}
	auth(raw, true)
	fault("NOT ((payload->'metadata') ? 'rotated_from_admin_api_token_id')")
	_, secret, _, err := s.RotateAPITokenForTenant(ctx, first.ID, first.TenantID, "admin_lab_bypass", adminAPITokenRotateRequest{}, now)
	checkErr(err)
	if secret != "" {
		t.Fatal("failed rotate exposed secret")
	}
	auth(raw, true)
	rows, err = s.ListAPITokensForTenant(ctx, first.TenantID)
	if err != nil || len(rows) != 1 || rows[0].Status != "active" {
		t.Fatal("rotation failed to roll back old revocation")
	}
	fault("")
	second, newRaw, ok, err := s.RotateAPITokenForTenant(ctx, first.ID, first.TenantID, "admin_lab_bypass", adminAPITokenRotateRequest{}, now)
	if err != nil || !ok {
		t.Fatal(err)
	}
	auth(raw, false)
	auth(newRaw, true)
	fault("status <> 'revoked'")
	_, _, err = s.RevokeAPITokenForTenant(ctx, second.ID, second.TenantID, now)
	checkErr(err)
	auth(newRaw, true)
	fault("")
	if _, ok, err := s.RevokeAPITokenForTenant(ctx, second.ID, second.TenantID, now); err != nil || !ok {
		t.Fatal(err)
	}
	auth(newRaw, false)
	reopened := postgresAdminAuthStore{DB: db}
	rows, err = reopened.ListAPITokensForTenant(ctx, first.TenantID)
	if err != nil || len(rows) != 2 || rows[0].Status != "revoked" || rows[1].Status != "revoked" {
		t.Fatal("stored revocations lost")
	}
	if _, _, err := s.CreateAPITokenForTenant(ctx, adminAPITokenCreateRequest{}, first.TenantID, "admin_lab_bypass", now); err == nil || errors.Is(err, errAdminAPITokenStorage) {
		t.Fatal("validation classified as storage")
	}
}

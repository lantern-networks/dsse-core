package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestManagedLegacyPrincipalAlias(t *testing.T) {
	now := time.Now().UTC()
	s := newLocalAdminCredentialStore("test")
	seedActiveAdminAccount(t, s, "legacy@example.com", "tenant_lab_001", "new-id", []string{"admin"}, now)
	auth := newAdminAuthStore()
	principal := principalFromCredential(s.byEmail["legacy@example.com"], now)
	principal.ID = "old-id"
	auth.UpsertPrincipal(principal)
	auth.UpsertSession(adminSession{ID: "legacy-session", TenantID: principal.TenantID, AdminPrincipalID: principal.ID, Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, LocalCredentials: s})
	r := httptest.NewRequest(http.MethodGet, "/admin/session", nil)
	r.AddCookie(&http.Cookie{Name: "admin_session", Value: "legacy-session"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("legacy session status=%d", w.Code)
	}
	identity := adminIdentity{PrincipalID: principal.ID, TenantID: "another-tenant", AuthMethod: "admin_session"}
	if _, allowed, err := refreshManagedAdminIdentity(context.Background(), auth, s, identity); err != nil || allowed {
		t.Fatal("alias crossed tenant", err)
	}
}

func TestPostgresManagedIdentityAndCredentialPurge(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	resetPostgresExportTaskQueueTables(t, ctx, db)
	applyPostgresExportTaskQueueMigration(t, ctx, db)
	defer resetPostgresExportTaskQueueTables(t, ctx, db)
	p := postgresCredentialPersistence{db: db}
	peer, err := newLocalAdminCredentialStoreWithPersistence("test", p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	writer := newLocalAdminCredentialStore("test")
	seedActiveAdminAccount(t, writer, "peer@example.com", "tenant_lab_001", "credential-id", []string{"admin"}, now)
	cred := cloneCredential(writer.byEmail["peer@example.com"])
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatal(err)
	}
	principal := principalFromCredential(cred, now)
	principal.ID = "legacy-principal-id"
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(principal)
	identity := adminIdentity{TenantID: principal.TenantID, PrincipalID: principal.ID, AuthMethod: "admin_session", Roles: []string{"admin"}}
	check := func(wantRole string, wantAllowed bool) {
		t.Helper()
		got, allowed, err := refreshManagedAdminIdentity(ctx, auth, peer, identity)
		if err != nil || allowed != wantAllowed {
			t.Fatalf("authorization=%v want %v err=%v", allowed, wantAllowed, err)
		}
		if allowed && (len(got.Roles) != 1 || got.Roles[0] != wantRole) {
			t.Fatalf("roles=%v", got.Roles)
		}
	}
	check("admin", true) // account added after this CP started, with a legacy ID
	cred.Roles = []string{"analyst"}
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatal(err)
	}
	check("analyst", true) // never restore the peer's startup admin role
	cred.Status = credentialStatusSuspended
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatal(err)
	}
	check("", false)
	cred.Status = credentialStatusActive
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatal(err)
	}
	// Both login factors can see a row created since this process started.
	if err := peer.refreshLoginCredentialLocked(cred.Email); err != nil {
		t.Fatal(err)
	}
	if got := peer.byEmail[credentialEmailKey(cred.Email)]; got == nil || got.Revision != cred.Revision {
		t.Fatal("login did not refresh shared revision")
	}
	keep := cloneCredential(cred)
	keep.Email = "other@example.com"
	keep.PrincipalID = "other"
	keep.TenantID = "other"
	keep.Revision = 0
	if err := p.Upsert(ctx, keep); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		row := purgeTenantRows(ctx, db, "admin_local_credentials", cred.TenantID)
		if row.Error != "" {
			t.Fatalf("purge attempt %d: %s", attempt, row.Error)
		}
		want := int64(0)
		if attempt == 0 {
			want = 1
		}
		if row.Count != want {
			t.Fatalf("purge count=%d want=%d", row.Count, want)
		}
	}
	check("", false)
	rows, err := p.LoadAll(ctx)
	if err != nil || len(rows) != 1 || rows[0].TenantID != "other" {
		t.Fatal("purge changed another tenant", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM admin_local_credentials WHERE false`); err == nil {
		t.Fatal("purge leaked writer protocol permission")
	}
	faultDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	faultDB.Close()
	peer.persistence = postgresCredentialPersistence{db: faultDB}
	if _, _, err := refreshManagedAdminIdentity(ctx, auth, peer, identity); err == nil {
		t.Fatal("unavailable authority accepted stale cache")
	}
}

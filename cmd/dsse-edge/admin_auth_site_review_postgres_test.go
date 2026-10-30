package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Each test owns a schema; no existing application tables are dropped.
func reviewAuthSitePostgresDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("auth_site_review_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		if err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	scoped := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scoped = u.String()
	}
	db, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPostgresFirstPartyIdentityAndBulkRevocation(t *testing.T) {
	db := reviewAuthSitePostgresDB(t)
	ctx := context.Background()
	for _, stmt := range postgresAdminAuthSchemaSQL() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	s := postgresAdminAuthStore{DB: db}
	now := time.Now().UTC().Truncate(time.Second)
	p := adminPrincipal{ID: "federated", TenantID: "tenant", Subject: "alice@example.test", Email: "alice@example.test", IDPID: "external-idp", Status: "active", CreatedAt: now.Format(time.RFC3339)}
	if err := s.PersistPrincipal(ctx, p); err != nil {
		t.Fatal(err)
	}
	if id, ok := s.PrincipalIDForSubject(p.TenantID, p.Subject); ok {
		t.Fatalf("adopted another provider's principal %q", id)
	}
	p.ID = "local"
	p.IDPID = "first_party"
	if err := s.PersistPrincipal(ctx, p); err != nil {
		t.Fatal(err)
	}
	if id, ok := s.PrincipalIDForSubject(p.TenantID, p.Subject); !ok || id != p.ID {
		t.Fatal("own provider lookup failed")
	}
	token, _, err := s.CreateAPITokenForTenant(ctx, adminAPITokenCreateRequest{Name: "review", Roles: []string{"auditor"}}, p.TenantID, p.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	session := adminSession{ID: "review-session", TenantID: p.TenantID, AdminPrincipalID: p.ID, Status: "active", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), LastActiveAt: now.Format(time.RFC3339)}
	if err := s.PersistSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	other, _, err := s.CreateAPITokenForTenant(ctx, adminAPITokenCreateRequest{Name: "other", Roles: []string{"auditor"}}, "Tenant", p.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	revokedAt := now.Add(time.Minute)
	if ns, nt, err := s.RevokeAllForTenant(ctx, p.TenantID, revokedAt); err != nil || ns != 1 || nt != 1 {
		t.Fatalf("bulk revoke counts: sessions=%d tokens=%d err=%v", ns, nt, err)
	}
	rows, err := s.ListAPITokensForTenant(ctx, p.TenantID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list failed: %v", err)
	}
	if rows[0].Status != "revoked" {
		t.Errorf("bulk-revoked token still listed as %q", rows[0].Status)
	}
	if rows[0].Metadata["revoked_at"] != revokedAt.Format(time.RFC3339) {
		t.Error("token revocation metadata was not persisted")
	}
	saved, found, err := s.adminSession(ctx, session.ID, p.TenantID)
	if err != nil || !found || saved.Status != "revoked" || saved.LastActiveAt != revokedAt.Format(time.RFC3339) {
		t.Errorf("session revocation payload disagrees with indexed state: found=%t status=%q err=%v", found, saved.Status, err)
	}
	untouched, found, err := s.adminAPIToken(ctx, other.ID, other.TenantID)
	if err != nil || !found || untouched.Status != "active" {
		t.Error("case-distinct tenant token changed")
	}
	if ns, nt, err := s.RevokeAllForTenant(ctx, p.TenantID, revokedAt); err != nil || ns != 0 || nt != 0 {
		t.Fatalf("repeat revoke is not idempotent: sessions=%d tokens=%d err=%v", ns, nt, err)
	}
	if _, raw, found, err := s.RotateAPITokenForTenant(ctx, token.ID, p.TenantID, p.ID, adminAPITokenRotateRequest{}, now); err == nil || raw != "" || !found {
		t.Errorf("bulk-revoked token was rotated: issued=%t found=%t err=%v", raw != "", found, err)
	}
}

func TestPostgresSiteMetadataRotationAndGenerationRollback(t *testing.T) {
	db := reviewAuthSitePostgresDB(t)
	ctx := context.Background()
	for _, stmt := range postgresAdminSiteSchemaSQL() {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := createSiteGenerationSequence(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &postgresAdminSiteStore{db: db}
	now := time.Now().UTC()
	seed := adminSiteModel{TenantID: "tenant", SiteID: "site", Name: "initial", BootstrapSecretHash: connectorRuntimeSecretHash("initial")}
	if _, err := s.Upsert(ctx, seed, now); err != nil {
		t.Fatal(err)
	}
	if s.ConfigGeneration() != 1 {
		t.Fatal("first write not visible")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 21)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Upsert(ctx, adminSiteModel{TenantID: seed.TenantID, SiteID: seed.SiteID, Name: fmt.Sprintf("edit-%d", i)}, now)
			errs <- err
		}(i)
	}
	newHash := connectorRuntimeSecretHash("rotated")
	wg.Add(1)
	go func() {
		defer wg.Done()
		rotated := seed
		rotated.BootstrapSecretHash = newHash
		_, err := s.Upsert(ctx, rotated, now)
		errs <- err
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	saved, ok, err := s.Get(ctx, seed.TenantID, seed.SiteID)
	if err != nil || !ok || saved.BootstrapSecretHash != newHash {
		t.Fatal("metadata update reverted concurrent secret rotation")
	}
	if s.ConfigGeneration() != 22 {
		t.Fatal("committed writes did not advance generation")
	}
	if _, err := db.ExecContext(ctx, `DROP SEQUENCE admin_sites_config_generation`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(ctx, adminSiteModel{TenantID: seed.TenantID, SiteID: seed.SiteID, Name: "must-not-commit"}, now); err == nil {
		t.Fatal("missing sequence did not fail write")
	}
	if err := s.Delete(ctx, seed.TenantID, seed.SiteID); err == nil {
		t.Fatal("missing sequence did not fail deletion")
	}
	after, ok, err := s.Get(ctx, seed.TenantID, seed.SiteID)
	if err != nil || !ok || after.Name != saved.Name || after.BootstrapSecretHash != newHash {
		t.Fatal("generation failure did not roll back Site mutation")
	}
}

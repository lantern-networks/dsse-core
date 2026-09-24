package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestApplicationScopedWriterCannotMutateManualEndpoint(t *testing.T) {
	for _, action := range []string{"publish", "unpublish", "delete", "retry-delete", "edit"} {
		t.Run(action, func(t *testing.T) {
			tenant := "tenant_lab_001"
			now := time.Now()
			apps := appcatalog.NewStore()
			assets := assetcatalog.NewStore()
			if action != "retry-delete" {
				_, err := apps.Upsert(context.Background(), appcatalog.Entry{ApplicationID: "app", Name: "App", ApplicationType: "private_app", Destination: "app.example.invalid", DestinationPort: 443, PublishProtocol: "web", Published: true}, tenant, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			original := assetcatalog.Endpoint{ID: "app-app", TenantID: tenant, Alias: "Manual resource", Kind: assetcatalog.KindNetwork, Address: "manual.example.invalid", Source: assetcatalog.SourceManual}
			if _, err := assets.UpsertEndpoint(original); err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "scoped-app", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "scope-test", TenantID: tenant, Name: "application scope", TokenHash: adminTokenHash("application-review-token"), Roles: []string{"admin"}, Scopes: []string{"admin.applications.write"}, CreatedByAdminPrincipalID: "scoped-app", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, AssetStore: assets, ApplicationCatalogStore: apps})
			method, path := "POST", "/admin/applications/app/"+action
			if action == "delete" || action == "retry-delete" {
				method, path = "DELETE", "/admin/applications/app"
			}
			body := `{"destination":"app.example.invalid","destination_port":443,"publish_protocol":"web"}`
			if action == "edit" {
				path = "/admin/applications"
				body = `{"application_id":"app","name":"Renamed app","application_type":"private_app","published":true,"destination":"app.example.invalid","destination_port":443,"publish_protocol":"web"}`
			}
			r := httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer application-review-token")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != 403 {
				t.Fatalf("cross-permission mutation %d: %s", rec.Code, rec.Body)
			}
			got, found := assets.GetEndpoint(tenant, original.ID)
			if !found || got.Address != original.Address || got.Alias != original.Alias {
				t.Fatal("manual resource changed")
			}
			entry, found, err := apps.Get(context.Background(), tenant, "app")
			if err != nil || found != (action != "retry-delete") || found && !entry.Published {
				t.Fatal("application changed before refusal")
			}
			errors := 0
			for _, row := range readTransportAudits(t, writer) {
				if stringPtrValue(row.Result) == "success" {
					t.Fatal("refusal recorded as success")
				}
				if stringPtrValue(row.Result) == "error" {
					errors++
				}
			}
			if errors != 1 {
				t.Fatalf("refusal audit count %d", errors)
			}
		})
	}
}

func TestApplicationScopedWriterOwnLifecycle(t *testing.T) {
	tenant := "tenant_lab_001"
	now := time.Now()
	apps := appcatalog.NewStore()
	assets := assetcatalog.NewStore()
	if _, err := apps.Upsert(context.Background(), appcatalog.Entry{ApplicationID: "own", Name: "Owned application", ApplicationType: "private_app"}, tenant, now); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "scoped-app", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "scope-test", TenantID: tenant, Name: "application scope", TokenHash: adminTokenHash("application-review-token"), Roles: []string{"admin"}, Scopes: []string{"admin.applications.write"}, CreatedByAdminPrincipalID: "scoped-app", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, AssetStore: assets, ApplicationCatalogStore: apps})
	send := func(method, path string) {
		r := httptest.NewRequest(method, path, strings.NewReader(`{"destination":"own.example.invalid","destination_port":443,"publish_protocol":"web"}`))
		r.Header.Set("Authorization", "Bearer application-review-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != 200 {
			t.Fatalf("own operation %s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	send("POST", "/admin/applications/own/publish")
	if e, found := assets.GetEndpoint(tenant, "app-own"); !found || e.Source != assetcatalog.SourceApplication {
		t.Fatal("publish missing ownership")
	}
	send("POST", "/admin/applications/own/publish")
	send("POST", "/admin/applications/own/unpublish")
	send("POST", "/admin/applications/own/publish")
	// Simulate a previous primary deletion whose derived cleanup must be retried.
	if err := apps.Delete(context.Background(), tenant, "own"); err != nil {
		t.Fatal(err)
	}
	send("DELETE", "/admin/applications/own")
	if _, found := assets.GetEndpoint(tenant, "app-own"); found {
		t.Fatal("owned retry failed")
	}
}

// A peer may replace the destination between an HTTP preflight and the derived
// write. Ownership must be checked against the locked shared row, not the cache.
func TestPostgresApplicationOwnershipUsesLatestRow(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is required")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_application_owner_latest"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	a, b := assetcatalog.NewStore(), assetcatalog.NewStore()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	own := assetcatalog.Endpoint{TenantID: "tenant", Alias: "App", Kind: assetcatalog.KindNetwork, Address: "app.invalid"}
	if _, err := a.UpsertApplicationEndpointContext(ctx, "id", own, false); err != nil {
		t.Fatal(err)
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteApplicationEndpointContext(ctx, "tenant", "id", false); err != nil {
		t.Fatal(err)
	}
	manual := own
	manual.ID = "app-id"
	manual.Source = assetcatalog.SourceManual
	manual.Address = "manual.invalid"
	if _, err := a.UpsertEndpointContext(ctx, manual); err != nil {
		t.Fatal(err)
	}
	before, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpsertApplicationEndpointContext(ctx, "id", own, false); !errors.Is(err, assetcatalog.ErrApplicationEndpointOwnership) {
		t.Fatalf("stale upsert: %v", err)
	}
	if _, err := b.DeleteApplicationEndpointContext(ctx, "tenant", "id", false); !errors.Is(err, assetcatalog.ErrApplicationEndpointOwnership) {
		t.Fatalf("stale delete: %v", err)
	}
	after, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected stale request changed shared row")
	}
	fresh := assetcatalog.NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok := fresh.GetEndpoint("tenant", "app-id")
	if !ok || got.Source != assetcatalog.SourceManual || got.Address != "manual.invalid" {
		t.Fatalf("manual lost: %+v", got)
	}
}

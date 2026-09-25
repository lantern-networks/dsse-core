package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminSitePersistenceFailurePreservesCommittedGeneration(t *testing.T) {
	for _, failure := range []string{"temp-write", "rename"} {
		for _, operation := range []string{"create", "update", "delete", "enrollment"} {
			t.Run(failure+"/"+operation, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "private-sites.json")
				store := newDurableAdminSiteStore(path)
				now := time.Now().UTC()
				tenant := "tenant_site_fixture"
				auth := newAdminAuthStore()
				auth.UpsertPrincipal(adminPrincipal{ID: "site-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
				auth.UpsertAPIToken(adminAPIToken{ID: "site-admin", TenantID: tenant, TokenHash: adminTokenHash("synthetic-site-store-token"),
					Roles: []string{"admin"}, Scopes: []string{"admin.connectors.read", "admin.connectors.write"},
					CreatedByAdminPrincipalID: "site-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
				writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
				if err != nil {
					t.Fatal(err)
				}
				handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, SiteStore: store, Writer: writer,
					ConnectorEnrollmentEdgeURL: "https://edge.example.test", ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ntest-anchor\n-----END CERTIFICATE-----\n"})
				request := func(method, route, body string) *httptest.ResponseRecorder {
					req := httptest.NewRequest(method, route, strings.NewReader(body))
					req.Header.Set("Authorization", "Bearer synthetic-site-store-token")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					return rec
				}
				if rec := request("POST", "/admin/sites", `{"site_id":"saved-site","name":"Saved","expected_connector_count":2}`); rec.Code != 200 {
					t.Fatalf("seed status %d", rec.Code)
				}
				// Seed an existing command so a failed rotation must retain the previous credential.
				if _, _, err := adminSiteEnrollmentCommandIssue(context.Background(), store, tenant, "saved-site", enrollmentTokenParams{EdgeURL: "https://edge.example.test"}, now); err != nil {
					t.Fatal(err)
				}
				before, _ := store.List(context.Background(), tenant)
				encodedBefore, _ := json.Marshal(before)
				saved, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				generation := store.ConfigGeneration()
				if failure == "rename" {
					if err := os.Rename(path, path+".backup"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(path+".tmp", 0700); err != nil {
						t.Fatal(err)
					}
				}
				var rec *httptest.ResponseRecorder
				switch operation {
				case "create":
					rec = request("POST", "/admin/sites", `{"site_id":"failed-site"}`)
				case "update":
					rec = request("POST", "/admin/sites", `{"site_id":"saved-site","name":"Unsaved"}`)
				case "delete":
					rec = request("DELETE", "/admin/sites/saved-site", "")
				case "enrollment":
					rec = request("POST", "/admin/sites/saved-site/enrollment-command", `{}`)
				}
				if rec.Code != 500 {
					t.Fatalf("failed write status %d, want 500", rec.Code)
				}
				if strings.Contains(rec.Body.String(), dir) || strings.Contains(rec.Body.String(), "bootstrap_secret") || strings.Contains(rec.Body.String(), "sha256:") {
					t.Fatal("response leaked private state")
				}
				live, _ := store.List(context.Background(), tenant)
				encodedLive, _ := json.Marshal(live)
				if !bytes.Equal(encodedBefore, encodedLive) || store.ConfigGeneration() != generation {
					t.Fatal("failed mutation changed state or generation")
				}
				if failure == "rename" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".backup", path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Remove(path + ".tmp"); err != nil {
						t.Fatal(err)
					}
				}
				disk, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(saved, disk) {
					t.Fatal("durable state changed")
				}
				// A subsequent unrelated commit must not preserve the failed update or rotation.
				if _, err := store.Upsert(context.Background(), adminSiteModel{TenantID: "other-tenant", SiteID: "later"}, now); err != nil {
					t.Fatal(err)
				}
				reloaded := newDurableAdminSiteStore(path)
				loaded, _ := reloaded.List(context.Background(), tenant)
				encodedLoaded, _ := json.Marshal(loaded)
				if !bytes.Equal(encodedBefore, encodedLoaded) {
					t.Fatal("failed mutation survived a later save and restart")
				}
				if store.ConfigGeneration() != generation+1 {
					t.Fatal("successful save did not advance generation once")
				}
				rows, err := writer.ReadJSONL("audit.log.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				success, failed := 0, 0
				for _, row := range rows {
					if row["event_type"] != "admin_config_change" {
						continue
					}
					if row["actor_user_id"] != "site-admin" || row["tenant_id"] != tenant {
						t.Fatal("wrong audit attribution")
					}
					switch row["result"] {
					case "success":
						success++
					case "error":
						failed++
					}
				}
				if success != 1 || failed != 1 {
					t.Fatalf("audit success=%d failure=%d", success, failed)
				}
			})
		}
	}
}

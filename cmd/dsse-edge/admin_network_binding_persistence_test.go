package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type refusingGovernancePersister struct {
	blobstore.Persister
	fail bool
}

func (p *refusingGovernancePersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("private database connection detail")
	}
	return p.Persister.Save(raw)
}

func TestAuthoredBindingEmptyStoreFailureAndAbsentRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.json")
	g := newConnectorRouteGovernanceWithPersistence(path)
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	if err := g.AddAuthored("new-tenant", "new-site", authoredRoute{FQDN: "unsaved.example.test"}); err == nil {
		t.Fatal("expected save failure")
	}
	if g.Export() != nil || g.ConfigGeneration() != 0 {
		t.Fatal("failed first write published a tenant or generation")
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := g.RemoveAuthored("absent-tenant", "absent-site", "fqdn:absent.example.test"); err != nil {
		t.Fatal(err)
	}
	if g.Export() != nil || g.ConfigGeneration() != 1 {
		t.Fatal("removing an absent binding created a tenant")
	}
	if err := g.AddAuthored("new-tenant", "new-site", authoredRoute{FQDN: "saved.example.test"}); err != nil {
		t.Fatal(err)
	}
	loaded := newConnectorRouteGovernanceWithPersistence(path)
	if rows := loaded.Routes("new-tenant", "new-site", nil, nil); len(rows) != 1 || rows[0].FQDN != "saved.example.test" {
		t.Fatalf("retry failed: %+v", rows)
	}
}

func TestAdminNetworkBindingPersistenceFailure(t *testing.T) {
	// Both APIs must report failure, retain routable state, and audit the refusal.
	for _, surface := range []string{"sites", "connectors"} {
		for _, fault := range []string{"temp-write", "rename", "persister"} {
			for _, operation := range []string{"add", "replace", "remove"} {
				t.Run(surface+"/"+fault+"/"+operation, func(t *testing.T) {
					dir := t.TempDir()
					path := filepath.Join(dir, "decisions.json")
					g := newConnectorRouteGovernanceWithPersistence(path)
					persister := &refusingGovernancePersister{Persister: blobstore.FilePersister{Path: path}}
					if fault == "persister" {
						g = newConnectorRouteGovernanceWithPersister("", true, persister)
					}
					previous := connectorRouteGov
					connectorRouteGov = g
					t.Cleanup(func() { connectorRouteGov = previous })
					now := time.Now().UTC()
					tenant := testEvaluator().PolicyBundle.TenantID
					registry := connector.NewRegistry()
					if _, err := registry.Register(model.ConnectorRegistration{ID: "saved-target", TenantID: tenant, ConnectorGroupID: "other-site", EdgeRegionID: "jp", PrivateBaseURL: "http://private.example.test", LastHeartbeatAt: now.Format(time.RFC3339), Status: "healthy"}, now); err != nil {
						t.Fatal(err)
					}
					creds := newLocalAdminCredentialStore("DSSE")
					seedActiveAdminAccount(t, creds, "review@example.test", tenant, "reviewer", []string{"admin", "super_admin"}, now)
					auth := newAdminAuthStore()
					auth.UpsertPrincipal(principalFromCredential(creds.byEmail["review@example.test"], now))
					auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
					writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
					if err != nil {
						t.Fatal(err)
					}
					handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: registry, AdminAuth: auth, LocalCredentials: creds, Writer: writer})
					route := "/admin/" + surface + "/saved-target/" + map[string]string{"sites": "networks", "connectors": "routes"}[surface]
					request := func(body string) *httptest.ResponseRecorder {
						req := httptest.NewRequest("POST", route, strings.NewReader(body))
						req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
						req.Header.Set("X-CSRF-Token", "review-csrf")
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
						return rec
					}
					if rec := request(`{"action":"add","fqdn":"saved.example.test","description":"Saved"}`); rec.Code != 200 {
						t.Fatalf("seed %d: %s", rec.Code, rec.Body.String())
					}
					before := g.Export()
					encodedBefore, _ := json.Marshal(before)
					generation := g.ConfigGeneration()
					saved, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "temp-write":
						err = os.Mkdir(path+".tmp", 0700)
					case "rename":
						if err = os.Rename(path, path+".backup"); err == nil {
							err = os.Mkdir(path, 0700)
						}
					case "persister":
						persister.fail = true
					}
					if err != nil {
						t.Fatal(err)
					}
					body := map[string]string{
						"add":     `{"action":"add","fqdn":"unsaved.example.test"}`,
						"replace": `{"action":"add","fqdn":"saved.example.test","description":"Unsaved"}`,
						"remove":  `{"action":"remove","fqdn":"saved.example.test"}`,
					}[operation]
					rec := request(body)
					if rec.Code != 500 || !strings.Contains(rec.Body.String(), "Could not save network binding.") {
						t.Fatalf("failure %d: %s", rec.Code, rec.Body.String())
					}
					if strings.Contains(rec.Body.String(), dir) || strings.Contains(rec.Body.String(), "private database") {
						t.Fatal("private storage error exposed")
					}
					live, _ := json.Marshal(g.Export())
					priorSnapshot, _ := json.Marshal(before)
					if !bytes.Equal(encodedBefore, live) || !bytes.Equal(encodedBefore, priorSnapshot) || g.ConfigGeneration() != generation {
						t.Fatal("failed write changed live state, exported snapshot or generation")
					}
					routes := g.Routes(tenant, "saved-target", nil, nil)
					if len(routes) != 1 || routes[0].FQDN != "saved.example.test" || routes[0].Description != "Saved" {
						t.Fatalf("failed change reached routing: %+v", routes)
					}
					switch fault {
					case "temp-write":
						err = os.Remove(path + ".tmp")
					case "rename":
						if err = os.Remove(path); err == nil {
							err = os.Rename(path+".backup", path)
						}
					case "persister":
						persister.fail = false
					}
					if err != nil {
						t.Fatal(err)
					}
					disk, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(saved, disk) {
						t.Fatal("saved state changed on refusal")
					}
					// Saving another tenant must not accidentally commit any refused change.
					if err := g.AddAuthored("other-tenant", "later", authoredRoute{FQDN: "later.example.test"}); err != nil {
						t.Fatal(err)
					}
					reloaded := newConnectorRouteGovernanceWithPersistence(path)
					loaded, _ := json.Marshal(reloaded.Export().Authored[tenant])
					wanted, _ := json.Marshal(before.Authored[tenant])
					if !bytes.Equal(loaded, wanted) || g.ConfigGeneration() != generation+1 {
						t.Fatal("refused change leaked into later commit/restart")
					}
					// The same request can be retried successfully once storage recovers.
					if rec := request(body); rec.Code != 200 {
						t.Fatalf("retry %d: %s", rec.Code, rec.Body.String())
					}
					if g.ConfigGeneration() != generation+2 {
						t.Fatal("retry did not advance generation once")
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
						if row["actor_user_id"] != "reviewer" || row["tenant_id"] != tenant || row["timestamp"] == nil {
							t.Fatal("incorrect audit attribution")
						}
						switch row["result"] {
						case "success":
							success++
						case "error":
							failed++
						}
					}
					if success != 2 || failed != 1 {
						t.Fatalf("audit success=%d error=%d", success, failed)
					}
				})
			}
		}
	}
}

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

type rejectingRoutePersister struct {
	blobstore.Persister
	fail bool
}

func (p *rejectingRoutePersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("private database connection detail")
	}
	return p.Persister.Save(raw)
}

func TestAdminNetworkBindingSaveFailureAndRetry(t *testing.T) {
	for _, surface := range []string{"sites", "connectors"} {
		for _, fault := range []string{"file", "shared-persister"} {
			for _, operation := range []string{"add", "remove"} {
				t.Run(surface+"/"+fault+"/"+operation, func(t *testing.T) {
					dir := t.TempDir()
					path := filepath.Join(dir, "decisions.json")
					g := newConnectorRouteGovernanceWithPersistence(path)
					persister := &rejectingRoutePersister{Persister: blobstore.FilePersister{Path: path}}
					if fault == "shared-persister" {
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
						req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
						req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
						req.Header.Set("X-CSRF-Token", "review-csrf")
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
						return rec
					}
					if rec := request(`{"action":"add","fqdn":"saved.example.test"}`); rec.Code != http.StatusOK {
						t.Fatalf("seed status=%d", rec.Code)
					}
					before, _ := json.Marshal(g.Export())
					generation := g.ConfigGeneration()
					saved, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if fault == "file" {
						if err := os.Mkdir(path+".tmp", 0700); err != nil {
							t.Fatal(err)
						}
					} else {
						persister.fail = true
					}
					body := `{"action":"add","fqdn":"unsaved.example.test"}`
					if operation == "remove" {
						body = `{"action":"remove","fqdn":"saved.example.test"}`
					}
					rec := request(body)
					if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Could not save network binding.") {
						t.Fatalf("save failure returned status=%d body=%s", rec.Code, rec.Body.String())
					}
					if strings.Contains(rec.Body.String(), dir) || strings.Contains(rec.Body.String(), "private database") {
						t.Fatal("storage detail exposed")
					}
					live, _ := json.Marshal(g.Export())
					if !bytes.Equal(before, live) || g.ConfigGeneration() != generation {
						t.Fatal("failed write changed live routes or generation")
					}
					if disk, err := os.ReadFile(path); err != nil || !bytes.Equal(saved, disk) {
						t.Fatal("failed write changed saved routes")
					}
					if fault == "file" {
						if err := os.Remove(path + ".tmp"); err != nil {
							t.Fatal(err)
						}
					} else {
						persister.fail = false
					}
					if rec := request(body); rec.Code != http.StatusOK {
						t.Fatalf("retry status=%d", rec.Code)
					}
					if g.ConfigGeneration() != generation+1 {
						t.Fatal("retry did not publish exactly once")
					}
					reloaded := newConnectorRouteGovernanceWithPersistence(path)
					routes := reloaded.Routes(tenant, "saved-target", nil, nil)
					if operation == "add" && (len(routes) != 2 || routes[1].FQDN != "unsaved.example.test") {
						t.Fatalf("add not retained after reload: %+v", routes)
					}
					if operation == "remove" && len(routes) != 0 {
						t.Fatalf("remove not retained after reload: %+v", routes)
					}
					rows, err := writer.ReadJSONL("audit.log.jsonl")
					if err != nil {
						t.Fatal(err)
					}
					var successes, failures, bindingSuccesses, bindingFailures int
					for _, row := range rows {
						if row["event_type"] != "admin_config_change" && row["event_type"] != "admin_route_binding_changed" {
							continue
						}
						if row["actor_user_id"] != "reviewer" || row["tenant_id"] != tenant {
							t.Fatal("incorrect audit attribution")
						}
						if row["event_type"] == "admin_route_binding_changed" {
							if row["target_type"] != "route_binding" || row["target_id"] != "saved-target" {
								t.Fatal("incorrect route-binding audit target")
							}
							switch row["result"] {
							case "success":
								bindingSuccesses++
							case "error":
								bindingFailures++
							}
							continue
						}
						switch row["result"] {
						case "success":
							successes++
						case "error":
							failures++
						}
					}
					if successes != 2 || failures != 1 || bindingSuccesses != 2 || bindingFailures != 1 {
						t.Fatalf("config audit success=%d error=%d, binding audit success=%d error=%d", successes, failures, bindingSuccesses, bindingFailures)
					}
				})
			}
		}
	}
}

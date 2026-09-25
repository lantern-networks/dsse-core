package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// A published application's catalog entry and selectable rule destination use
// different stores. Failure of the latter must never be acknowledged as success.
func TestApplicationAssetSaveFailureIsPartial(t *testing.T) {
	for _, operation := range []string{"publish", "unpublish", "delete"} {
		t.Run(operation, func(t *testing.T) {
			assetStore := assetcatalog.NewStore()
			persisted := &memoryPersister{}
			gate := &rejectingRoutePersister{Persister: persisted}
			if err := assetStore.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			handler := newServerWithConfig(serverConfig{
				Evaluator:        testEvaluator(),
				Registry:         connector.NewRegistry(),
				AdminAuth:        newAdminAuthStore(),
				AssetStore:       assetStore,
				Writer:           writer,
				AdminAuditOutbox: outbox,
			})
			request := func(method, path, body string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
				return rec
			}
			path := "/admin/applications/wiki"
			seed := request(http.MethodPost, path+"/publish", `{"name":"Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`)
			if seed.Code != http.StatusOK {
				t.Fatalf("seed publish: %d %s", seed.Code, seed.Body.String())
			}
			before := len(outbox.insertedAudits)
			generation := assetStore.ConfigGeneration()
			gate.fail = true
			var rec *httptest.ResponseRecorder
			wantEvent := "admin_application_published"
			switch operation {
			case "publish":
				rec = request(http.MethodPost, path+"/publish", `{"name":"Wiki Updated","destination":"wiki2.example.test","destination_port":443,"publish_protocol":"web"}`)
			case "unpublish":
				wantEvent = "admin_application_unpublished"
				rec = request(http.MethodPost, path+"/unpublish", "")
			case "delete":
				wantEvent = "admin_application_deleted"
				rec = request(http.MethodDelete, path, "")
			}
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("failed %s returned %d: %s", operation, rec.Code, rec.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response["partial"] != true {
				t.Fatalf("failed %s response = %#v, err=%v", operation, response, err)
			}
			if strings.Contains(rec.Body.String(), "private database connection detail") {
				t.Fatal("storage detail escaped in response")
			}
			if endpoint, found := assetStore.GetEndpoint("tenant_lab_001", "app-wiki"); !found || endpoint.Address != "wiki.example.test" || assetStore.ConfigGeneration() != generation {
				t.Fatalf("failed %s changed live destination or generation: %+v found=%v generation=%d", operation, endpoint, found, assetStore.ConfigGeneration())
			}
			// The first store has moved while the durable rule destination has not.
			// A 200 would misrepresent this observable disagreement to the operator.
			app := request(http.MethodGet, path, "")
			if operation == "delete" {
				if app.Code != http.StatusNotFound {
					t.Fatalf("deleted app status = %d, want 404", app.Code)
				}
			} else {
				if app.Code != http.StatusOK {
					t.Fatalf("changed app status = %d", app.Code)
				}
				var body map[string]any
				if err := json.Unmarshal(app.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if operation == "publish" && body["destination"] != "wiki2.example.test" || operation == "unpublish" && body["published"] == true {
					t.Fatalf("application change was not observable: %#v", body)
				}
			}
			reloadedAssets := assetcatalog.NewStore()
			if err := reloadedAssets.SetPersister(persisted); err != nil {
				t.Fatal(err)
			}
			endpoint, found := reloadedAssets.GetEndpoint("tenant_lab_001", "app-wiki")
			if !found || endpoint.Address != "wiki.example.test" {
				t.Fatalf("durable rule destination changed despite rejected save: %+v found=%v", endpoint, found)
			}
			if len(outbox.insertedAudits) != before+1 {
				t.Fatalf("failed %s audits = %d, want one result audit", operation, len(outbox.insertedAudits)-before)
			}
			audit := outbox.insertedAudits[before]
			if audit.EventType != wantEvent || audit.Result == nil || *audit.Result != "partial" || audit.Metadata["asset_endpoint_persistence_confirmed"] != false {
				t.Fatalf("failed %s audit = %#v", operation, audit)
			}
		})
	}
}

func TestApplicationPublishCannotReplaceManualEndpointWithoutEndpointScope(t *testing.T) {
	assets := assetcatalog.NewStore()
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "app-wiki", TenantID: "tenant_lab_001", Alias: "operator destination", Kind: assetcatalog.KindNetwork, Address: "operator.example.test", Source: assetcatalog.SourceManual}); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	auth.UpsertPrincipal(adminPrincipal{ID: "app-operator", TenantID: "tenant_lab_001", Subject: "app-operator", Email: "operator@example.test", Roles: []string{"admin"}, Status: "active", CreatedAt: now.Format(time.RFC3339)})
	auth.UpsertAPIToken(adminAPIToken{ID: "app-only", TenantID: "tenant_lab_001", Name: "app-only", TokenHash: adminTokenHash("app-only-token"), Roles: []string{"admin"}, Scopes: []string{"admin.applications.write", "admin.applications.read"}, CreatedByAdminPrincipalID: "app-operator", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: auth, AssetStore: assets, Writer: writer})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer app-only-token")
		handler.ServeHTTP(rec, req)
		return rec
	}
	path := "/admin/applications/wiki"
	if rec := request(http.MethodPost, path+"/publish", `{"name":"Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("publish over manual destination = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := request(http.MethodGet, path, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("denied publish changed application = %d", rec.Code)
	}
	if endpoint, found := assets.GetEndpoint("tenant_lab_001", "app-wiki"); !found || endpoint.Address != "operator.example.test" {
		t.Fatalf("manual endpoint changed: %+v found=%v", endpoint, found)
	}
}

func TestApplicationAssetDeleteRetryPersistsAfterPartialFailure(t *testing.T) {
	for _, operation := range []string{"unpublish", "delete"} {
		t.Run(operation, func(t *testing.T) {
			assetStore := assetcatalog.NewStore()
			persisted := &memoryPersister{}
			gate := &rejectingRoutePersister{Persister: persisted}
			if err := assetStore.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			appPath := filepath.Join(t.TempDir(), "applications.json")
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), AssetStore: assetStore, ApplicationCatalogStorePath: appPath, Writer: writer, AdminAuditOutbox: outbox})
			request := func(method, path, body string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
				return rec
			}
			path := "/admin/applications/wiki"
			if rec := request(http.MethodPost, path+"/publish", `{"name":"Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`); rec.Code != http.StatusOK {
				t.Fatalf("seed publish = %d: %s", rec.Code, rec.Body.String())
			}
			method, route := http.MethodPost, path+"/unpublish"
			if operation == "delete" {
				method, route = http.MethodDelete, path
			}
			gate.fail = true
			if rec := request(method, route, ""); rec.Code != http.StatusInternalServerError {
				t.Fatalf("first %s = %d", operation, rec.Code)
			}
			if len(outbox.insertedAudits) != 2 || outbox.insertedAudits[1].Result == nil || *outbox.insertedAudits[1].Result != "partial" {
				t.Fatalf("failed %s did not emit only a partial result audit: %+v", operation, outbox.insertedAudits)
			}
			gate.fail = false
			// A restarted control plane reloads both durable stores before retry.
			assetStore = assetcatalog.NewStore()
			if err := assetStore.SetPersister(gate); err != nil {
				t.Fatal(err)
			}
			handler = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), AssetStore: assetStore, ApplicationCatalogStorePath: appPath, Writer: writer, AdminAuditOutbox: outbox})
			if rec := request(method, route, ""); rec.Code != http.StatusOK {
				t.Fatalf("retry %s = %d: %s", operation, rec.Code, rec.Body.String())
			}
			reloaded := assetcatalog.NewStore()
			if err := reloaded.SetPersister(persisted); err != nil {
				t.Fatal(err)
			}
			if endpoint, found := reloaded.GetEndpoint("tenant_lab_001", "app-wiki"); found {
				t.Fatalf("%s retry left durable endpoint: %+v", operation, endpoint)
			}
			if len(outbox.insertedAudits) != 3 || outbox.insertedAudits[2].Result != nil && *outbox.insertedAudits[2].Result == "partial" {
				t.Fatalf("%s retry did not emit a success result audit: %+v", operation, outbox.insertedAudits)
			}
		})
	}
}

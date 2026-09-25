package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestApplicationCatalogSaveFailureAndRetry(t *testing.T) {
	for _, operation := range []string{"create", "edit", "publish", "unpublish", "delete"} {
		t.Run(operation, func(t *testing.T) {
			const tenant = "tenant_lab_001"
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "private-app-storage.json")
			apps := appcatalog.NewStore()
			if err := apps.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			assets := assetcatalog.NewStore()
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), ApplicationCatalogStore: apps, AssetStore: assets, Writer: writer, AdminAuditOutbox: outbox})
			request := func(method, url, body string) *httptest.ResponseRecorder {
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest(method, url, strings.NewReader(body)))
				return r
			}
			seed := request(http.MethodPost, "/admin/applications/wiki/publish", `{"name":"Wiki","destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`)
			if seed.Code != 200 {
				t.Fatalf("seed: %d %s", seed.Code, seed.Body.String())
			}
			method, url, body := http.MethodPost, "/admin/applications", `{"application_id":"new","name":"New"}`
			switch operation {
			case "edit":
				body = `{"application_id":"wiki","name":"Renamed","published":true,"destination":"wiki.example.test","destination_port":443,"publish_protocol":"web"}`
			case "publish":
				url = "/admin/applications/wiki/publish"
				body = `{"name":"Wiki","destination":"new.example.test","destination_port":443,"publish_protocol":"web"}`
			case "unpublish":
				url = "/admin/applications/wiki/unpublish"
				body = ""
			case "delete":
				method = http.MethodDelete
				url = "/admin/applications/wiki"
				body = ""
			}
			beforeHTTP := request(http.MethodGet, "/admin/applications/wiki", "")
			beforeAudits := len(outbox.insertedAudits)
			before, err := apps.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			endpoint, _ := assets.GetEndpoint(tenant, "app-wiki")
			generation := assets.ConfigGeneration()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path+".tmp", 0700); err != nil {
				t.Fatal(err)
			}
			failed := request(method, url, body)
			if failed.Code != http.StatusServiceUnavailable {
				t.Fatalf("save failure: status=%d body=%s", failed.Code, failed.Body.String())
			}
			if strings.Contains(failed.Body.String(), path) || strings.Contains(failed.Body.String(), ".tmp") {
				t.Fatal("private persistence path exposed")
			}
			afterHTTP := request(http.MethodGet, "/admin/applications/wiki", "")
			if beforeHTTP.Code != afterHTTP.Code || beforeHTTP.Body.String() != afterHTTP.Body.String() {
				t.Fatal("failed save changed product GET")
			}
			if len(outbox.insertedAudits) != beforeAudits {
				t.Fatal("failed save emitted a successful application audit")
			}
			after, err := apps.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected application changed live state")
			}
			current, _ := assets.GetEndpoint(tenant, "app-wiki")
			if !reflect.DeepEqual(endpoint, current) || generation != assets.ConfigGeneration() {
				t.Fatal("rejected application changed rule destination")
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != string(saved) {
				t.Fatal("rejected application changed disk")
			}
			failedAudit := outbox.wrapperAudits[len(outbox.wrapperAudits)-1]
			if failedAudit.Result == nil || *failedAudit.Result == "success" || failedAudit.TenantID != tenant || failedAudit.ActorUserID == nil {
				t.Fatalf("failure audit: %+v", failedAudit)
			}
			if err := os.Remove(path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			if _, err := apps.Upsert(ctx, appcatalog.Entry{ApplicationID: "unrelated"}, "other-tenant", time.Now()); err != nil {
				t.Fatal(err)
			}
			fresh := appcatalog.NewStore()
			if err := fresh.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			reload, err := fresh.ExportSnapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before[tenant], reload[tenant]) {
				t.Fatal("unrelated save persisted rejected change")
			}
			retried := request(method, url, body)
			if retried.Code != http.StatusOK {
				t.Fatalf("retry: %d %s", retried.Code, retried.Body.String())
			}
			final := appcatalog.NewStore()
			if err := final.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			live, _ := apps.ExportSnapshot(ctx)
			durable, _ := final.ExportSnapshot(ctx)
			if !reflect.DeepEqual(live, durable) {
				t.Fatal("successful retry differs from reloaded catalog")
			}
			if len(outbox.insertedAudits) != beforeAudits+1 {
				t.Fatal("successful retry missing application audit")
			}
			successAudit := outbox.wrapperAudits[len(outbox.wrapperAudits)-1]
			if successAudit.Result == nil || *successAudit.Result != "success" || successAudit.TenantID != tenant {
				t.Fatalf("success audit: %+v", successAudit)
			}
		})
	}
}

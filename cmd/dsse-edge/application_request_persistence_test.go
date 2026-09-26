package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
)

type cancelAfterApplicationSave struct {
	*appcatalog.Store
	cancel context.CancelFunc
}

func (s *cancelAfterApplicationSave) Upsert(ctx context.Context, e appcatalog.Entry, tenant string, now time.Time) (appcatalog.Entry, error) {
	saved, err := s.Store.Upsert(ctx, e, tenant, now)
	if err == nil {
		s.cancel()
	}
	return saved, err
}
func (s *cancelAfterApplicationSave) Delete(ctx context.Context, tenant, id string) error {
	err := s.Store.Delete(ctx, tenant, id)
	if err == nil {
		s.cancel()
	}
	return err
}

func TestApplicationCanceledAfterPrimarySaveDoesNotAcknowledgeDestination(t *testing.T) {
	for _, op := range []string{"publish", "unpublish", "delete", "rename"} {
		t.Run(op, func(t *testing.T) {
			const tenant = "tenant_lab_001"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			apps := &cancelAfterApplicationSave{Store: appcatalog.NewStore(), cancel: cancel}
			assets := assetcatalog.NewStore()
			disk := &sharedCPAssetBlob{}
			if err := assets.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			row := appcatalog.Entry{ApplicationID: "wiki", Name: "Original", ApplicationType: "private_app", Published: true, Destination: "wiki.example.test", DestinationPort: 443, PublishProtocol: "web", Status: "active"}
			if _, err := apps.Store.Upsert(context.Background(), row, tenant, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := assets.UpsertApplicationEndpoint("wiki", assetcatalog.Endpoint{TenantID: tenant, Alias: "Original", Kind: assetcatalog.KindNetwork, Address: "wiki.example.test"}, false); err != nil {
				t.Fatal(err)
			}
			before, _ := disk.Load()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), AssetStore: assets, ApplicationCatalogStore: apps})
			method, path, body := "POST", "/admin/applications/wiki/"+op, `{"name":"Changed","destination":"new.example.test","destination_port":443,"publish_protocol":"web"}`
			if op == "delete" {
				method, path = "DELETE", "/admin/applications/wiki"
			}
			if op == "rename" {
				path = "/admin/applications"
				row.Name = "Changed"
				raw, _ := json.Marshal(row)
				body = string(raw)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx))
			if rec.Code != 500 {
				t.Fatalf("interrupted second save acknowledged: %d %s", rec.Code, rec.Body)
			}
			var result map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result["partial"] != true {
				t.Fatal("missing partial result")
			}
			after, _ := disk.Load()
			if string(after) != string(before) {
				t.Fatal("canceled request changed shared destination")
			}
			// Reload the shared destination and retry with an active request. The primary
			// application save may already be present (or absent after deletion).
			fresh := assetcatalog.NewStore()
			if err := fresh.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			apps.cancel = func() {}
			retry := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), AssetStore: fresh, ApplicationCatalogStore: apps})
			rec = httptest.NewRecorder()
			retry.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
			if rec.Code != 200 {
				t.Fatalf("retry failed: %d %s", rec.Code, rec.Body)
			}
			final := assetcatalog.NewStore()
			if err := final.SetPersister(disk); err != nil {
				t.Fatal(err)
			}
			ep, found := final.GetEndpoint(tenant, "app-wiki")
			if op == "delete" || op == "unpublish" {
				if found {
					t.Fatal("retry left destination")
				}
			} else if !found || ep.Alias != "Changed" {
				t.Fatal("retry did not persist destination")
			}
		})
	}
}

func TestApplicationCannotChangeBuiltInDestinationBeforeRefusal(t *testing.T) {
	for _, op := range []string{"publish", "unpublish", "delete", "rename"} {
		t.Run(op, func(t *testing.T) {
			const tenant = "tenant_lab_001"
			apps := appcatalog.NewStore()
			assets := assetcatalog.NewStore()
			row := appcatalog.Entry{ApplicationID: "wiki", Name: "Original", ApplicationType: "private_app", Published: true, Destination: "wiki.example.test", DestinationPort: 443, PublishProtocol: "web", Status: "active"}
			if _, err := apps.Upsert(context.Background(), row, tenant, time.Now()); err != nil {
				t.Fatal(err)
			}
			assets.SetBuiltInCatalog([]assetcatalog.Endpoint{{ID: "app-wiki", TenantID: tenant, Alias: "Original", Kind: assetcatalog.KindNetwork, Address: "managed.example.test", Source: assetcatalog.SourceApplication}}, nil)
			before, _, _ := apps.Get(context.Background(), tenant, "wiki")
			rawBefore, _ := json.Marshal(before)
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), AssetStore: assets, ApplicationCatalogStore: apps})
			method, path, body := "POST", "/admin/applications/wiki/"+op, `{"name":"Changed","destination":"new.example.test","destination_port":443,"publish_protocol":"web"}`
			if op == "delete" {
				method, path = "DELETE", "/admin/applications/wiki"
			}
			if op == "rename" {
				path = "/admin/applications"
				row.Name = "Changed"
				raw, _ := json.Marshal(row)
				body = string(raw)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
			if rec.Code != 403 {
				t.Fatalf("immutable destination not refused before saving application: %d %s", rec.Code, rec.Body)
			}
			after, found, _ := apps.Get(context.Background(), tenant, "wiki")
			rawAfter, _ := json.Marshal(after)
			if !found || string(rawBefore) != string(rawAfter) {
				t.Fatal("application changed before ownership refusal")
			}
		})
	}
}

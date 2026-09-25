package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAssetAdminRecordsTargetedDomainAudits(t *testing.T) {
	const tenant = "tenant_lab_001"
	p := &assetDurabilityPersister{}
	store := assetcatalog.NewStore()
	if err := store.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, AssetStore: store,
		AdminAuth: newAdminAuthStore(), Writer: writer, AdminAuditOutbox: outbox})
	for _, op := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/admin/assets/endpoints", `{"id":"endpoint-one","kind":"network","alias":"secret-host","address":"host.example.invalid"}`, 200},
		{http.MethodPost, "/admin/assets/groups", `{"id":"group-one","alias":"secret-group","static_members":["endpoint-one"]}`, 200},
		{http.MethodPost, "/admin/assets/services", `{"id":"service-one","alias":"secret-service","ports":[{"protocol":"tcp","port":22}]}`, 200},
		{http.MethodDelete, "/admin/assets/groups/group-one", "", 200},
		{http.MethodDelete, "/admin/assets/services/service-one", "", 200},
		{http.MethodDelete, "/admin/assets/endpoints/endpoint-one", "", 200},
		{http.MethodPost, "/admin/assets/endpoints", `{"id":"endpoint-two","kind":"network","alias":"secret-second-host","address":"second.example.invalid"}`, 200},
	} {
		rec := doAdmin(t, h, op.method, op.path, op.body)
		if rec.Code != op.status {
			t.Fatalf("%s %s: %d %s", op.method, op.path, rec.Code, rec.Body.String())
		}
	}
	p.fail = true
	beforeGeneration := store.ConfigGeneration()
	if rec := doAdmin(t, h, http.MethodPost, "/admin/assets/groups", `{"id":"failed-group","alias":"secret-failed"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed group status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doAdmin(t, h, http.MethodPost, "/admin/assets/endpoints", `{"id":"failed-endpoint","kind":"network","alias":"secret-failed-host","address":"failed.example.invalid"}`); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "private-storage-location") {
		t.Fatalf("failed endpoint status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doAdmin(t, h, http.MethodDelete, "/admin/assets/endpoints/endpoint-two", ""); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "private-storage-location") {
		t.Fatalf("failed endpoint deletion status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := store.GetEndpoint(tenant, "endpoint-two"); !ok || store.ConfigGeneration() != beforeGeneration {
		t.Fatal("refused endpoint saves changed the live catalog")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.insertedAudits) != 10 {
		t.Fatalf("domain audits=%d, want 10", len(outbox.insertedAudits))
	}
	wantTargets := []struct{ kind, id, action string }{
		{"asset_endpoint", "endpoint-one", "upsert"},
		{"asset_group", "group-one", "upsert"},
		{"asset_service", "service-one", "upsert"},
		{"asset_group", "group-one", "delete"},
		{"asset_service", "service-one", "delete"},
		{"asset_endpoint", "endpoint-one", "delete"},
		{"asset_endpoint", "endpoint-two", "upsert"},
		{"asset_group", "failed-group", "upsert"},
		{"asset_endpoint", "failed-endpoint", "upsert"},
		{"asset_endpoint", "endpoint-two", "delete"},
	}
	for i, row := range outbox.insertedAudits {
		wantResult := "saved"
		if i >= 7 {
			wantResult = "persistence_unconfirmed"
		}
		if row.EventType != "admin_asset_catalog_changed" || row.TenantID != tenant || row.ActorUserID == nil || *row.ActorUserID == "" ||
			row.TargetType == nil || *row.TargetType != wantTargets[i].kind || row.TargetID == nil || *row.TargetID != wantTargets[i].id ||
			row.Action == nil || *row.Action != wantTargets[i].action || row.Result == nil || *row.Result != wantResult {
			t.Fatalf("domain audit %d lacks actor/tenant/target/outcome: %+v", i, row)
		}
		for _, private := range []string{"secret-host", "secret-group", "secret-service", "secret-failed", "host.example.invalid", "failed.example.invalid", "second.example.invalid", "private-storage-location"} {
			raw, _ := json.Marshal(row)
			if strings.Contains(string(raw), private) {
				t.Fatalf("domain audit %d leaked catalog data", i)
			}
		}
	}
	if len(outbox.wrapperAudits) != 10 {
		t.Fatalf("common audits=%d, want 10", len(outbox.wrapperAudits))
	}
}

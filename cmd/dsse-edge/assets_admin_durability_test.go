package main

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
)

type assetDurabilityPersister struct {
	raw  []byte
	fail bool
}

func (p *assetDurabilityPersister) Load() ([]byte, error) { return bytes.Clone(p.raw), nil }
func (p *assetDurabilityPersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("private-storage-location")
	}
	p.raw = bytes.Clone(raw)
	return nil
}

func TestAssetAdminRejectsUnconfirmedGroupCreateAndServiceDelete(t *testing.T) {
	const tenant = "tenant_lab_001"
	p := &assetDurabilityPersister{}
	store := assetcatalog.NewStore()
	if err := store.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertService(assetcatalog.Service{ID: "service-one", TenantID: tenant, Alias: "SSH", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 22}}}); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, AssetStore: store, AdminAuth: newAdminAuthStore(), Writer: writer, AdminAuditOutbox: outbox})
	beforeGeneration, beforeRaw := store.ConfigGeneration(), bytes.Clone(p.raw)
	p.fail = true
	for _, op := range []struct{ method, path, body string }{
		{http.MethodPost, "/admin/assets/groups", `{"id":"group-one","alias":"Operators"}`},
		{http.MethodDelete, "/admin/assets/services/service-one", ""},
	} {
		rec := doAdmin(t, h, op.method, op.path, op.body)
		if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "private-storage-location") {
			t.Fatalf("%s %s status=%d body=%s", op.method, op.path, rec.Code, rec.Body.String())
		}
		if len(store.ListGroups(tenant)) != 0 || len(store.ListServices(tenant)) != 1 || store.ConfigGeneration() != beforeGeneration || !bytes.Equal(p.raw, beforeRaw) {
			t.Fatal("unconfirmed API request changed live or saved catalog")
		}
	}
	p.fail = false
	if rec := doAdmin(t, h, http.MethodPost, "/admin/assets/groups", `{"id":"group-one","alias":"Operators"}`); rec.Code != http.StatusOK {
		t.Fatalf("group retry: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAdmin(t, h, http.MethodDelete, "/admin/assets/services/service-one", ""); rec.Code != http.StatusOK {
		t.Fatalf("service retry: %d %s", rec.Code, rec.Body.String())
	}
	reloaded := assetcatalog.NewStore()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.ListGroups(tenant)) != 1 || len(reloaded.ListServices(tenant)) != 0 {
		t.Fatal("confirmed API retry was not durable")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	if len(outbox.wrapperAudits) != 4 {
		t.Fatalf("HTTP audit count=%d, want 4", len(outbox.wrapperAudits))
	}
	for i, row := range outbox.wrapperAudits {
		want := "error"
		if i >= 2 {
			want = "success"
		}
		if row.Result == nil || *row.Result != want || row.ActorUserID == nil || *row.ActorUserID == "" || row.TenantID != tenant {
			t.Fatalf("HTTP audit %d: result=%v actor=%v tenant=%q", i, row.Result, row.ActorUserID, row.TenantID)
		}
	}
}

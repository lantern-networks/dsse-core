package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/catalogfeed"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPostgresCatalogOverridePeerTermAndEngine(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "catalog_overrides"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved != nil {
			p.Save(saved)
		} else {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		}
	}()
	x, y := knownbypass.NewOverrideStore(), knownbypass.NewOverrideStore()
	for _, s := range []*knownbypass.OverrideStore{x, y} {
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	now := time.Now()
	if _, e := y.Set("foreign", knownbypass.Override{EntryID: "github_asset_cdn", Mode: "force_inspect"}, now); e != nil {
		t.Fatal(e)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "override-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "override-session", TenantID: tenant, AdminPrincipalID: "override-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "override-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	oldE := cpLeaderElectorInstance
	defer func() { cpLeaderElectorInstance = oldE }()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	posture := inspectionposture.NewStore()
	rules := policyrule.NewStore()
	assets := assetcatalog.NewStore()
	apply := newTenantInspectionApplier(engine, posture, rules, assets, x, func() []knownbypass.Group { return knownbypass.Catalog().Entries }, []string{"*"}, nil)
	apply("")
	config := serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: tenant, CatalogOverrides: x, NetworkExtensionLabTLS: engine, InspectionPosture: posture.Get, ApplyMaterializedCertPinBypass: apply, RuleStore: rules, AssetStore: assets}
	h := newServerWithConfig(config)
	cpLeaderElectorInstance = a
	a.tick()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "override-session"})
		r.Header.Set("X-CSRF-Token", "override-csrf")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	inspecting := func(tenant string) bool {
		return engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "github.githubassets.com", Port: 443})
	}
	bodyText := `{"entry_id":"github_asset_cdn","mode":"force_inspect","reason":"shared test"}`
	for _, withFeed := range []bool{false, true} {
		if withFeed {
			config.CatalogFeed = catalogfeed.NewStore(nil)
			h = newServerWithConfig(config)
		}
		before, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		oldMatch := inspecting(tenant)
		body := &pausedSeatBody{Reader: strings.NewReader(bodyText), entered: make(chan struct{}), resume: make(chan struct{})}
		r := httptest.NewRequest("POST", "/admin/predefined-catalog/overrides", body)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "override-session"})
		r.Header.Set("X-CSRF-Token", "override-csrf")
		rr := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); h.ServeHTTP(rr, r) }()
		select {
		case <-body.entered:
		case <-done:
			t.Fatalf("body unread %d", rr.Code)
		case <-time.After(5 * time.Second):
			t.Fatal("body timeout")
		}
		a.release()
		b.tick()
		if !b.IsLeader() {
			t.Fatal("peer not elected")
		}
		b.release()
		a.tick()
		if !a.IsLeader() {
			t.Fatal("not reelected")
		}
		close(body.resume)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("response timeout")
		}
		after, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		if rr.Code != 500 || !bytes.Equal(before, after) || inspecting(tenant) != oldMatch {
			t.Fatalf("stale term changed DB/engine: %d %s", rr.Code, rr.Body)
		}
		if rr := request("POST", "/admin/predefined-catalog/overrides", bodyText); rr.Code != 200 {
			t.Fatalf("fresh %d %s", rr.Code, rr.Body)
		}
		if !inspecting(tenant) || !inspecting("foreign") {
			t.Fatal("fresh peer state not applied to engine")
		}
	}
	// A stale instance's clear and purge retain the acceptance term.
	stale := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	if _, e := y.ClearContext(stale, tenant, "github_asset_cdn"); e == nil {
		t.Fatal("old clear accepted")
	}
	if _, e := y.RemoveTenantContext(stale, tenant); e == nil {
		t.Fatal("old purge accepted")
	}
	// A peer removes our override; checked reads must reflect it in the local engine.
	if ok, e := y.ClearContext(captureCPWriteLease(context.Background()), tenant, "github_asset_cdn"); e != nil || !ok {
		t.Fatalf("peer clear %v %v", ok, e)
	}
	if rr := request("GET", "/admin/inspection-posture", ""); rr.Code != 200 {
		t.Fatalf("checked posture %d %s", rr.Code, rr.Body)
	}
	if inspecting(tenant) || !inspecting("foreign") {
		t.Fatal("refreshed engine lost scope or retained cleared override")
	}
	if rr := request("POST", "/admin/predefined-catalog/overrides", bodyText); rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	if rr := request("POST", "/admin/predefined-catalog/overrides/github_asset_cdn/clear", ""); rr.Code != 200 {
		t.Fatalf("clear %d %s", rr.Code, rr.Body)
	}
	if inspecting(tenant) || !inspecting("foreign") {
		t.Fatal("clear did not apply")
	}
	restored := knownbypass.NewOverrideStore()
	if e := restored.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if len(restored.List(tenant)) != 0 || len(restored.List("foreign")) != 1 {
		t.Fatal("restore differs")
	}
	raw, e := p.Load()
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Save([]byte(`null`)); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/admin/predefined-catalog", "/admin/inspection-posture", "/admin/intercept/bypass-hosts", "/admin/effective-policy?destination=github.githubassets.com", "/admin/egress-effective-rules"} {
		if rr := request("GET", path, ""); rr.Code != 503 {
			t.Fatalf("corrupt authority %s %d", path, rr.Code)
		}
	}
	if inspecting(tenant) || !inspecting("foreign") {
		t.Fatal("failed refresh changed engine")
	}
	if e = p.Save(raw); e != nil {
		t.Fatal(e)
	}
	if n, e := restored.RemoveTenantContext(captureCPWriteLease(context.Background()), "foreign"); e != nil || n != 1 {
		t.Fatalf("purge %d %v", n, e)
	}
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, w) {
		if row.EventType == "admin_config_change" && row.TargetID != nil && strings.HasPrefix(*row.TargetID, "/admin/predefined-catalog/overrides") && row.Result != nil {
			outcomes[*row.Result]++
		}
	}
	if outcomes["error"] != 2 || outcomes["success"] != 4 {
		raw, _ := json.Marshal(outcomes)
		t.Fatalf("audit %s", raw)
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPostgresInspectionPosturePeerTermBundleAudit(t *testing.T) {
	leader, peerLeader := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "inspection_posture"}
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
	a, b := inspectionposture.NewStore(), inspectionposture.NewStore()
	for _, s := range []*inspectionposture.Store{a, b} {
		if _, e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	initial := inspectionposture.DefaultPosture()
	initial.BypassGroups = []string{"m365_optimize"}
	if _, e := b.Set(initial); e != nil {
		t.Fatal(e)
	}
	if got, e := a.InitializeContext(context.Background(), inspectionposture.DefaultPosture()); e != nil || len(got.BypassGroups) != 1 {
		t.Fatalf("seed %+v %v", got, e)
	}
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	cpLeaderElectorInstance = leader
	edgeIsControlPlane = true
	leader.tick()
	now := time.Now()
	tenant := testEvaluator().PolicyBundle.TenantID
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "posture-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "posture-session", TenantID: tenant, AdminPrincipalID: "posture-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "posture-csrf"}})
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	controller := newInspectionPostureAdmin(a, func(string) { engine.SetInterceptHosts(inspectionposture.EffectiveInterceptHosts(a.Get())) })
	config := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: tenant, InspectionPosture: a.Get, InspectionPostureGeneration: a.ConfigGeneration, SetInspectionPosture: controller.set, UpdateInspectionPosture: controller.update, RefreshInspectionPosture: controller.refresh, NetworkExtensionLabTLS: engine}
	h := newServerWithConfig(config)
	req := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "posture-session"})
		r.Header.Set("X-CSRF-Token", "posture-csrf")
		return r
	}
	call := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(method, path, body))
		if w.Code != status {
			t.Fatalf("%s %d want %d: %s", path, w.Code, status, w.Body)
		}
		return w
	}
	raw, _ := p.Load()
	gen := a.ConfigGeneration()
	paused := &pausedSeatBody{Reader: strings.NewReader(`{"known_bypass_enabled":false}`), entered: make(chan struct{}), resume: make(chan struct{})}
	r := req("POST", "/admin/inspection-posture", "")
	r.Body = paused
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	select {
	case <-paused.entered:
	case <-done:
		t.Fatalf("body unread %d", w.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("body timeout")
	}
	leader.release()
	peerLeader.tick()
	if !peerLeader.IsLeader() {
		t.Fatal("peer not leader")
	}
	peerLeader.release()
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("not reelected")
	}
	close(paused.resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request timeout")
	}
	after, _ := p.Load()
	if w.Code != 500 || !bytes.Equal(raw, after) || a.ConfigGeneration() != gen {
		t.Fatalf("old term %d", w.Code)
	}
	fresh := initial
	fresh.Mode = inspectionposture.ModeBypassDefault
	fresh.DecryptAllowlistHosts = []string{"peer.invalid"}
	if _, e := b.SetContext(captureCPWriteLease(context.Background()), fresh); e != nil {
		t.Fatal(e)
	}
	call("POST", "/admin/inspection-posture", `{"known_bypass_enabled":false}`, 200)
	if got := a.Get(); got.Mode != fresh.Mode || !reflect.DeepEqual(got.DecryptAllowlistHosts, fresh.DecryptAllowlistHosts) || got.KnownBypassEnabled {
		t.Fatalf("peer lost %+v", got)
	}
	if !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "peer.invalid", Port: 443}) || engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "other.invalid", Port: 443}) {
		t.Fatal("engine mismatch")
	}
	fresh = a.Get()
	fresh.BypassGroups = nil
	fresh.DecryptAllowlistHosts = []string{"new-peer.invalid"}
	if _, e := b.SetContext(captureCPWriteLease(context.Background()), fresh); e != nil {
		t.Fatal(e)
	}
	call("POST", "/admin/inspection-posture", `{"bypass_groups":["m365_optimize"]}`, 409)
	gen = a.ConfigGeneration()
	bundle := call("GET", "/admin/config-bundle", "", 200)
	var payload configBundlePayload
	if e := json.Unmarshal(bundle.Body.Bytes(), &payload); e != nil {
		t.Fatal(e)
	}
	if payload.InspectionPosture == nil || !reflect.DeepEqual(payload.InspectionPosture.Posture, a.Get()) || a.ConfigGeneration() <= gen {
		t.Fatal("bundle not refreshed")
	}
	if !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "new-peer.invalid", Port: 443}) {
		t.Fatal("refresh not applied")
	}
	stable := a.Get()
	gen = a.ConfigGeneration()
	raw, _ = p.Load()
	if e := p.Save([]byte(`null`)); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/admin/inspection-posture", "/admin/config-bundle", "/admin/egress-effective-rules", "/admin/effective-policy?destination=peer.invalid", "/admin/intercept/bypass-hosts"} {
		call("GET", path, "", 503)
	}
	call("POST", "/admin/inspection-posture", `{"mode":"decrypt_all"}`, 500)
	if !reflect.DeepEqual(a.Get(), stable) || a.ConfigGeneration() != gen {
		t.Fatal("corrupt authority changed live")
	}
	if e := p.Save(raw); e != nil {
		t.Fatal(e)
	}
	call("POST", "/admin/inspection-posture", `{"mode":"decrypt_all"}`, 200)
	restored := inspectionposture.NewStore()
	if _, e := restored.SetPersister(p); e != nil || !reflect.DeepEqual(restored.Get(), a.Get()) {
		t.Fatal("restart differs", e)
	}
	outcomes := map[string]int{}
	knownBefore := false
	for _, row := range readTransportAudits(t, writer) {
		if row.EventType == "admin_inspection_posture_changed" {
			outcomes[*row.Result]++
			if *row.Result == "saved" && row.Metadata["before_mode"] == "bypass_default" {
				knownBefore = true
			}
			if *row.Result == "persistence_unconfirmed" && row.Metadata["authority_snapshot_available"] != false {
				t.Fatal("unknown authority claimed")
			}
		}
	}
	if outcomes["saved"] != 2 || outcomes["persistence_unconfirmed"] != 2 || !knownBefore {
		t.Fatalf("audit %+v", outcomes)
	}
}

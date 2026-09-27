package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInspectionPostureSharedPartialPreservesPeer(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := inspectionposture.NewStore(), inspectionposture.NewStore()
	for _, s := range []*inspectionposture.Store{a, b} {
		if _, err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	peer := inspectionposture.DefaultPosture()
	peer.DecryptAllowlistHosts = []string{"peer.example.invalid"}
	if _, err := b.Set(peer); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	now := time.Now()
	tenant := testEvaluator().PolicyBundle.TenantID
	auth.UpsertPrincipal(adminPrincipal{ID: "posture-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "posture-session", TenantID: tenant, AdminPrincipalID: "posture-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "posture-csrf"}})
	controller := newInspectionPostureAdmin(a, nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: tenant, InspectionPosture: a.Get, SetInspectionPosture: controller.set, UpdateInspectionPosture: controller.update, RefreshInspectionPosture: controller.refresh})
	r := httptest.NewRequest("POST", "/admin/inspection-posture", strings.NewReader(`{"known_bypass_enabled":false}`))
	r.AddCookie(&http.Cookie{Name: "admin_session", Value: "posture-session"})
	r.Header.Set("X-CSRF-Token", "posture-csrf")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	restored := inspectionposture.NewStore()
	if _, err := restored.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got := restored.Get()
	if len(got.DecryptAllowlistHosts) != 1 || got.DecryptAllowlistHosts[0] != "peer.example.invalid" || got.KnownBypassEnabled {
		t.Fatal("partial update erased peer's acknowledged posture field")
	}
}

func TestInspectionPostureSharedSeedAndFailure(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := inspectionposture.NewStore(), inspectionposture.NewStore()
	for _, s := range []*inspectionposture.Store{a, b} {
		if _, e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	peer := inspectionposture.DefaultPosture()
	peer.DecryptAllowlistHosts = []string{"peer.invalid"}
	if _, e := b.Set(peer); e != nil {
		t.Fatal(e)
	}
	if got, e := a.InitializeContext(context.Background(), inspectionposture.DefaultPosture()); e != nil || len(got.DecryptAllowlistHosts) != 1 {
		t.Fatalf("seed overwrote peer: %+v %v", got, e)
	}
	before, gen := a.Get(), a.ConfigGeneration()
	raw := append([]byte(nil), p.raw...)
	p.fail = true
	if _, _, e := a.UpdateContext(context.Background(), func(p inspectionposture.Posture) (inspectionposture.Posture, error) {
		p.KnownBypassEnabled = false
		return p, nil
	}); e == nil {
		t.Fatal("save failure accepted")
	}
	if !reflect.DeepEqual(a.Get(), before) || a.ConfigGeneration() != gen {
		t.Fatal("failed save became live")
	}
	p.fail = false
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{}`)} {
		p.raw = bad
		if _, e := a.RefreshShared(); e == nil {
			t.Fatal("bad authority read")
		}
		if _, e := a.InitializeContext(context.Background(), inspectionposture.DefaultPosture()); e == nil {
			t.Fatal("missing/corrupt authority reseeded")
		}
		if !reflect.DeepEqual(a.Get(), before) || a.ConfigGeneration() != gen {
			t.Fatal("bad authority changed live")
		}
	}
	p.raw = raw
	if _, _, e := a.UpdateContext(context.Background(), func(p inspectionposture.Posture) (inspectionposture.Posture, error) {
		p.KnownBypassEnabled = false
		return p, nil
	}); e != nil {
		t.Fatal(e)
	}
	if changed, e := b.RefreshShared(); e != nil || !changed || b.Get().KnownBypassEnabled {
		t.Fatalf("peer refresh %v %v", changed, e)
	}
}

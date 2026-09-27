package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresPolicyAssetsPeerMutation(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, kind := range []string{"rules", "assets"} {
		t.Run(kind, func(t *testing.T) {
			p := postgresBlobPersister{db: db, key: "test_policy_asset_peer_" + kind}
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			if kind == "rules" {
				fresh := func() *policyrule.Store {
					s := policyrule.NewStore()
					if err := s.SetPersister(p); err != nil {
						t.Fatal(err)
					}
					return s
				}
				a, b, reader := fresh(), fresh(), fresh()
				makeRule := func(tenant, id string) policyrule.Rule {
					return policyrule.Rule{ID: id, TenantID: tenant, Plane: "egress", Source: []string{"*"}, Destination: []string{"*"}, Action: policyrule.Action{Access: "deny"}}
				}
				for _, r := range []policyrule.Rule{makeRule("target", "peer"), makeRule("foreign", "kept")} {
					if _, err := a.Upsert(r); err != nil {
						t.Fatal(err)
					}
				}
				if err := reader.RefreshShared(); err != nil {
					t.Fatal(err)
				}
				if len(reader.List("target", "")) != 1 || len(reader.List("foreign", "")) != 1 {
					t.Fatal("peer rule read was stale")
				}
				if _, err := b.Upsert(makeRule("target", "own")); err != nil {
					t.Fatal(err)
				}
				if len(fresh().List("target", "")) != 2 || len(fresh().List("foreign", "")) != 1 {
					t.Fatal("stale rule edit erased peer or foreign rules")
				}
				if ok, err := a.Delete("target", "own"); !ok || err != nil {
					t.Fatalf("stale delete missed peer rule: %v %v", ok, err)
				}
				if len(fresh().List("target", "")) != 1 || len(fresh().List("foreign", "")) != 1 {
					t.Fatal("rule delete erased unrelated rules")
				}
			} else {
				fresh := func() *assetcatalog.Store {
					s := assetcatalog.NewStore()
					if err := s.SetPersister(p); err != nil {
						t.Fatal(err)
					}
					return s
				}
				a, b, reader := fresh(), fresh(), fresh()
				for _, g := range []assetcatalog.Group{{ID: "peer", TenantID: "target", Alias: "peer"}, {ID: "kept", TenantID: "foreign", Alias: "kept"}} {
					if _, err := a.UpsertGroup(g); err != nil {
						t.Fatal(err)
					}
				}
				if err := reader.RefreshShared(); err != nil {
					t.Fatal(err)
				}
				if len(reader.ListGroups("target")) != 1 || len(reader.ListGroups("foreign")) != 1 {
					t.Fatal("peer asset read was stale")
				}
				if _, err := b.UpsertGroup(assetcatalog.Group{ID: "own", TenantID: "target", Alias: "own"}); err != nil {
					t.Fatal(err)
				}
				if len(fresh().ListGroups("target")) != 2 || len(fresh().ListGroups("foreign")) != 1 {
					t.Fatal("stale catalog edit erased peer or foreign groups")
				}
				if ok, err := a.DeleteGroup("target", "own"); !ok || err != nil {
					t.Fatalf("stale delete missed peer group: %v %v", ok, err)
				}
				if len(fresh().ListGroups("target")) != 1 || len(fresh().ListGroups("foreign")) != 1 {
					t.Fatal("catalog delete erased unrelated groups")
				}
			}
		})
	}
}

func TestPostgresPolicyAssetsOldRequestAndReadFailure(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rp := postgresBlobPersister{db: db, key: "test_rules_request"}
	ap := postgresBlobPersister{db: db, key: "test_assets_request"}
	for _, p := range []postgresBlobPersister{rp, ap} {
		if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
			t.Fatal(err)
		}
		defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	}
	rules := policyrule.NewStore()
	assets := assetcatalog.NewStore()
	if err := rules.SetPersister(rp); err != nil {
		t.Fatal(err)
	}
	if err := assets.SetPersister(ap); err != nil {
		t.Fatal(err)
	}
	tenant := "tenant_lab_001"
	now := time.Now()
	r := policyrule.Rule{ID: "keep", TenantID: tenant, Plane: "egress", Source: []string{"*"}, Destination: []string{"*"}, Action: policyrule.Action{Access: "deny"}}
	if _, err := rules.Upsert(r); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "ep", TenantID: tenant, Alias: "ep", Kind: assetcatalog.KindNetwork, Address: "example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertGroup(assetcatalog.Group{ID: "grp", TenantID: tenant, Alias: "grp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertService(assetcatalog.Service{ID: "svc", TenantID: tenant, Alias: "svc", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 443}}}); err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "shared-session", TenantID: tenant, AdminPrincipalID: "review", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "shared-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Writer: w, Evaluator: testEvaluator(), AdminAuth: auth, RuleStore: rules, AssetStore: assets})
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	for _, tc := range []struct{ path, body string }{{"/admin/rules", `{"id":"keep","plane":"egress","source":["*"],"destination":["*"],"action":{"access":"allow"}}`}, {"/admin/assets/endpoints", `{"id":"ep","alias":"changed","kind":"network","address":"changed.invalid"}`}, {"/admin/assets/groups", `{"id":"grp","alias":"changed"}`}, {"/admin/assets/services", `{"id":"svc","alias":"changed","ports":[{"protocol":"tcp","port":80}]}`}} {
		t.Run(tc.path, func(t *testing.T) {
			beforeR, _ := rp.Load()
			beforeA, _ := ap.Load()
			body := &pausedSeatBody{Reader: strings.NewReader(tc.body), entered: make(chan struct{}), resume: make(chan struct{})}
			req := httptest.NewRequest("POST", tc.path, body)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "shared-session"})
			req.Header.Set("X-CSRF-Token", "shared-csrf")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(rec, req) }()
			select {
			case <-body.entered:
			case <-done:
				t.Fatalf("body unread: %d %s", rec.Code, rec.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("body deadline")
			}
			lease := captureCPWriteLease(context.Background())
			a.release()
			b.tick()
			if !b.IsLeader() {
				t.Fatal("peer not leader")
			}
			b.release()
			a.tick()
			if !a.IsLeader() {
				t.Fatal("original did not reacquire")
			}
			close(body.resume)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("request deadline")
			}
			if rec.Code != 500 || !strings.Contains(rec.Body.String(), "not confirmed") {
				t.Fatalf("old request escaped persistence boundary: %d %s", rec.Code, rec.Body)
			}
			if _, err := rules.DeleteContext(lease, tenant, "keep"); !errors.Is(err, policyrule.ErrPersistence) {
				t.Fatalf("old rule deletion: %v", err)
			}
			if _, err := rules.RemoveTenantContext(lease, tenant); !errors.Is(err, policyrule.ErrPersistence) {
				t.Fatalf("old purge: %v", err)
			}
			for _, del := range []func(context.Context, string, string) (bool, error){assets.DeleteEndpointContext, assets.DeleteGroupContext, assets.DeleteServiceContext} {
				if _, err := del(lease, tenant, "missing"); !errors.Is(err, assetcatalog.ErrPersistence) {
					t.Fatalf("old asset deletion: %v", err)
				}
			}
			afterR, _ := rp.Load()
			afterA, _ := ap.Load()
			if !bytes.Equal(beforeR, afterR) || !bytes.Equal(beforeA, afterA) {
				t.Fatal("refused request changed persistent state")
			}
		})
	}
	for _, p := range []postgresBlobPersister{rp, ap} {
		raw, err := p.Load()
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Save([]byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if p.key == rp.key {
			if err := policyrule.NewStore().SetPersister(p); !errors.Is(err, policyrule.ErrPersistence) {
				t.Fatalf("corrupt rule startup: %v", err)
			}
		} else {
			if err := assetcatalog.NewStore().SetPersister(p); !errors.Is(err, assetcatalog.ErrPersistence) {
				t.Fatalf("corrupt catalog startup: %v", err)
			}
		}
		paths := []string{"/admin/rules", "/admin/config-bundle"}
		if p.key == ap.key {
			paths = append(paths, "/admin/assets/endpoints", "/admin/assets/groups", "/admin/assets/groups/grp/members", "/admin/assets/services")
		}
		for _, path := range paths {
			req := httptest.NewRequest("GET", path, nil)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "shared-session"})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 503 {
				t.Fatalf("corrupt %s %s: %d %s", p.key, path, rec.Code, rec.Body)
			}
		}
		if p.key == rp.key {
			if _, err := rules.Upsert(r); !errors.Is(err, policyrule.ErrPersistence) {
				t.Fatalf("corrupt rule write: %v", err)
			}
		} else {
			if _, err := assets.UpsertGroup(assetcatalog.Group{TenantID: tenant, Alias: "bad"}); !errors.Is(err, assetcatalog.ErrPersistence) {
				t.Fatalf("corrupt asset write: %v", err)
			}
		}
		if err := p.Save(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := rules.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if err := assets.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	r.Name = "recovered"
	if _, err := rules.UpsertContext(captureCPWriteLease(context.Background()), r); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertGroupContext(captureCPWriteLease(context.Background()), assetcatalog.Group{ID: "grp", TenantID: tenant, Alias: "recovered"}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresCatalogKeepsLocalInventoryAndAllocatesFreshIDs(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_catalog_local"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	a, b := assetcatalog.NewStore(), assetcatalog.NewStore()
	for _, s := range []*assetcatalog.Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	b.SetBuiltInServices(assetcatalog.BuiltInServices())
	if _, err := b.UpsertEndpoint(assetcatalog.Endpoint{ID: "enrolled-local", TenantID: "target", Alias: "local-device", Kind: assetcatalog.KindSteeredDevice, Source: assetcatalog.SourceEnrolled, Identity: "local"}); err != nil {
		t.Fatal(err)
	}
	first, err := a.UpsertGroup(assetcatalog.Group{TenantID: "target", Alias: "unique"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.UpsertGroup(assetcatalog.Group{TenantID: "target", Alias: "unique"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.Alias == second.Alias {
		t.Fatal("stale sequence or alias allocation collided")
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.GetEndpoint("target", "enrolled-local"); !ok || len(b.ListServices("target")) == 0 {
		t.Fatal("shared refresh discarded local inventory or built-ins")
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("enrolled-local")) {
		t.Fatal("volatile inventory persisted in authored blob")
	}
	if ok, err := a.DeleteGroup("target", second.ID); !ok || err != nil {
		t.Fatalf("fresh delete %v %v", ok, err)
	}
	if err := b.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if got := b.ListGroups("target"); len(got) != 1 || got[0].ID != first.ID {
		t.Fatalf("peer deletion not refreshed: %v", got)
	}
	if _, ok := b.GetEndpoint("target", "enrolled-local"); !ok {
		t.Fatal("peer deletion dropped local endpoint")
	}
}

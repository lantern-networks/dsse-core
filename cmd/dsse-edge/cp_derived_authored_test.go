package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestPostgresDerivedAuthoredRequestsKeepAcceptedTerm(t *testing.T) {
	for _, kind := range []string{"observation", "certpin", "application", "tenant"} {
		t.Run(kind, func(t *testing.T) {
			a, b := postgresFailureElectors(t)
			db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			rp := postgresBlobPersister{db: db, key: "test_derived_rules_" + kind}
			ap := postgresBlobPersister{db: db, key: "test_derived_assets_" + kind}
			for _, p := range []postgresBlobPersister{rp, ap} {
				if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
					t.Fatal(err)
				}
				defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			}
			rules, assets := policyrule.NewStore(), assetcatalog.NewStore()
			if err := rules.SetPersister(rp); err != nil {
				t.Fatal(err)
			}
			if err := assets.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			tenant := "tenant_lab_001"
			now := time.Now()
			obs := eastwestobserve.NewStore()
			flow := obs.Observe(tenant, "*", "", "10.0.0.10", "ssh", 22, now)
			apps := appcatalog.NewStore()
			if _, err := apps.Upsert(context.Background(), appcatalog.Entry{ApplicationID: "app", Name: "App", ApplicationType: "private_app"}, tenant, now); err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "derived-session", TenantID: tenant, AdminPrincipalID: "review", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "derived-csrf"}})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, RuleStore: rules, AssetStore: assets, EastWestObserveStore: obs, ApplicationCatalogStore: apps, OperatorTenantID: tenant})
			old := cpLeaderElectorInstance
			cpLeaderElectorInstance = a
			defer func() { cpLeaderElectorInstance = old }()
			a.tick()
			path, data := "/admin/cert-pin-bypass", `{"host":"pinned.example.invalid"}`
			if kind == "observation" {
				path = "/admin/east-west/observations/adopt"
				data = fmt.Sprintf(`{"observation_ids":[%q]}`, flow.ObservationID)
			}
			if kind == "application" {
				path = "/admin/applications/app/publish"
				data = `{"name":"App","destination":"app.example.invalid","destination_port":443,"publish_protocol":"web"}`
			}
			if kind == "tenant" {
				path = "/admin/tenants"
				data = `{"display_name":"Derived tenant"}`
			}
			beforeR, _ := rp.Load()
			beforeA, _ := ap.Load()
			body := &pausedSeatBody{Reader: strings.NewReader(data), entered: make(chan struct{}), resume: make(chan struct{})}
			req := httptest.NewRequest("POST", path, body)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "derived-session"})
			req.Header.Set("X-CSRF-Token", "derived-csrf")
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
			afterR, _ := rp.Load()
			afterA, _ := ap.Load()
			expectedStatus := 500
			if kind == "tenant" {
				expectedStatus = 200
				if !strings.Contains(rec.Body.String(), "starting_posture_note") {
					t.Fatal("missing partial tenant notice", rec.Body)
				}
			}
			if rec.Code != expectedStatus || !bytes.Equal(beforeR, afterR) || !bytes.Equal(beforeA, afterA) {
				t.Fatalf("old request changed authority: status=%d rulesChanged=%v assetsChanged=%v body=%s", rec.Code, !bytes.Equal(beforeR, afterR), !bytes.Equal(beforeA, afterA), rec.Body)
			}
			// A fresh request succeeds; prior partial state is recoverable without changing IDs.
			retry := httptest.NewRequest("POST", path, strings.NewReader(data))
			retry.AddCookie(&http.Cookie{Name: "admin_session", Value: "derived-session"})
			retry.Header.Set("X-CSRF-Token", "derived-csrf")
			if kind != "tenant" {
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, retry)
				if rr.Code != 200 {
					t.Fatalf("fresh retry: %d %s", rr.Code, rr.Body)
				}
			}
		})
	}
}

func TestCandidateReviewRefusesStandbyBeforeReadingBody(t *testing.T) {
	e := standbyAuditElection(t)
	_ = e
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	mw := newAdminEndpointMiddleware(testEvaluator(), w, nil, standbyNoAuthCalls{}, "", false, nil, nil, nil)
	req := httptest.NewRequest("POST", "/admin/cert-pin-bypass", standbyUnreadBody{})
	rec := httptest.NewRecorder()
	mw("admin.policy_candidates.review", func(http.ResponseWriter, *http.Request) { t.Error("standby review reached handler") })(rec, req)
	if rec.Code != 409 {
		t.Fatal("standby review accepted", rec.Code)
	}
}

func TestPostgresApplicationDerivedFailureRetry(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is required")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, action := range []string{"publish", "unpublish", "delete"} {
		t.Run(action, func(t *testing.T) {
			tenant := "tenant_lab_001"
			now := time.Now()
			root := t.TempDir()
			ap := postgresBlobPersister{db: db, key: "test_app_derived_retry"}
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", ap.key)
			defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", ap.key)
			assets := assetcatalog.NewStore()
			if err := assets.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			apps := appcatalog.NewStore()
			if err := apps.SetStatePath(filepath.Join(root, "apps.json")); err != nil {
				t.Fatal(err)
			}
			entry := appcatalog.Entry{ApplicationID: "app", Name: "App", ApplicationType: "private_app", Destination: "app.example.invalid", DestinationPort: 443, PublishProtocol: "web", Published: action != "publish"}
			if _, err := apps.Upsert(context.Background(), entry, tenant, now); err != nil {
				t.Fatal(err)
			}
			for _, owner := range []string{tenant, "tenant_other"} {
				if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "app-app", TenantID: owner, Alias: "App", Kind: assetcatalog.KindNetwork, Source: assetcatalog.SourceManual, Address: "old.example.invalid"}); err != nil {
					t.Fatal(err)
				}
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "derived-session", TenantID: tenant, AdminPrincipalID: "review", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "derived-csrf"}})
			writer, err := logs.NewWriter(filepath.Join(root, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, AssetStore: assets, ApplicationCatalogStore: apps})
			send := func() *httptest.ResponseRecorder {
				method, path := "POST", "/admin/applications/app/"+action
				if action == "delete" {
					method, path = "DELETE", "/admin/applications/app"
				}
				r := httptest.NewRequest(method, path, strings.NewReader(`{"name":"App","destination":"app.example.invalid","destination_port":443,"publish_protocol":"web"}`))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "derived-session"})
				r.Header.Set("X-CSRF-Token", "derived-csrf")
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, r)
				return rr
			}
			before, err := ap.Load()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("ALTER TABLE cp_state_blobs ADD CONSTRAINT test_app_derived_failure CHECK (store_key != 'test_app_derived_retry') NOT VALID"); err != nil {
				t.Fatal(err)
			}
			defer db.Exec("ALTER TABLE cp_state_blobs DROP CONSTRAINT IF EXISTS test_app_derived_failure")
			rr := send()
			if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"partial":true`) {
				t.Fatalf("partial not reported: %d %s", rr.Code, rr.Body)
			}
			after, err := ap.Load()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed derived write changed row", err)
			}
			reloaded := appcatalog.NewStore()
			if err := reloaded.SetStatePath(filepath.Join(root, "apps.json")); err != nil {
				t.Fatal(err)
			}
			saved, found, err := reloaded.Get(context.Background(), tenant, "app")
			if err != nil || found != (action != "delete") || found && saved.Published != (action == "publish") {
				t.Fatalf("primary state not confirmed: %+v %v %v", saved, found, err)
			}
			if _, err := db.Exec("ALTER TABLE cp_state_blobs DROP CONSTRAINT test_app_derived_failure"); err != nil {
				t.Fatal(err)
			}
			rr = send()
			if rr.Code != 200 {
				t.Fatalf("retry: %d %s", rr.Code, rr.Body)
			}
			fresh := assetcatalog.NewStore()
			if err := fresh.SetPersister(ap); err != nil {
				t.Fatal(err)
			}
			ep, found := fresh.GetEndpoint(tenant, "app-app")
			if found != (action == "publish") || found && ep.Address != "app.example.invalid" {
				t.Fatalf("derived retry: %+v %v", ep, found)
			}
			foreign, ok := fresh.GetEndpoint("tenant_other", "app-app")
			if !ok || foreign.Address != "old.example.invalid" {
				t.Fatal("foreign endpoint changed")
			}
			partial, success, commonError := 0, 0, 0
			for _, a := range readTransportAudits(t, writer) {
				if stringPtrValue(a.TargetID) == "app" && strings.HasPrefix(a.EventType, "admin_application_") {
					if a.TenantID != tenant || stringPtrValue(a.ActorUserID) != "review" {
						t.Fatalf("bad audit scope: %+v", a)
					}
					switch stringPtrValue(a.Result) {
					case "partial":
						partial++
						if a.Metadata["failed_stage"] != "asset_endpoint" {
							t.Fatal("missing failed stage")
						}
					case "success":
						success++
					}
				}
				if stringPtrValue(a.Result) == "error" {
					commonError++
				}
			}
			if partial != 1 || success != 1 || commonError != 1 {
				t.Fatalf("audits: partial=%d success=%d error=%d", partial, success, commonError)
			}
		})
	}
}

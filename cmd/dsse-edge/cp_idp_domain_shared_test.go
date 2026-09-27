package main

import (
	"bytes"
	"context"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresIdPDomainLatestRowAndTerm(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	for _, key := range []string{"idp_connections", "organization_domains"} {
		t.Run(key, func(t *testing.T) {
			cpLeaderElectorInstance = nil
			edgeIsControlPlane = true
			p := postgresBlobPersister{db: db, key: key}
			original, _ := p.Load()
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
			defer func() {
				if original == nil {
					db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
				} else {
					db.Exec("INSERT INTO cp_state_blobs(store_key,payload)VALUES($1,$2)ON CONFLICT(store_key)DO UPDATE SET payload=$2", key, original)
				}
			}()
			gate := &runtimeLeaseGate{postgresBlobPersister: p}
			writer, e := logs.NewWriter(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "pair-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "pair-session", TenantID: "tenant_lab_001", AdminPrincipalID: "pair-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "pair-csrf"}})
			h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth})
			var handler http.Handler = h
			path, method, body := "/admin/idp-connections", "POST", `{"idp_id":"own","issuer":"https://idp.invalid","authorization_endpoint":"https://idp.invalid/auth","client_id":"fixture"}`
			var peerWrite func(string) error
			if key == "idp_connections" {
				a := theIdPRegistry.Load()
				if e = a.SetPersister(gate); e != nil {
					t.Fatal(e)
				}
				b := idpregistry.NewStore()
				b.SetPersister(p)
				peerWrite = func(tenant string) error {
					_, e := b.UpsertContext(captureCPWriteLease(context.Background()), idpregistry.Connection{TenantID: tenant, IdPID: "keep", Issuer: "https://peer.invalid", AuthorizationEndpoint: "https://peer.invalid/auth", ClientID: "peer"})
					return e
				}
			} else {
				a, b := newOrganizationDomainsStore(), newOrganizationDomainsStore()
				a.SetPersister(gate)
				b.SetPersister(p)
				mux := http.NewServeMux()
				registerOrganizationDomainRoutes(mux, func(_ string, fn http.HandlerFunc) http.HandlerFunc {
					return func(w http.ResponseWriter, r *http.Request) {
						r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "pair-admin", TenantID: "tenant_lab_001"})
						r = r.WithContext(captureCPWriteLease(r.Context()))
						fn(w, r)
					}
				}, a)
				handler = mux
				path, method, body = "/admin/organization-domains", "PUT", `{"domains":["own.invalid"]}`
				peerWrite = func(tenant string) error {
					_, e := b.SetDomainsContext(captureCPWriteLease(context.Background()), tenant, []string{"peer.invalid"})
					return e
				}
			}
			call := func(method, path, body string, want int) {
				t.Helper()
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "pair-session"})
				r.Header.Set("X-CSRF-Token", "pair-csrf")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("%s %s %d want %d: %s", method, path, w.Code, want, w.Body)
				}
			}
			if e = peerWrite("foreign"); e != nil {
				t.Fatal(e)
			}
			cpLeaderElectorInstance = leader
			leader.tick()
			if !leader.IsLeader() {
				t.Fatal("election")
			}
			before, _ := p.Load()
			gate.before = func() {
				leader.release()
				peer.tick()
				if !peer.IsLeader() {
					t.Fatal("peer")
				}
				peer.release()
				leader.tick()
			}
			call(method, path, body, 500)
			gate.before = nil
			after, _ := p.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("old term overwrote authority")
			}
			call(method, path, body, 200)
			after, _ = p.Load()
			if !bytes.Contains(after, []byte("foreign")) || !bytes.Contains(after, []byte("tenant_lab_001")) {
				t.Fatal("peer lost")
			}
			call("GET", path, "", 200)
			if key == "idp_connections" {
				call("POST", path+"/keep/default", `{}`, 400)
				call("DELETE", path+"/keep", `{}`, 404)
			}
			for _, raw := range [][]byte{[]byte(`null`), []byte(`{}`), {}} {
				db.Exec("UPDATE cp_state_blobs SET payload=$2 WHERE store_key=$1", key, raw)
				call("GET", path, "", 500)
				call(method, path, body, 500)
			}
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
			call(method, path, body, 500)
			db.Exec("INSERT INTO cp_state_blobs(store_key,payload)VALUES($1,$2)", key, after)
			call("GET", path, "", 200)
			if key == "idp_connections" {
				r := idpregistry.NewStore()
				if e = r.SetPersister(p); e != nil {
					t.Fatal(e)
				}
				if len(r.ListAll()) != 2 {
					t.Fatal("restart")
				}
			} else {
				r := newOrganizationDomainsStore()
				if e = r.SetPersister(p); e != nil {
					t.Fatal(e)
				}
				if len(r.Domains("foreign")) != 1 {
					t.Fatal("restart")
				}
			}
			leader.release()
		})
	}
}

func TestPostgresDomainFlushPreservesPeerAndFailedAttachment(t *testing.T) {
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN required")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = nil
	defer func() { cpLeaderElectorInstance = old }()
	key := "domain_flush_test"
	p := postgresBlobPersister{db: db, key: key}
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	a, b := newOrganizationDomainsStore(), newOrganizationDomainsStore()
	a.SetPersister(p)
	b.SetPersister(p)
	b.SetDomainsDurable("foreign", []string{"keep.invalid"})
	a.SetDomains("own", []string{"pending.invalid"})
	if err = a.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if got := b.Domains("own"); len(got) != 1 || got[0] != "pending.invalid" {
		t.Fatal("read did not refresh")
	}
	b.SetDomainsDurable("foreign", []string{"latest.invalid"})
	if _, err = a.SetDomainsDurable("own", nil); err != nil {
		t.Fatal(err)
	}
	restart := newOrganizationDomainsStore()
	restart.SetPersister(p)
	if got := restart.Domains("foreign"); len(got) != 1 || got[0] != "latest.invalid" {
		t.Fatal("peer lost on clear")
	}
	bad := dlpSnapshotReader([]byte(`null`))
	if err = a.SetPersister(bad); err == nil {
		t.Fatal("accepted invalid attachment")
	}
	if _, err = a.SetDomainsDurable("own", []string{"accepted.invalid"}); err != nil {
		t.Fatal("writer was replaced", err)
	}
	if got := b.Domains("own"); len(got) != 1 || got[0] != "accepted.invalid" {
		t.Fatal("accepted state absent")
	}
}

// Both management routes use the real authentication/audit stack with shared storage.
func TestPostgresIdPDomainAuthorizationAndAudit(t *testing.T) {
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN required")
	}
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldDB, oldE, oldCP := cpStateBlobDB, cpLeaderElectorInstance, edgeIsControlPlane
	cpStateBlobDB, cpLeaderElectorInstance, edgeIsControlPlane = db, nil, true
	defer func() { cpStateBlobDB, cpLeaderElectorInstance, edgeIsControlPlane = oldDB, oldE, oldCP }()
	for _, key := range []string{"idp_connections", "organization_domains"} {
		p := postgresBlobPersister{db: db, key: key}
		raw, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
		defer func(key string, raw []byte) {
			if raw == nil {
				db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
			} else {
				db.Exec("INSERT INTO cp_state_blobs(store_key,payload)VALUES($1,$2)ON CONFLICT(store_key)DO UPDATE SET payload=$2", key, raw)
			}
		}(key, raw)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	auth := newAdminAuthStore()
	for _, role := range []string{"admin", "viewer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: role, TenantID: "tenant_lab_001", Roles: []string{role}, Status: "active"})
		auth.UpsertSession(adminSession{ID: role, TenantID: "tenant_lab_001", AdminPrincipalID: role, Roles: []string{role}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "test-csrf"}})
	}
	h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth, IdPConnectionStorePath: "postgres", OrganizationDomainsStorePath: "postgres", OperatorTenantID: "operator"})
	for _, tc := range []struct{ method, path, body string }{{"POST", "/admin/idp-connections", `{"idp_id":"own","issuer":"https://idp.invalid","authorization_endpoint":"https://idp.invalid/auth","client_id":"fixture"}`}, {"PUT", "/admin/organization-domains", `{"domains":["owned.invalid"]}`}} {
		for _, role := range []string{"viewer", "admin"} {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.AddCookie(&http.Cookie{Name: "admin_session", Value: role})
			r.Header.Set("X-CSRF-Token", "test-csrf")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 200
			if role == "viewer" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s %s %d: %s", role, tc.path, w.Code, w.Body)
			}
		}
	}
	rows := readTransportAudits(t, writer)
	success, denied := 0, 0
	for _, row := range rows {
		if row.TenantID != "tenant_lab_001" {
			t.Fatal("audit tenant")
		}
		if row.EventType == "admin_rbac_denied" {
			if stringPtrValue(row.ActorUserID) != "viewer" || stringPtrValue(row.Result) != "failure" {
				t.Fatal("denial audit attribution")
			}
			denied++
		}
		if row.EventType == "admin_config_change" {
			if stringPtrValue(row.Result) == "success" {
				success++
			} else {
				denied++
			}
		}
	}
	if success != 2 || denied != 2 {
		t.Fatalf("audit outcomes %d/%d", success, denied)
	}
}

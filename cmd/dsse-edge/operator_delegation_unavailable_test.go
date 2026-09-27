package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type unavailableDelegationStore struct {
	adminTenantModelAdminStore
	fail bool
}

func (s *unavailableDelegationStore) List(ctx context.Context) ([]adminTenantModel, error) {
	if s.fail {
		return nil, errors.New("private registry backend address")
	}
	return s.adminTenantModelAdminStore.List(ctx)
}

func TestOperatorDelegationLookupFailureStopsTenantActions(t *testing.T) {
	ev := testEvaluator()
	declareOperatorTenantForTest(t, ev.PolicyBundle.TenantID)
	store := &unavailableDelegationStore{adminTenantModelAdminStore: newAdminTenantModelStore(ev.PolicyBundle, time.Now()), fail: true}
	delegate(t, store, "tenant_customer", true, false)
	auth := newAdminAuthStore()
	for _, v := range []struct {
		id, tenant string
		roles      []string
	}{{"op", ev.PolicyBundle.TenantID, []string{"admin", "super_admin"}}, {"customer", "tenant_customer", []string{"admin"}}} {
		auth.UpsertPrincipal(adminPrincipal{ID: v.id, TenantID: v.tenant, Roles: v.roles, Status: "active"})
		auth.UpsertSession(adminSession{ID: v.id, TenantID: v.tenant, AdminPrincipalID: v.id, Roles: v.roles, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "csrf"}})
	}
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	gate := newAdminEndpointMiddleware(ev, writer, nil, auth, "", false, store, nil, nil)
	call := func(actor, permission, method, path, target string) (int, bool, string) {
		invoked := false
		h := gate(permission, func(w http.ResponseWriter, r *http.Request) { invoked = true; w.WriteHeader(200) })
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: actor})
		req.Header.Set("X-CSRF-Token", "csrf")
		req.Header.Set("X-Operate-Tenant", target)
		rr := httptest.NewRecorder()
		h(rr, req)
		return rr.Code, invoked, rr.Body.String()
	}
	for _, c := range []struct{ permission, method, path string }{{"admin.config.read", "GET", "/admin/tenant"}, {"admin.config.write", "POST", "/admin/tenant"}, {"admin.policy.write|admin.tenant.admin", "POST", "/admin/rules"}, {"admin.endpoints.write", "POST", "/admin/transport-admission/revoke"}, {"admin.grants.write", "POST", "/admin/grants/grant-bearer-not-for-audits/revoke"}} {
		t.Run(c.method+c.path, func(t *testing.T) {
			code, called, body := call("op", c.permission, c.method, c.path, "tenant_customer")
			if code != 503 || called {
				t.Fatalf("registry failure: status=%d handler_called=%v body=%s", code, called, body)
			}
			if strings.Contains(body, "private registry") {
				t.Fatal("backend detail leaked")
			}
		})
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), `"event_type":"admin_authorization_unavailable"`); n != 5 {
		t.Fatalf("lookup failure audits=%d: %s", n, raw)
	}
	if strings.Contains(string(raw), "grant-bearer-not-for-audits") {
		t.Fatal("grant credential in audit")
	}
	if strings.Contains(string(raw), "private registry") {
		t.Fatal("backend detail in audit")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a model.AuditLog
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
		if a.TenantID != ev.PolicyBundle.TenantID || stringPtrValue(a.ActorUserID) != "op" || stringPtrValue(a.Result) != "error" || stringPtrValue(a.Reason) != "operator_delegation_unavailable" || a.Metadata["status_code"] != float64(503) {
			t.Fatalf("wrong failure attribution: %+v", a)
		}
		if a.Metadata["path"] == "/admin/grants/{grant_id}/revoke" && a.Metadata["grant_ref"] != accessGrantAuditReference("grant-bearer-not-for-audits") {
			t.Fatal("missing grant reference")
		}
		reasons, _ := json.Marshal(a.Metadata["reason_codes"])
		if string(reasons) != `["operator_delegation_unavailable"]` {
			t.Fatalf("wrong reason codes: %s", reasons)
		}
	}

	for _, c := range []struct{ actor, scope, path, target string }{{"customer", "admin.config.write", "/admin/tenant", ""}, {"op", "admin.config.write", "/admin/tenant", ev.PolicyBundle.TenantID}, {"op", "admin.tenant.admin", "/admin/tenants", "tenant_customer"}, {"op", "admin.config.read|admin.tenant.admin", "/admin/operator-access", "tenant_customer"}} {
		code, called, _ := call(c.actor, c.scope, "POST", c.path, c.target)
		if code != 200 || !called {
			t.Fatalf("unrelated/own/control request blocked: %+v %d", c, code)
		}
	}
	store.fail = false
	if code, called, _ := call("op", "admin.config.write", "POST", "/admin/tenant", "tenant_customer"); code != 200 || !called {
		t.Fatalf("delegated recovery: %d called=%v", code, called)
	}
	delegate(t, store, "tenant_customer", false, false)
	if code, called, _ := call("op", "admin.config.write", "POST", "/admin/tenant", "tenant_customer"); code != 403 || called {
		t.Fatalf("withdrawn delegation: %d called=%v", code, called)
	}
}

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// seedActiveAdminAccount drives the full first-party activation (invite -> password -> TOTP -> complete) so the
// account is "active" with a password and enrolled TOTP, bound to the given tenant and principal.
func seedActiveAdminAccount(t *testing.T, store *localAdminCredentialStore, email, tenantID, principalID string, roles []string, now time.Time) {
	t.Helper()
	token, err := store.Invite(email, tenantID, principalID, roles, now)
	if err != nil {
		t.Fatalf("invite %s: %v", email, err)
	}
	if err := store.SetActivationPassword(token, "a-strong-passphrase-123", now); err != nil {
		t.Fatalf("set password %s: %v", email, err)
	}
	secret, _, err := store.BeginTOTPEnrollment(token, now)
	if err != nil {
		t.Fatalf("begin totp %s: %v", email, err)
	}
	code, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := store.CompleteActivation(token, code, now); err != nil {
		t.Fatalf("complete activation %s: %v", email, err)
	}
}

// TestAdminAccountStoreTenantScoping is the store-level property guard: List/SetStatus/SetRoles/Delete never
// read or mutate an account belonging to another tenant — the customer trust boundary.
func TestAdminAccountStoreTenantScoping(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	seedActiveAdminAccount(t, store, "a@tenant-a.example", "tenant_a", "adm_a", []string{"admin"}, now)
	seedActiveAdminAccount(t, store, "b@tenant-b.example", "tenant_b", "adm_b", []string{"admin"}, now)

	// List is tenant-scoped: tenant_a sees only adm_a.
	listA := store.List("tenant_a")
	if len(listA) != 1 || listA[0].PrincipalID != "adm_a" {
		t.Fatalf("List(tenant_a) = %+v, want exactly adm_a", listA)
	}
	if listA[0].Email != "a@tenant-a.example" || listA[0].Status != credentialStatusActive {
		t.Fatalf("summary leaked or wrong: %+v", listA[0])
	}

	// Empty tenant fails closed (no accounts).
	if got := store.List(""); len(got) != 0 {
		t.Fatalf("List(\"\") = %+v, want none (fail-closed)", got)
	}

	// Cross-tenant SetStatus is a no-op that returns not-found; adm_b is unchanged.
	if _, err := store.SetStatus("tenant_a", "adm_b", credentialStatusSuspended, now); !errors.Is(err, errAdminAccountNotFound) {
		t.Fatalf("cross-tenant SetStatus err = %v, want errAdminAccountNotFound", err)
	}
	// Cross-tenant SetRoles likewise.
	if _, err := store.SetRoles("tenant_a", "adm_b", []string{"auditor"}, now); !errors.Is(err, errAdminAccountNotFound) {
		t.Fatalf("cross-tenant SetRoles err = %v, want errAdminAccountNotFound", err)
	}
	// Cross-tenant Delete likewise; adm_b survives in tenant_b.
	if _, err := store.Delete("tenant_a", "adm_b", now); !errors.Is(err, errAdminAccountNotFound) {
		t.Fatalf("cross-tenant Delete err = %v, want errAdminAccountNotFound", err)
	}
	if listB := store.List("tenant_b"); len(listB) != 1 || listB[0].Roles[0] != "admin" || listB[0].Status != credentialStatusActive {
		t.Fatalf("adm_b altered across tenants: %+v", listB)
	}
}

// TestAdminAccountStoreStatusAndRoles covers suspend/reactivate semantics and the never-activated guard.
func TestAdminAccountStoreStatusAndRoles(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	seedActiveAdminAccount(t, store, "a@t.example", "t", "adm_a", []string{"admin"}, now)

	if _, err := store.SetStatus("t", "adm_a", credentialStatusSuspended, now); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	// A suspended account cannot pass the password factor.
	if _, err := store.VerifyPassword("a@t.example", "a-strong-passphrase-123", now); err == nil {
		t.Fatalf("suspended account must not log in")
	}
	if _, err := store.SetStatus("t", "adm_a", credentialStatusActive, now); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := store.VerifyPassword("a@t.example", "a-strong-passphrase-123", now); err != nil {
		t.Fatalf("reactivated account must log in: %v", err)
	}

	// A never-activated (pending) invite cannot be flipped to active.
	if _, err := store.Invite("p@t.example", "t", "adm_p", []string{"admin"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetStatus("t", "adm_p", credentialStatusActive, now); err == nil {
		t.Fatalf("pending account must not be set active")
	}

	// Role replacement.
	summary, err := store.SetRoles("t", "adm_a", []string{"auditor"}, now)
	if err != nil || len(summary.Roles) != 1 || summary.Roles[0] != "auditor" {
		t.Fatalf("SetRoles = %+v err=%v", summary, err)
	}
}

func newAdminAccountTestServer(t *testing.T, store *localAdminCredentialStore) (http.Handler, map[string]string) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	raw := map[string]string{}
	add := func(key, principalID string, roles []string) {
		rawToken := "raw-" + key
		auth.UpsertPrincipal(adminPrincipal{
			ID: principalID, TenantID: "tenant_lab_001", Subject: "sub_" + key,
			Email: key + "@example.invalid", Roles: roles, IDPID: "keycloak_lab",
			Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		})
		auth.UpsertAPIToken(adminAPIToken{
			ID: "tok_" + key, TenantID: "tenant_lab_001", Name: key,
			TokenHash: adminTokenHash(rawToken), Roles: roles, Scopes: []string{"*"},
			CreatedByAdminPrincipalID: principalID,
			CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
		})
		raw[key] = rawToken
	}
	add("admin", "adm_caller_admin", []string{"admin"})
	add("tenant_admin", "adm_caller_tenant_admin", []string{"tenant_admin"})
	add("analyst", "adm_caller_analyst", []string{"analyst"})
	add("auditor", "adm_caller_auditor", []string{"auditor"})
	// An owner-like operator that holds BOTH admin.accounts.write and admin.tenant.admin.
	add("operator", "adm_caller_operator", []string{"admin", "super_admin"})

	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        auth,
		LocalCredentials: store,
	})
	return handler, raw
}

// TestAdminAccountManagementEndpoints exercises the HTTP surface: tenant-scoped listing (no cross-tenant
// leakage), suspend/reactivate/delete, privilege-escalation refusal, self/last-admin delete guards, and RBAC.
func TestAdminAccountManagementEndpoints(t *testing.T) {
	now := time.Now().UTC()
	store := newLocalAdminCredentialStore("Lantern DSSE")
	// Two managed accounts in the caller's tenant, plus one in a different tenant.
	seedActiveAdminAccount(t, store, "target@lab.example", "tenant_lab_001", "adm_target", []string{"admin"}, now)
	seedActiveAdminAccount(t, store, "keeper@lab.example", "tenant_lab_001", "adm_keeper", []string{"admin"}, now)
	seedActiveAdminAccount(t, store, "other@foreign.example", "tenant_other", "adm_other", []string{"admin"}, now)

	handler, raw := newAdminAccountTestServer(t, store)
	do := func(method, path, bearer, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("authorization", "Bearer "+bearer)
		}
		if body != "" {
			req.Header.Set("content-type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	decode := func(rec *httptest.ResponseRecorder) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}

	// --- list: tenant-scoped, no cross-tenant leakage ---
	rec := do(http.MethodGet, "/admin/admins", raw["admin"], "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	admins, _ := decode(rec)["admins"].([]any)
	if len(admins) != 2 {
		t.Fatalf("list returned %d admins, want 2 (tenant_lab_001 only): %s", len(admins), rec.Body.String())
	}
	for _, a := range admins {
		m, _ := a.(map[string]any)
		if pid, _ := m["principal_id"].(string); pid == "adm_other" {
			t.Fatalf("cross-tenant account leaked into list: %v", m)
		}
	}

	// analyst lacks admin.accounts.read.
	if rec := do(http.MethodGet, "/admin/admins", raw["analyst"], ""); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst list: want 403, got %d", rec.Code)
	}
	// auditor was granted admin.accounts.read.
	if rec := do(http.MethodGet, "/admin/admins", raw["auditor"], ""); rec.Code != http.StatusOK {
		t.Fatalf("auditor list: want 200, got %d", rec.Code)
	}

	// --- suspend then reactivate ---
	rec = do(http.MethodPost, "/admin/admins/adm_target/suspend", raw["admin"], "")
	if rec.Code != http.StatusOK || decode(rec)["status"] != credentialStatusSuspended {
		t.Fatalf("suspend: want 200 suspended, got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(http.MethodPost, "/admin/admins/adm_target/reactivate", raw["admin"], "")
	if rec.Code != http.StatusOK || decode(rec)["status"] != credentialStatusActive {
		t.Fatalf("reactivate: want 200 active, got %d body=%s", rec.Code, rec.Body.String())
	}

	// --- cross-tenant target is 404 (caller is tenant_lab_001) ---
	if rec := do(http.MethodPost, "/admin/admins/adm_other/suspend", raw["admin"], ""); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant suspend: want 404, got %d", rec.Code)
	}

	// --- privilege escalation: admin (no tenant.admin) cannot grant super_admin ---
	if rec := do(http.MethodPost, "/admin/admins/adm_target/roles", raw["admin"], `{"roles":["super_admin"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("escalation by admin: want 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/admin/admins/adm_target/roles", raw["tenant_admin"], `{"roles":["owner"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("escalation by tenant_admin to owner: want 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	// operator (admin + super_admin) may grant a cross-tenant operator role.
	if rec := do(http.MethodPost, "/admin/admins/adm_target/roles", raw["operator"], `{"roles":["super_admin"]}`); rec.Code != http.StatusOK {
		t.Fatalf("escalation by operator: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// restore adm_target to admin for later guards (operator can do this; adm_keeper keeps the tenant safe).
	if rec := do(http.MethodPost, "/admin/admins/adm_target/roles", raw["operator"], `{"roles":["admin"]}`); rec.Code != http.StatusOK {
		t.Fatalf("restore roles: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// unknown role rejected.
	if rec := do(http.MethodPost, "/admin/admins/adm_target/roles", raw["admin"], `{"roles":["wizard"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: want 400, got %d", rec.Code)
	}

	// --- privilege escalation via INVITE: a tenant-confined admin cannot invite a cross-tenant operator role
	// (parity with the roles-handler guard above; tenant-isolation review finding #3). These are REFUSALS, so
	// they create no account and do not perturb the later admin-count guards. ---
	if rec := do(http.MethodPost, "/admin/admins/invite", raw["admin"], `{"email":"esc@lab.example","roles":["super_admin"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("invite escalation by admin: want 403, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/admin/admins/invite", raw["tenant_admin"], `{"email":"esc2@lab.example","roles":["owner"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("invite escalation by tenant_admin to owner: want 403, got %d body=%s", rec.Code, rec.Body.String())
	}

	// --- self-delete guard (caller principal == path) ---
	if rec := do(http.MethodDelete, "/admin/admins/adm_caller_admin", raw["admin"], ""); rec.Code != http.StatusConflict {
		t.Fatalf("self-delete: want 409, got %d body=%s", rec.Code, rec.Body.String())
	}

	// --- delete a non-last admin succeeds (adm_keeper remains admin-capable) ---
	if rec := do(http.MethodDelete, "/admin/admins/adm_target", raw["admin"], ""); rec.Code != http.StatusOK {
		t.Fatalf("delete adm_target: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// --- last-admin guard: deleting the only remaining admin-capable account is refused ---
	if rec := do(http.MethodDelete, "/admin/admins/adm_keeper", raw["admin"], ""); rec.Code != http.StatusConflict {
		t.Fatalf("last-admin delete: want 409, got %d body=%s", rec.Code, rec.Body.String())
	}
	// adm_keeper still present.
	rec = do(http.MethodGet, "/admin/admins", raw["admin"], "")
	if admins, _ := decode(rec)["admins"].([]any); len(admins) != 1 {
		t.Fatalf("after deletes want 1 admin remaining, got %d", len(admins))
	}
}

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// interceptionRootsAs asks GET /admin/interception-roots as a specific admin identity. Roles are part of the
// question here, not scenery: an operator (admin.tenant.admin) is supposed to see the whole table, and a
// tenant admin is not, so a test that does not choose a role is not testing a boundary.
func interceptionRootsAs(t *testing.T, interception *edgeplane.NetworkExtensionLabTLSInterception, tenant string, roles []string) map[string]any {
	t.Helper()
	mux := http.NewServeMux()
	registerInterceptionPKIRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		serverConfig{NetworkExtensionLabTLS: interception}, testEvaluator(), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/interception-roots", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_test", TenantID: tenant, Roles: roles, AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func rootTenants(t *testing.T, body map[string]any) []string {
	t.Helper()
	rows, _ := body["per_tenant"].([]any)
	out := []string{}
	for _, row := range rows {
		if m, ok := row.(map[string]any); ok {
			out = append(out, m["tenant"].(string))
		}
	}
	return out
}

func provisionedInterception(t *testing.T, tenants ...string) *edgeplane.NetworkExtensionLabTLSInterception {
	t.Helper()
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	interception.SetPerTenantInterceptionRootDir(t.TempDir())
	for _, tenant := range tenants {
		if _, err := interception.ProvisionTenantInterceptionRoot(tenant); err != nil {
			t.Fatalf("provision %s: %v", tenant, err)
		}
	}
	return interception
}

// ★ THE INTERCEPTION-ROOT LIST NAMED EVERY ORGANIZATION ON THE DEPLOYMENT (2026-08-16). The POST beside it was
// closed a day earlier — a customer could mint another customer's interception root — and the read was left
// answering with the whole per-tenant table to any admin.
//
// What leaks is not key material: a root certificate is public, and a tenant's own devices must be given it.
// What leaks is the MEMBERSHIP LIST — every other organization on this deployment, by tenant id, to any
// customer who asks. On a single-tenant node that list has one row and the defect is invisible, which is how
// it survived.
func TestInterceptionRootListShowsATenantOnlyItsOwn(t *testing.T) {
	interception := provisionedInterception(t, "tenant_a", "tenant_b")

	body := interceptionRootsAs(t, interception, "tenant_a", []string{"admin"})

	got := rootTenants(t, body)
	// Both halves: the other organization is absent AND the caller's own is present. Without the second, this
	// passes just as well on an empty list, which is what a broken filter and a correct one look like from
	// outside.
	if len(got) != 1 || got[0] != "tenant_a" {
		t.Fatalf("a tenant admin sees %v; it owns exactly one interception root", got)
	}
	if body["default_root_pem"] == "" {
		t.Fatal("the anchor this node signs under is missing — it is what the caller's own devices trust today")
	}
}

// The operator keeps the fleet view, and this is the one place that differs from the device screens:
// distributing each tenant's root to that tenant's devices is an operator act, and it cannot be done from a
// list that shows one tenant at a time.
func TestAnOperatorStillSeesEveryTenantsInterceptionRoot(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator")
	interception := provisionedInterception(t, "tenant_a", "tenant_b")

	got := rootTenants(t, interceptionRootsAs(t, interception, "tenant_operator", []string{"super_admin"}))

	if len(got) != 2 {
		t.Fatalf("an operator sees %v; distributing roots fleet-wide needs all of them", got)
	}
}

// ★ AND THE ANSWER SAYS WHETHER THOSE ROOTS SIGN ANYTHING. Provisioning a per-tenant root, listing it and
// distributing it tells an operator nothing about which CA a device will really see: under the shared scope —
// and under the offline intermediate the reference deployment actually runs — every leaf is minted by ONE CA
// regardless of how many roots exist. A screen that cannot say so teaches its reader that interception is
// separated per tenant when it is not. This is E-13b, reported rather than implied.
func TestTheRootListSaysWhetherPerTenantRootsActuallySign(t *testing.T) {
	interception := provisionedInterception(t, "tenant_a")

	scope, _ := interceptionRootsAs(t, interception, "tenant_a", []string{"admin"})["signing_scope"].(map[string]any)

	if scope == nil {
		t.Fatal("the list does not say what signs; a root that exists and a root that signs are different facts")
	}
	if scope["per_tenant_signing"] != false {
		t.Fatalf("claimed per-tenant signing while the registry is shared: %v", scope)
	}
	if scope["configured"] != "shared" {
		t.Fatalf("configured = %v, want shared", scope["configured"])
	}
}

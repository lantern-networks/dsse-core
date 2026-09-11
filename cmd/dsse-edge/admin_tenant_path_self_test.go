package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ★★ A TENANT ADMINISTRATOR HAD NO WAY TO NAME THEIR OWN TENANT IN A PATH (2026-08-18).
//
// The PKI routes split on where the tenant is written. /admin/tenant-cas takes it in the BODY, so a customer
// administrator omits it and the server answers for whoever is calling — that is how the device-CA screen
// works, after an earlier fix removed an empty string it had been posting. The interception-CA routes take it
// in the PATH, where "omit it" is not available: an empty segment does not mean "me", it routes to the
// node-wide collection endpoint, which is operator-only.
//
// So the Console had to write the customer's own tenant id into the URL — an id the customer's own screen has
// no reliable source for and should not need, since the session already established who is calling. Every
// screen that replaces a tenant's own interception authority hits this, which is the act the product says
// belongs to the tenant administrator and not to the provider.
func TestSelfInATenantPathMeansTheCallersOwnTenant(t *testing.T) {
	as := func(tenant string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		if tenant == "" {
			return r
		}
		return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{},
			adminIdentity{PrincipalID: "adm_test", TenantID: tenant, AuthMethod: "admin_session"}))
	}

	got, err := adminResolveTenantPathTarget(as("tenant_northwind"), "self")
	if err != nil {
		t.Fatalf("self for a tenant administrator: %v", err)
	}
	if got != "tenant_northwind" {
		t.Fatalf("self resolved to %q, not the caller's own tenant", got)
	}

	// Case-insensitively, the same way every other tenant comparison in this tree works.
	if got, err := adminResolveTenantPathTarget(as("tenant_northwind"), "SELF"); err != nil || got != "tenant_northwind" {
		t.Fatalf("SELF resolved to %q (%v)", got, err)
	}

	// ★ AND AN OPERATOR WHO HAS NOT ENTERED A TENANT HAS NO "SELF". The alternative is performing a tenant act
	// against an empty tenant id — which adminTenantPKITargetAllowed permits, because an empty target is how a
	// single-tenant deployment addresses itself — and reporting success for a tenant that does not exist.
	if got, err := adminResolveTenantPathTarget(as(""), "self"); err == nil {
		t.Fatalf("an unscoped operator resolved self to %q instead of being refused", got)
	} else if !strings.Contains(err.Error(), "enter a tenant") {
		t.Fatalf("the refusal does not say what to do instead: %v", err)
	}

	// ★ THE CONTROL. Without it this passes for an implementation that returns the caller's tenant for EVERY
	// path value — which would silently redirect an operator's cross-tenant act onto themselves, the exact
	// failure the write-tenant work closed elsewhere.
	if got, err := adminResolveTenantPathTarget(as("tenant_operator_001"), "tenant_northwind"); err != nil {
		t.Fatalf("naming another tenant: %v", err)
	} else if got != "tenant_northwind" {
		t.Fatalf("a named tenant was rewritten to %q — a write was redirected onto the caller", got)
	}
	// A literal that merely contains "self" is not the keyword.
	if got, _ := adminResolveTenantPathTarget(as("tenant_a"), "tenant_selfserve"); got != "tenant_selfserve" {
		t.Fatalf("a tenant whose id contains \"self\" was rewritten to %q", got)
	}
}

// And the route actually uses it: resolving in a helper nothing calls is the shape this repo has been bitten by.
func TestTheInterceptionCARoutesResolveSelf(t *testing.T) {
	raw, err := os.ReadFile("admin_interception_pki_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	src := string(raw)
	tenantRoutes := strings.Count(src, `r.PathValue("tenant")`)
	resolves := strings.Count(src, "adminResolveTenantPathTarget(r, target)")
	if tenantRoutes == 0 {
		t.Fatal("no {tenant} routes found — this gate is reading the wrong file and would pass for anything")
	}
	if resolves != tenantRoutes {
		t.Fatalf("%d routes take a {tenant} path value and %d resolve \"self\" — a tenant administrator cannot "+
			"address their own tenant on the rest", tenantRoutes, resolves)
	}
}

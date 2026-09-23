package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func lifecycleRequest(tenant string, roles ...string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/admin/tenants/tenant_victim", nil)
	if tenant == "" && len(roles) == 0 {
		return r
	}
	if len(roles) == 0 {
		roles = []string{"admin", "super_admin"}
	}
	return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_probe", TenantID: tenant, Roles: roles, AuthMethod: "admin_session"}))
}

// ★★★ A CUSTOMER ENDED ANOTHER CUSTOMER (2026-08-22, measured live — see the file this tests).
func TestEndingAnOrganizationBelongsToWhoeverOperatesTheDeployment(t *testing.T) {
	declareOperatorTenant("tenant_operator_001", true)
	t.Cleanup(func() { declareOperatorTenant("tenant_operator_001", true) })

	// The measured attacker: a real customer's own super_admin, holding admin.tenant.admin.
	w := httptest.NewRecorder()
	if adminOperatorOnlyOrganizationAct(w, lifecycleRequest("tenant_reference_lab"), "deleting an organization") {
		t.Fatal("a customer super_admin was allowed to delete an organization")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("refused with HTTP %d, not 403", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "tenant_reference_lab") {
		t.Fatalf("the refusal does not tell the caller which organization they are in: %s", body)
	}

	// ★ THE CONTROL. Without it this passes for a gate that refuses EVERYONE, which would take organization
	// administration away from the operator entirely and look identical from the customer's side.
	if !adminOperatorOnlyOrganizationAct(httptest.NewRecorder(),
		lifecycleRequest("tenant_operator_001"), "deleting an organization") {
		t.Fatal("the operator was refused — this gate would close the route for everybody")
	}
	// ★ AND A DEPLOYMENT WITH NO TENANT MODEL STILL ADMINISTERS ITSELF.
	if !adminOperatorOnlyOrganizationAct(httptest.NewRecorder(), lifecycleRequest(""), "deleting an organization") {
		t.Fatal("an unscoped single-tenant deployment was refused")
	}
	// ★ AND THE ROLE ALONE IS STILL NOT THE ANSWER: a customer keeping the role but losing the organization
	// match must stay refused even when no operator organization is declared at all.
	declareOperatorTenant("", true)
	if adminOperatorOnlyOrganizationAct(httptest.NewRecorder(),
		lifecycleRequest("tenant_reference_lab"), "deleting an organization") {
		t.Fatal("with no operator organization declared, a customer was allowed to delete an organization")
	}
}

// Counting is the other shape: your own organization is the point of the route; another's is not.
func TestCountingAnotherOrganizationsDataNeedsCrossOrganizationRights(t *testing.T) {
	readRequest := func(tenant string) *http.Request { r := lifecycleRequest(tenant); r.Method = http.MethodGet; return r }

	declareOperatorTenant("tenant_operator_001", true)
	t.Cleanup(func() { declareOperatorTenant("tenant_operator_001", true) })

	if adminTenantPathReadAllowed(httptest.NewRecorder(),
		readRequest("tenant_reference_lab"), "tenant_northwind", "counting the data of") {
		t.Fatal("a customer counted another organization's data")
	}
	// ★ THE CONTROL: their own organization still answers, or the route is useless to the customer it is for.
	if !adminTenantPathReadAllowed(httptest.NewRecorder(),
		readRequest("tenant_reference_lab"), "tenant_reference_lab", "counting the data of") {
		t.Fatal("an organization was refused a count of its OWN data")
	}
	if !adminTenantPathReadAllowed(httptest.NewRecorder(),
		readRequest("tenant_operator_001"), "tenant_northwind", "counting the data of") {
		t.Fatal("the operator was refused")
	}
}

// ★★ AND THE RATCHET: every admin route that names an organization in its PATH asks whether the caller may.
//
// The middleware guard for X-Operate-Tenant does not help here — the victim is in the URL, not a header — so
// there is no place this can be enforced centrally. It therefore has to be enforced per route, which is
// exactly the kind of rule that gets forgotten. This counts them instead.
func TestEveryTenantPathRouteAsksWhetherTheCallerMay(t *testing.T) {
	// Recognised gates, each of which resolves the caller's organization rather than trusting the path.
	gates := []string{
		"adminOperatorOnlyOrganizationAct(",
		"adminTenantPathReadAllowed(",
		"adminTenantPKITargetAllowed(",
		"adminCallerIsOperator(",
	}
	// Named exceptions, with the reason. A route listed here still gates; it just does it inline and
	// predates the helpers. Empty is fine; a name with no reason is not.
	inlineGates := map[string]string{
		"DELETE /admin/seat-allocations/{tenant}": "compares the path against adminTenantIDFromRequest inline " +
			"and refuses with \"may only release seats for\"",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	// ★ NOT ONLY /admin/ (2026-08-22). Every cross-organization sweep this tree has written greps for routes
	// under /admin/, and there are eight admin-GATED routes that do not live there — break-glass and the
	// connector surface. None takes an organization in its path today and all eight are unregistered in the
	// reference deployment, so this widening finds nothing now; it is here because the blind spot was real and
	// the next route to be added outside /admin/ would inherit it.
	route := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) (/[^"]*\{tenant[^"]*)"`)
	var open []string
	found := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		src := string(raw)
		for _, m := range route.FindAllStringSubmatchIndex(src, -1) {
			found++
			method, path := src[m[2]:m[3]], src[m[4]:m[5]]
			// The handler body: up to the next registration, or the end of the file.
			end := strings.Index(src[m[1]:], "mux.HandleFunc(")
			body := src[m[0]:]
			if end > 0 {
				body = src[m[0] : m[1]+end]
			}
			gated := false
			for _, g := range gates {
				if strings.Contains(body, g) {
					gated = true
					break
				}
			}
			key := method + " " + path
			if !gated && strings.TrimSpace(inlineGates[key]) == "" {
				open = append(open, key+"  ("+name+")")
			}
		}
	}
	// ★ NOTHING FOUND IS NOT A PASS. Five of these routes were open on 2026-08-22; a regex that stops matching
	// would report a clean sweep of nothing at all, which is the shape this repo keeps finding in its own gates.
	if found < 10 {
		t.Fatalf("only %d tenant-path routes matched — this gate is looking for the wrong thing and would "+
			"pass for anything", found)
	}
	if len(open) > 0 {
		t.Fatalf("%d admin route(s) name an organization in the path and never ask whether the caller may:\n  %s\n"+
			"A customer's super_admin holds admin.tenant.admin, so the permission alone is not the answer — "+
			"see an_organizations_life_is_not_a_customers_to_end.go.", len(open), strings.Join(open, "\n  "))
	}
	t.Logf("%d tenant-path admin routes, all gated", found)
}

// ★★ THE CLAIM THE lab_bypass EXEMPTION RESTS ON, MEASURED RATHER THAN ASSERTED IN A COMMENT.
//
// adminIdentityMayActAcrossOrganizations lets an identity whose AuthMethod is "lab_bypass" act across
// organizations, on the grounds that it is synthesised for an UNAUTHENTICATED request and its tenant id is
// the node's own, not a claim about the caller. That is only safe while such an identity cannot be produced
// in a deployment that is not in lab mode. If it ever can, the exemption becomes a way to cross every
// organization boundary in this product by presenting nothing at all.
func TestLabBypassIsUnreachableWithoutDevMode(t *testing.T) {
	store := newAdminAuthStore()
	now := time.Now().UTC()

	// Nothing presented, no legacy token armed, production (devMode=false).
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	identity, ok, err := adminRequestIdentity(req, "tenant_lab_001", "", store, false, now)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if ok {
		t.Fatalf("an unauthenticated request authenticated in production as %+v", identity)
	}

	// ★ THE CONTROL. Without it this passes for a build where adminRequestIdentity always refuses, and the
	// exemption above would be dead code guarding nothing — which reads exactly like a gate that works.
	labIdentity, labOK, err := adminRequestIdentity(req, "tenant_lab_001", "", store, true, now)
	if err != nil {
		t.Fatalf("resolve identity in lab mode: %v", err)
	}
	if !labOK {
		t.Fatal("lab mode did not synthesise an identity — this test is no longer measuring the exemption")
	}
	if labIdentity.AuthMethod != adminLabBypassAuthMethod {
		t.Fatalf("lab mode stamped AuthMethod %q, and the exemption keys on %q — one of them has been renamed "+
			"and the check now matches nothing", labIdentity.AuthMethod, adminLabBypassAuthMethod)
	}
	// And that identity is the one the exemption is for.
	declareOperatorTenant("tenant_operator_001", true)
	t.Cleanup(func() { declareOperatorTenant("tenant_operator_001", true) })
	if !adminIdentityMayActAcrossOrganizations(labIdentity) {
		t.Fatal("the lab-mode identity was refused — an unauthenticated lab deployment cannot administer itself")
	}
	// ★ AND THE EXEMPTION IS NOT A PASSWORD. A real customer session that merely CLAIMS lab_bypass is not one:
	// AuthMethod is stamped by the server, never read from the request, so this is the shape to keep proving.
	customer := adminIdentity{PrincipalID: "adm_c", TenantID: "tenant_reference_lab",
		Roles: []string{"admin", "super_admin"}, AuthMethod: "admin_session"}
	if adminIdentityMayActAcrossOrganizations(customer) {
		t.Fatal("a customer session acted across organizations")
	}
}

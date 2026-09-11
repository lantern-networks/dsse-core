package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
)

func deploymentWideIdentity(tenant, authMethod string) adminIdentity {
	return adminIdentity{PrincipalID: "adm_probe", TenantID: tenant, Roles: []string{"admin", "super_admin"},
		AuthMethod: authMethod}
}

// ★★★ A CUSTOMER REACHED ALL THIRTEEN DEPLOYMENT-WIDE ROUTES (2026-08-22, measured live).
func TestDeploymentWideActsBelongToWhoeverOperatesTheDeployment(t *testing.T) {
	declareOperatorTenant("tenant_operator_001", true)
	t.Cleanup(func() { declareOperatorTenant("tenant_operator_001", true) })

	for permission, what := range adminDeploymentWidePermissions {
		err := adminDeploymentWideActAllowed(deploymentWideIdentity("tenant_reference_lab", "admin_session"), permission)
		if err == nil {
			t.Fatalf("a customer super_admin was allowed a deployment-wide act gated on %s", permission)
		}
		if !strings.Contains(err.Error(), what) || !strings.Contains(err.Error(), "tenant_reference_lab") {
			t.Fatalf("the refusal for %s says neither what it changes nor who is calling: %v", permission, err)
		}
		// ★ THE CONTROL. Without it this passes for a gate that refuses everyone, which would take the
		// deployment's own administration away from the operator and look identical from a customer's side.
		if err := adminDeploymentWideActAllowed(deploymentWideIdentity("tenant_operator_001", "admin_session"), permission); err != nil {
			t.Fatalf("the operator was refused %s: %v", permission, err)
		}
	}

	// ★ EVERY OTHER ROUTE IS UNTOUCHED, or this gate is a blanket refusal wearing a specific name.
	for _, ordinary := range []string{"admin.policy.write", "admin.steering.write", "admin.enrollment.write",
		"admin.tenant.admin", "admin.platform.write|admin.tenant.admin"} {
		if err := adminDeploymentWideActAllowed(deploymentWideIdentity("tenant_reference_lab", "admin_session"), ordinary); err != nil {
			t.Fatalf("a customer was refused %s, which is not a deployment-wide act: %v", ordinary, err)
		}
	}
}

// ★★ AND THE PERMISSIONS NAMED HERE ARE THE ONES THE ROLE TABLE CALLS THE OPERATOR'S.
//
// The set above is hand-written, and a hand-written set drifts: the day a fourteenth deployment-wide route
// arrives under a new permission, nothing here notices. So it is checked against the place the product
// already states the answer — the super_admin grant in the role table, whose comment says in as many words
// that these are "acts on the whole installation".
func TestTheDeploymentWidePermissionsAreTheOnesTheRoleTableCallsTheOperators(t *testing.T) {
	raw, err := os.ReadFile("admin_auth_store.go")
	if err != nil {
		t.Fatalf("read the role table: %v", err)
	}
	block := regexp.MustCompile(`(?s)"super_admin":\s*\{(.*?)\n\t\},`).FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatal("the super_admin role block was not found — this gate is reading the wrong file")
	}
	granted := map[string]bool{}
	for _, m := range regexp.MustCompile(`"(admin\.[a-z._]+)":\s*true`).FindAllStringSubmatch(block[1], -1) {
		granted[m[1]] = true
	}
	if len(granted) < 5 {
		t.Fatalf("only %d permissions parsed out of the super_admin grant — the shape has changed and this "+
			"check is measuring nothing", len(granted))
	}
	for permission := range adminDeploymentWidePermissions {
		if !granted[permission] {
			t.Errorf("%s is treated as deployment-wide here but super_admin no longer holds it — one of the "+
				"two has moved, and the gate may now be refusing an act nobody can perform", permission)
		}
	}
}

// And the routes actually go through the middleware that calls it: a gate wired into nothing is the shape
// this repo has been bitten by more than once.
func TestTheDeploymentWideGateIsWiredIntoTheAdminMiddleware(t *testing.T) {
	raw, err := os.ReadFile("admin_endpoint_middleware.go")
	if err != nil {
		t.Fatalf("read the middleware: %v", err)
	}
	if !strings.Contains(string(raw), "adminDeploymentWideActAllowed(identity, permission)") {
		t.Fatal("the admin middleware does not call adminDeploymentWideActAllowed, so nothing is gated")
	}
	// And there is something to gate.
	entries, _ := os.ReadDir(".")
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, _ := os.ReadFile(e.Name())
		count += strings.Count(string(b), `adminEndpoint("admin.platform.write"`)
		count += strings.Count(string(b), `adminEndpoint("admin.quota.write"`)
	}
	if count < 10 {
		t.Fatalf("only %d deployment-wide routes found (13 on 2026-08-22) — the registration shape has "+
			"changed and this check would pass for a tree with none", count)
	}
	t.Logf("%d deployment-wide routes behind the middleware gate", count)
}

// ★★★ THROUGH THE DOOR THE CALLER ACTUALLY USES (2026-08-22).
//
// The first version of this gate was correct as a function and wrong at its only call site: inside the admin
// middleware the identity is attached to the request context on the LAST line, so asking the request who was
// calling found nobody, read that as an unscoped single-tenant deployment, and let every customer through.
// The unit test above passed the whole time, because it called the helper directly with a request that had
// been given an identity by hand.
//
// So this one signs a customer in and makes the request, and asserts on what the SERVER answers.
func TestACustomerIsRefusedADeploymentWideRouteThroughTheAdminMiddleware(t *testing.T) {
	const customerBearer = "raw-customer-super-admin-deployment-wide"
	const operatorBearer = "raw-operator-deployment-wide"
	auth := newAdminAuthStore()
	seat := func(principal, tenant, bearer string) {
		auth.UpsertPrincipal(adminPrincipal{ID: principal, TenantID: tenant, Subject: principal,
			Email: principal + "@lab.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "first_party",
			Status: "active", CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
		auth.UpsertAPIToken(adminAPIToken{ID: "tok_" + principal, TenantID: tenant, Name: principal,
			TokenHash: adminTokenHash(bearer), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
			CreatedByAdminPrincipalID: principal,
			CreatedAt:                 time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			ExpiresAt:                 time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Status: "active"})
	}
	seat("adm_customer", "tenant_reference_lab", customerBearer)
	seat("adm_operator", "tenant_operator_001", operatorBearer)

	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         connector.NewRegistry(),
		AdminAuth:        auth,
		TenantModelStore: newAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now().UTC()),
		OperatorTenantID: "tenant_operator_001",
	})

	post := func(bearer, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("authorization", "Bearer "+bearer)
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Publishing software to every device in the deployment.
	rec := post(customerBearer, "/admin/agent-updates", `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a customer super_admin reached agent release publishing: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "whole deployment") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}
	// Asserting that a device holds a certificate, which counts towards a fleet-wide withdrawal.
	rec = post(customerBearer, "/admin/transport-trust-anchors/"+strings.Repeat("0", 64)+"/acknowledge",
		`{"identity":"probe","reason":"probe"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a customer super_admin acknowledged a fleet trust anchor: HTTP %d %s", rec.Code, rec.Body.String())
	}

	// ★ THE CONTROL, AND IT IS THE PART THAT MATTERS. Without it this passes for a build where the route is
	// simply unreachable — 403 for everybody reads exactly like 403 for the wrong people. The operator must
	// get PAST authorization; whether the empty body is then accepted is not this test's business.
	rec = post(operatorBearer, "/admin/agent-updates", `{}`)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("the operator was refused agent release publishing, so this gate refuses everyone: %s", rec.Body.String())
	}
	rec = post(operatorBearer, "/admin/transport-trust-anchors/"+strings.Repeat("0", 64)+"/acknowledge",
		`{"identity":"probe","reason":"probe"}`)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("the operator was refused a trust-anchor acknowledgement: %s", rec.Body.String())
	}

	// ★ AND A CUSTOMER'S OWN ORGANIZATION IS UNAFFECTED, or this closed a customer-side act to fix an
	// operator-side hole — which is the mistake the 2026-08-15 note warns against by name.
	own := httptest.NewRequest(http.MethodGet, "/admin/policies", nil)
	own.Header.Set("authorization", "Bearer "+customerBearer)
	ownRec := httptest.NewRecorder()
	handler.ServeHTTP(ownRec, own)
	if ownRec.Code == http.StatusForbidden {
		t.Fatalf("a customer lost a read of their own organization: %s", ownRec.Body.String())
	}
}

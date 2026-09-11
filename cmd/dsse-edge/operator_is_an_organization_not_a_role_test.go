package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ A CUSTOMER'S super_admin IS NOT AN OPERATOR (2026-08-21, found live). Signed in as a super_admin of
// tenant_reference_lab — a customer organization, is_operator_tenant: false — X-Operate-Tenant: tenant_northwind
// returned that organization's policies, licence, PKI install bundle and entire audit trail. The gate asked
// which ROLE the caller held; the role is granted inside a customer organization.
func TestACustomersSuperAdminIsNotAnOperator(t *testing.T) {
	customer := adminIdentity{PrincipalID: "adm_customer", TenantID: "tenant_reference_lab",
		Roles: []string{"admin", "super_admin"}}
	operator := adminIdentity{PrincipalID: "adm_operator", TenantID: "tenant_operator_001",
		Roles: []string{"admin", "super_admin"}}
	tenantAdmin := adminIdentity{PrincipalID: "adm_plain", TenantID: "tenant_operator_001",
		Roles: []string{"admin"}}
	unscoped := adminIdentity{PrincipalID: "adm_unscoped", Roles: []string{"super_admin"}}
	// ★ AND A NON-OPERATOR ROLE WITH NO ORGANIZATION IS STILL NOT AN OPERATOR. An earlier draft let the empty
	// organization short-circuit ahead of the role, so a plain admin sending X-Operate-Tenant was answered as
	// the organization it named. The fail-closed test found it; this keeps it found.
	unscopedPlain := adminIdentity{PrincipalID: "adm_unscoped_plain", Roles: []string{"admin"}}

	// The negative control first: with no operator organization declared, NOBODY who belongs to one crosses.
	declareOperatorTenant("", true)
	if adminIdentityMayActAcrossOrganizations(customer) {
		t.Fatal("with no operator organization configured, a customer super_admin was allowed to cross. " +
			"Refusing is the safe direction: the alternative is every customer's super_admin reaching every other.")
	}
	if adminIdentityMayActAcrossOrganizations(operator) {
		t.Fatal("with no operator organization configured, a principal of tenant_operator_001 crossed — " +
			"nothing had named that organization as the operator, so there was nothing to be answered from")
	}
	if !adminIdentityMayActAcrossOrganizations(unscoped) {
		t.Fatal("a deployment with no tenant model attaches no organization to the identity; there is nothing " +
			"to cross and this must stay allowed, or every single-tenant edge loses its admin plane")
	}
	if adminIdentityMayActAcrossOrganizations(unscopedPlain) {
		t.Fatal("an identity with no organization AND no admin.tenant.admin was allowed to cross — the role " +
			"is checked first, precisely so an empty organization cannot short-circuit past it")
	}

	declareOperatorTenant("tenant_operator_001", true)
	defer declareOperatorTenant("", false)

	if adminIdentityMayActAcrossOrganizations(customer) {
		t.Fatal("★ a super_admin of tenant_reference_lab was allowed to act inside another organization. " +
			"super_admin is a role a CUSTOMER grants inside itself; it is not a cross-organization right.")
	}
	if !adminIdentityMayActAcrossOrganizations(operator) {
		t.Fatal("the operator organization's super_admin was refused — that is the one principal this whole " +
			"envelope exists to let through, and refusing it locks the deployment out of its own customers")
	}
	if adminIdentityMayActAcrossOrganizations(tenantAdmin) {
		t.Fatal("an ordinary administrator of the operator organization crossed. Belonging to the operator " +
			"is necessary, not sufficient: admin.tenant.admin is still required.")
	}
}

// ★ AND NOTHING MAY GO BACK TO ASKING THE ROLE ALONE. Four separate gates each carried this check, and one of
// them being fixed would not have helped: the reader that answered the audit trail was a different one from
// the reader that answered the install bundle. This is the ratchet, not the fix.
func TestNoCrossOrganizationGateAsksOnlyForTheRole(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package: %v", err)
	}
	// The role check is legitimate INSIDE one organization — granting roles, seating administrators. What is
	// forbidden is using it to decide whether a caller may be answered as a DIFFERENT organization, which in
	// this package is always in the company of the operate override or the caller's own tenant id.
	pattern := regexp.MustCompile(`adminPermissionAllowed\([^)]*Roles, "admin\.tenant\.admin"\)`)
	offenders := []string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// The helper itself holds the one legitimate role check, and its comment quotes the header it replaced.
		if name == "operator_is_an_organization_not_a_role.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		for _, line := range lineNumbersMatching(text, pattern) {
			window := windowAround(text, line, 6)
			if strings.Contains(window, "X-Operate-Tenant") || strings.Contains(window, "adminOperateTenant(") {
				offenders = append(offenders, name+":"+line)
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these decide cross-organization reach from the ROLE alone: %s\n"+
			"Use adminIdentityMayActAcrossOrganizations — the caller must hold admin.tenant.admin AND belong "+
			"to the organization named by -operator-tenant-id. A customer's super_admin is a super_admin of "+
			"that customer.", strings.Join(offenders, ", "))
	}
	// ★ AND THE CHECK ITSELF MUST STILL BE FINDABLE, or this passes because the helper was renamed away.
	found := false
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(body), "func adminIdentityMayActAcrossOrganizations(") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("adminIdentityMayActAcrossOrganizations is gone — this check now proves nothing")
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func lineNumbersMatching(text string, pattern *regexp.Regexp) []string {
	out := []string{}
	for i, line := range strings.Split(text, "\n") {
		if pattern.MatchString(line) {
			out = append(out, itoa(i+1))
		}
	}
	return out
}

func windowAround(text, line string, radius int) string {
	lines := strings.Split(text, "\n")
	n := atoiSafe(line) - 1
	lo, hi := n-radius, n+radius
	if lo < 0 {
		lo = 0
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	return strings.Join(lines[lo:hi], "\n")
}

// ★★★ AND THE CUSTOMER LIST IS NOT A CUSTOMER'S TO READ (2026-08-21, measured live). GET /admin/tenants asks
// for admin.tenant.admin, which super_admin grants inside a CUSTOMER organization — so an administrator of
// tenant_reference_lab was handed every organization on the deployment: ids, display names, plans, status.
func TestTheTenantListShowsACustomerOnlyItsOwnOrganization(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")

	now := time.Now().UTC()
	auth := newAdminAuthStore()
	seed := func(id, tenant, bearer string, roles []string) {
		auth.UpsertPrincipal(adminPrincipal{ID: "adm_" + id, TenantID: tenant, Subject: "sub_" + id,
			Email: id + "@example.invalid", Roles: roles, IDPID: "keycloak_lab", Status: "active",
			CreatedAt: now.Add(-time.Hour).Format(time.RFC3339)})
		auth.UpsertAPIToken(adminAPIToken{ID: "tok_" + id, TenantID: tenant, Name: id,
			TokenHash: adminTokenHash(bearer), Roles: roles, Scopes: []string{"*"},
			CreatedByAdminPrincipalID: "adm_" + id,
			CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active"})
	}
	seed("customer", "tenant_reference_lab", "raw-customer-super-admin", []string{"admin", "super_admin"})
	seed("operator", "tenant_operator_001", "raw-real-operator", []string{"admin", "super_admin"})

	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "tenant_operator_001")
	for _, id := range []string{"tenant_operator_001", "tenant_reference_lab", "tenant_northwind", "tenant_acme"} {
		if _, err := tenants.Put(context.Background(),
			adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants,
		OperatorTenantID: "tenant_operator_001",
	})

	list := func(bearer string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		req.Header.Set("authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /admin/tenants as %s: HTTP %d %s", bearer, rec.Code, rec.Body.String())
		}
		var body struct {
			Tenants []adminTenantModel `json:"tenants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ids := make([]string, 0, len(body.Tenants))
		for _, tenant := range body.Tenants {
			ids = append(ids, tenant.TenantID)
		}
		sort.Strings(ids)
		return ids
	}

	got := list("raw-customer-super-admin")
	if len(got) != 1 || got[0] != "tenant_reference_lab" {
		t.Fatalf("a customer's super_admin was handed the customer list: %v — a multi-tenant deployment must "+
			"never disclose who else is on it", got)
	}

	// ★ THE CONTROL, so this does not pass because the route broke for everybody. The operator still sees the
	// whole deployment, which is the only reason the route exists.
	whole := list("raw-real-operator")
	if len(whole) < 4 {
		t.Fatalf("the operator lost the deployment view (%v) — the filter was supposed to narrow the CALLER, "+
			"not the route", whole)
	}
}

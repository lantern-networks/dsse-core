package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★ CAN ONE CUSTOMER NAME ANOTHER IN A WRITE? (2026-08-18, measured live with two real customer sessions —
// the first time this deployment had two, so the first time the question could be asked at all.)
//
// Ten admin writes take a tenant in the path: the interception issuer and its revocation, the per-tenant
// interception root and its withdrawal, a tenant CA and one of its certificates, seat allocations, tenant
// deletion and purge. Acme's own administrator naming tenant_northwind was refused on all ten.
//
// The control is what makes that mean something: Acme naming ITSELF passes the guard on the same routes
// (400 on a malformed body, 200 where the route takes none), so the ten refusals are a tenant boundary and
// not an absent permission.
//
// This test pins the guard rather than the live result: every {tenant} write must run the cross-tenant check
// before it acts. A route added tomorrow that forgets it is the whole failure mode — and the repo has closed
// that exact family twice, on reads and on writes.
func TestEveryTenantPathWriteChecksTheCrossTenantGuard(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	// The scope is captured too: a {tenant} write is also safe when NO CUSTOMER HOLDS the permission it
	// requires, because then the tenant boundary is enforced one layer up and the handler never runs.
	//
	// Measured, not assumed (2026-08-18, read from a real customer session's own permission list): a customer
	// administrator holds admin.policy.write, admin.enrollment.write and admin.retention.write, and does NOT
	// hold admin.tenant.admin, admin.quota.write, admin.platform.write, admin.certs.write or admin.dns.write.
	// Deleting or purging a tenant, and moving seat allocations, sit behind the second group.
	route := regexp.MustCompile(`mux\.HandleFunc\("((?:POST|PUT|PATCH|DELETE) /admin/[^"]*\{tenant[^"]*)",\s*adminEndpoint\("([^"]+)"`)
	operatorOnly := map[string]bool{
		"admin.tenant.admin": true, "admin.quota.write": true, "admin.platform.write": true,
		"admin.certs.write": true, "admin.dns.write": true,
	}
	scopeIsOperatorOnly := func(scope string) bool {
		// Either-of scopes ("a|b") are reachable by a customer if ANY alternative is theirs.
		for _, alt := range strings.Split(scope, "|") {
			if !operatorOnly[strings.TrimSpace(alt)] {
				return false
			}
		}
		return strings.TrimSpace(scope) != ""
	}
	var unguarded []string
	found := 0
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			continue
		}
		lines := strings.Split(string(raw), "\n")
		for i, l := range lines {
			m := route.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			found++
			if scopeIsOperatorOnly(m[2]) {
				continue
			}
			// The handler body, to the closing of the registration.
			body := strings.Join(lines[i:min(i+90, len(lines))], "\n")
			if !strings.Contains(body, "adminTenantPKITargetAllowed") &&
				!strings.Contains(body, "adminTenantForWrite") &&
				!strings.Contains(body, "adminCallerIsOperator") {
				unguarded = append(unguarded, m[1]+" ("+m[2]+")  ["+f.Name()+"]")
			}
		}
	}
	if found < 8 {
		t.Fatalf("only %d {tenant} writes found — this gate is reading the wrong tree and would pass for "+
			"anything", found)
	}
	if len(unguarded) > 0 {
		t.Fatalf("these writes take another tenant's name in the path and no cross-tenant guard is visible in "+
			"the handler: %v", unguarded)
	}
}

// ★ AND THE GUARD ITSELF MUST STILL REFUSE. The scan above proves the call is present; this proves what it
// answers, so a guard that was quietly loosened cannot pass by still being called.
func TestOneCustomerMayNotNameAnother(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	as := func(tenant string, operator bool) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/admin/interception-intermediate/tenant_northwind", nil)
		roles := []string{"admin"}
		if operator {
			roles = append(roles, "super_admin")
			r.Header.Set("X-Operate-Tenant", "tenant_northwind")
		}
		return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{},
			adminIdentity{PrincipalID: "adm", TenantID: tenant, Roles: roles, AuthMethod: "admin_session"}))
	}
	if err := adminTenantPKITargetAllowed(as("tenant_acme", false), "tenant_northwind", "writing"); err == nil {
		t.Fatal("one customer may name another in a write")
	}
	// The control: its own tenant passes, or the refusal above is a permission gap rather than a boundary —
	// which is exactly the ambiguity the live probe had to resolve with a second credential.
	if err := adminTenantPKITargetAllowed(as("tenant_acme", false), "tenant_acme", "writing"); err != nil {
		t.Fatalf("a customer cannot write its own tenant, so the refusal above proves nothing: %v", err)
	}
	// And an operator still reaches another tenant — that is the envelope, not a hole.
	if err := adminTenantPKITargetAllowed(as("tenant_operator_001", true), "tenant_northwind", "writing"); err != nil {
		t.Fatalf("an operator can no longer act inside a tenant: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ★★ AND A TENANT NAMED IN THE BODY IS THE OTHER HALF (2026-08-18). Four writes decode a tenant from the
// request body. Three are behind a scope no customer holds; the fourth, POST /admin/admins/invite, refuses a
// body tenant that is not the one being operated in — inline, with a sentence written for the reader rather
// than through one of the shared helpers, which is why the scan above does not see it.
//
// Measured as Acme's own administrator: naming tenant_northwind in the body answers 400 ("this invitation
// would go to organization tenant_acme, not tenant_northwind"), and naming it in X-Operate-Tenant answers 403
// ("you may only act in tenant_acme"). Both refusals say what happened and what to do instead.
//
// The gate is on the SHAPE: a body field that names a tenant must be compared against the operating tenant,
// or dropped. A field that changes nothing is worse than a field that does not exist — that is not a slogan
// here, it is what this route did on 2026-08-15, when the decoder silently discarded tenant_id and seated the
// administrator in the caller's tenant with a 201 and no mention of which organization they had joined.
func TestABodyTenantIsComparedAgainstTheOperatingTenant(t *testing.T) {
	src, err := os.ReadFile("admin_auth_store.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, `TenantID string`) || !strings.Contains(body, `json:"tenant_id"`) {
		t.Fatal("the invite body no longer declares tenant_id — if the field was removed, a client that sends " +
			"it is silently ignored again, which is the 2026-08-15 defect")
	}
	if !strings.Contains(body, "this invitation would go to organization") {
		t.Fatal("the invite no longer refuses a body tenant that differs from the operating tenant")
	}
}

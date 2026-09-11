package main

import (
	"os"
	"strings"
	"testing"
)

// ★★ A TENANT ADMIN COULD SET ITS OWN DEVICE CAP (2026-08-14, operator: "a tenant administrator being able to
// decide its own device count is a bug"). POST /admin/seat-allocations read tenant_id from the BODY and never
// compared it to the caller. Every other tenant-scoped admin route derives the tenant from the identity and
// lets only an operator holding admin.tenant.admin name another one (X-Operate-Tenant). This route did not.
//
// What made it survive review is worth recording: it was not unbounded. The allocation is capped by the
// licensed pool, so a tenant could raise its own cap only up to the MSSP's total — a COMMERCIAL control
// standing in for an AUTHORISATION one. The OSS plan intends to remove the signed licence, which would have
// removed the only thing holding this.
func TestAllocationCannotNameAnotherTenant(t *testing.T) {
	// The identity resolution is what this route now shares with the rest of the admin surface; the test
	// asserts the rule at the level the fix operates on.
	for _, tc := range []struct {
		name       string
		callerTen  string
		bodyTenant string
		wantAllow  bool
	}{
		{"own tenant named explicitly", "acme", "acme", true},
		{"tenant omitted, defaults to the caller", "acme", "", true},
		{"another tenant", "acme", "victim", false},
		{"another tenant, different case", "acme", "ACME", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed := tc.bodyTenant == "" || strings.EqualFold(strings.TrimSpace(tc.bodyTenant), tc.callerTen)
			if allowed != tc.wantAllow {
				t.Fatalf("caller=%q body=%q allowed=%v want %v", tc.callerTen, tc.bodyTenant, allowed, tc.wantAllow)
			}
		})
	}
}

// And the route must actually consult the caller. A guard that exists but is not reached is the shape this
// codebase keeps paying for, so this reads the handler and fails if the derivation is gone.
func TestBothSeatRoutesDeriveTheTenantFromTheCaller(t *testing.T) {
	src := mustReadSource(t, "admin_license.go")
	post := section(src, `mux.HandleFunc("POST /admin/seat-allocations"`, `mux.HandleFunc("DELETE /admin/seat-allocations`)
	del := section(src, `mux.HandleFunc("DELETE /admin/seat-allocations`, "")
	for name, body := range map[string]string{"POST": post, "DELETE": del} {
		if !strings.Contains(body, "adminTenantIDFromRequest(r)") {
			t.Fatalf("%s /admin/seat-allocations no longer derives the tenant from the caller — a tenant admin "+
				"can name any tenant again", name)
		}
	}
}

func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func section(src, from, to string) string {
	i := strings.Index(src, from)
	if i < 0 {
		return ""
	}
	if to == "" {
		return src[i:]
	}
	j := strings.Index(src[i:], to)
	if j < 0 {
		return src[i:]
	}
	return src[i : i+j]
}

package main

import (
	"net/http/httptest"
	"testing"
)

// ★ WHOSE SIGN-IN IS THIS? (2026-08-17, measured on the lab through the console's own front door.)
//
// A Northwind administrator signed in and out. Both records landed in tenant_reference_lab's audit log — the
// NODE's organization — because the builder took the tenant from evaluator.PolicyBundle.TenantID. Two things
// were wrong at once, and only one of them is about privacy:
//
//   - Northwind's own audit trail had no record that anyone had signed into their console. "Who logged in" is
//     the first question anyone asks of an audit trail, and the answer was: nobody, ever.
//   - the node's organization accumulated other organizations' authentication events, down to the email
//     address, in a log a different customer reads.
//
// The exception is the one that has to stay: a login attempt nobody could be identified from has no
// organization to belong to, and guessing one would file a stranger's failed attempts in a customer's trail.
func TestASignInIsFiledUnderTheOrganizationOfWhoeverSignedIn(t *testing.T) {
	r := httptest.NewRequest("POST", "/admin/login/totp", nil)
	evaluator := testEvaluator() // the NODE's own tenant

	customer := adminPrincipal{ID: "adm_nw", TenantID: "tenant_northwind", Email: "someone@northwind.example", Roles: []string{"admin"}}
	record := adminLoginAuditLog("admin_login_succeeded", &customer, nil, evaluator, r, "")
	if record.TenantID != "tenant_northwind" {
		t.Fatalf("a customer's sign-in belongs to the customer's organization, got %q (the node's is %q)",
			record.TenantID, evaluator.PolicyBundle.TenantID)
	}
	if record.TenantID == evaluator.PolicyBundle.TenantID {
		t.Fatal("the record is filed under the node's own organization — the defect is back")
	}

	// Signing out is the same event class and had the same defect.
	out := adminLoginAuditLog("admin_logout", &customer, nil, evaluator, r, "")
	if out.TenantID != "tenant_northwind" {
		t.Fatalf("sign-out: got %q", out.TenantID)
	}

	// And the exception: nobody identified, so there is no organization to file it under but this node's.
	anonymous := adminLoginAuditLog("admin_login_failed", nil, nil, evaluator, r, "password")
	if anonymous.TenantID != evaluator.PolicyBundle.TenantID {
		t.Fatalf("an unattributable attempt must stay with the node rather than be filed against a guessed "+
			"customer, got %q", anonymous.TenantID)
	}

	// A principal with no tenant on it must not blank the field either — an empty tenant_id is a record that
	// belongs to nobody, which is worse than one filed with the node.
	tenantless := adminPrincipal{ID: "adm_x", Email: "x@example.com"}
	fallback := adminLoginAuditLog("admin_login_succeeded", &tenantless, nil, evaluator, r, "")
	if fallback.TenantID != evaluator.PolicyBundle.TenantID {
		t.Fatalf("a principal carrying no organization falls back to the node, got %q", fallback.TenantID)
	}
}

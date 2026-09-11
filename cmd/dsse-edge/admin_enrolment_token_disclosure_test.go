package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★ THE WARNING NAMED ANOTHER CUSTOMER TO THIS ONE (2026-08-18, walked through the Console as Northwind's own
// administrator, who holds no cross-tenant rights).
//
// "This node enrols devices for tenant_reference_lab only." Every word true, the warning itself is a fix from
// the day before — it stopped the product handing out credentials nothing can use — and it discloses the
// identity of a different customer of the same provider on a screen belonging to this one. In an MSSP
// deployment those two may be competitors.
//
// Nothing in the disclosed half is actionable. What the reader can act on is "not for you, bring your own
// device CA", which the rest of the message already says. Whoever answers for the deployment keeps the name,
// because they are who can do something about it.
func TestTheEnrolmentWarningDoesNotNameAnotherTenantToACustomer(t *testing.T) {
	as := func(tenant string, operator bool) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/admin/enrolment-tokens", nil)
		roles := []string{"admin"}
		if operator {
			roles = append(roles, "super_admin")
		}
		return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{},
			adminIdentity{PrincipalID: "adm_test", TenantID: tenant, Roles: roles, AuthMethod: "admin_session"}))
	}

	customer := as("tenant_northwind", false)
	warning := enrolmentTokenTenantWarning("tenant_northwind", "tenant_reference_lab",
		adminAnsweringForTheDeployment(customer), false)
	if warning == "" {
		t.Fatal("the customer lost the warning entirely — they would mint credentials nothing can use, which " +
			"is the defect this message exists to prevent")
	}
	if strings.Contains(warning, "tenant_reference_lab") {
		t.Fatalf("another customer is named on this customer's screen: %q", warning)
	}
	if !strings.Contains(warning, "tenant_northwind") {
		t.Fatalf("the warning no longer says whose tokens these are: %q", warning)
	}
	// The Console composes its own sentence from this field, so withholding it in prose is not enough.
	if got := enrolmentTokenEnrolsForDisclosure(customer, "tenant_reference_lab"); got != "" {
		t.Fatalf("enrols_for_tenant handed the Console %q to render on a customer's screen", got)
	}

	// ★ THE CONTROL. An operator answering for the deployment must still get the name — they are the only
	// person who can move the enrolment path, and a rule that hides it from everybody replaces a disclosure
	// with an unanswerable screen.
	operator := as("", true)
	opWarning := enrolmentTokenTenantWarning("tenant_northwind", "tenant_reference_lab",
		adminAnsweringForTheDeployment(operator), false)
	if !strings.Contains(opWarning, "tenant_reference_lab") {
		t.Fatalf("the operator lost the name too: %q", opWarning)
	}
	if got := enrolmentTokenEnrolsForDisclosure(operator, "tenant_reference_lab"); got != "tenant_reference_lab" {
		t.Fatalf("the operator's enrols_for_tenant is %q", got)
	}

	// And a node whose own tenant IS the caller's says nothing at all: there is no mismatch to warn about.
	if w := enrolmentTokenTenantWarning("tenant_northwind", "tenant_northwind", false, false); w != "" {
		t.Fatalf("a matching tenant produced a warning: %q", w)
	}
	// That tenant may of course see its own name.
	own := as("tenant_reference_lab", false)
	if got := enrolmentTokenEnrolsForDisclosure(own, "tenant_reference_lab"); got != "tenant_reference_lab" {
		t.Fatalf("a tenant was denied its own name: %q", got)
	}
}

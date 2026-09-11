package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ A CUSTOMER CANCELLED THE OPERATOR'S FLEET-WIDE RENEWAL ORDER (2026-08-22, measured).
//
// edgeRenewBefore is ONE value on the node. The route is named "fleet" and says so in its own answer. It was
// gated on admin.endpoints.write, which every tenant administrator holds — measured with tenant_northwind's
// own administrator, roles ["admin"]: the operator placed the order, that customer cancelled it, HTTP 200.
func TestTheFleetRenewalOrderBelongsToWhoeverOperatesTheDeployment(t *testing.T) {
	raw, err := os.ReadFile("admin_device_certificate_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	src := string(raw)
	route := regexp.MustCompile(`mux\.HandleFunc\("(POST|DELETE) (/admin/device-certificates/renew-all)"`)
	found := 0
	for _, m := range route.FindAllStringSubmatchIndex(src, -1) {
		found++
		end := strings.Index(src[m[1]:], "mux.HandleFunc(")
		body := src[m[0]:]
		if end > 0 {
			body = src[m[0] : m[1]+end]
		}
		if !strings.Contains(body, "adminOperatorOnlyOrganizationAct(") {
			t.Errorf("%s %s does not ask whether the caller operates this deployment — a customer "+
				"administrator can place or cancel a renewal order for every device in every organization",
				src[m[2]:m[3]], src[m[4]:m[5]])
		}
	}
	// ★ NOTHING FOUND IS NOT A PASS. Both verbs were open on 2026-08-22; a regex that stops matching would
	// report a clean sweep of nothing at all.
	if found != 2 {
		t.Fatalf("matched %d renew-all routes, expected both verbs — this gate is looking for the wrong thing", found)
	}

	// ★ AND THE PERMISSION IS NOT MOVED. admin.endpoints.write also covers a customer's own device
	// administration; folding it into the deployment-wide set would take enable/disable/groups away from every
	// tenant administrator to close this one hole — the mistake the role table warns about by name, and the
	// one that caused two of tonight's other findings.
	if _, moved := adminDeploymentWidePermissions["admin.endpoints.write"]; moved {
		t.Fatal("admin.endpoints.write was made deployment-wide, which takes a customer's own device " +
			"administration away from them")
	}
}

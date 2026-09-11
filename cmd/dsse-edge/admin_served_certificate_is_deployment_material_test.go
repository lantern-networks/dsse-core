package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★★★ THE CERTIFICATE THIS NODE SERVES IS THE DEPLOYMENT'S, AND EVERY CUSTOMER COULD REPLACE IT
// (2026-08-17, measured with tenant_northwind's own administrator — a principal holding no cross-tenant
// permission anywhere).
//
//	PUT /admin/certs/edge  ->  400 "no certificate found"
//
// A 400 from the body validator means the permission check PASSED. The route replaces the certificate this
// Edge presents to every device of every organization; POST /admin/certs/{name}/rollback does the same with
// no body to get wrong, and POST/DELETE /admin/pki/operations stage a transport trust rotation. All four were
// gated on admin.certs.write, which the per-tenant `admin` role held.
//
// It is the hole admin.platform.write was created to close in August — a customer account reaching the
// trust-anchor and device-client-CA routes and rotating the interception intermediate — with this scope left
// behind in that sweep. The operator did not hold it either: super_admin has no admin.certs.write, so the
// party whose material this is could not replace it while every customer could.
//
// The test is written against the ROUTES rather than the scope name, so a new deployment-level certificate
// route gated the old way fails here rather than shipping.
func TestReplacingTheServedCertificateIsAnOperatorAct(t *testing.T) {
	// 1. The role table: a customer administrator must not hold it, the operator must.
	if adminPermissionsByRole["admin"]["admin.certs.write"] {
		t.Fatal("the per-tenant admin role holds admin.certs.write again — every customer administrator can " +
			"replace the certificate this node serves to every other organization's devices")
	}
	if !adminPermissionsByRole["super_admin"]["admin.certs.write"] {
		t.Fatal("super_admin lost admin.certs.write — the party whose material this is cannot replace it")
	}
	// A customer must keep the READ: they have to be able to see the PKI that intercepts them.
	if !adminPermissionsByRole["admin"]["admin.certs.read"] {
		t.Fatal("a customer can no longer read the PKI — that is scoping turned into blinding")
	}

	// 2. And the permission check agrees, which is what the middleware actually calls.
	if adminPermissionAllowed([]string{"admin"}, "admin.certs.write") {
		t.Fatal("adminPermissionAllowed still lets the admin role write certificates")
	}
	if !adminPermissionAllowed([]string{"super_admin"}, "admin.certs.write") {
		t.Fatal("adminPermissionAllowed refuses the operator")
	}
	// owner keeps everything by construction; if that stops being true this test is asking the wrong question.
	if !adminPermissionAllowed([]string{"owner"}, "admin.certs.write") {
		t.Fatal("owner no longer holds the wildcard, so this test's premise is wrong")
	}

	// 3. Every route that requires it is deployment material. Listed here so a NEW route gated on
	//    admin.certs.write has to be looked at: if it is a tenant's own certificate, it needs a tenant scope,
	//    and if it is the deployment's it belongs in this list.
	deployment := map[string]bool{
		"PUT /admin/certs/{name}":           true,
		"POST /admin/certs/{name}/rollback": true,
		"POST /admin/pki/operations":        true,
		"DELETE /admin/pki/operations":      true,
	}
	pattern := regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH) (/admin/[a-zA-Z0-9/_{}.-]+)", adminEndpoint\("admin\.certs\.write"`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(".", e.Name()))
		if rerr != nil {
			continue
		}
		for _, m := range pattern.FindAllStringSubmatch(string(src), -1) {
			found = append(found, m[1]+" "+m[2])
		}
	}
	sort.Strings(found)
	if len(found) == 0 {
		t.Fatal("no admin.certs.write routes were found — the pattern stopped matching, so this check asserts nothing")
	}
	for _, route := range found {
		if !deployment[route] {
			t.Fatalf("%s requires admin.certs.write, which is now an operator scope. If that route is a "+
				"TENANT's own certificate it must not use this scope; if it is the deployment's, add it to the "+
				"list in this test so the next reader knows it was considered.", route)
		}
	}
}

// ★★ THE SAME QUESTION FOR THE REST OF THE DEPLOYMENT'S CONTROLS (2026-08-17). Found by asking, of every
// write route a customer can reach, whether its handler mentions a tenant at all. Five did not; three were
// real:
//
//	PUT  /admin/dns-policy         the NODE's resolver policy — deny, sinkhole, stub. A customer could
//	                               sinkhole a domain for every organization on the Edge.
//	POST /admin/retention-config   how long this node keeps each log stream. A customer setting audit
//	                               retention to a day drops every organization's history.
//	POST /admin/transport-admission/revoke   covered by its own test — the kill-switch.
//
// The scope moves for DNS because it gates that one route and nothing else. Retention is gated in the handler
// instead, because admin.retention.write also carries POST /admin/legal-hold, which IS a customer's own act
// on their own organization: closing an operator hole by removing a customer's right is not a fix.
func TestTheNodesOwnControlsAreNotEveryCustomers(t *testing.T) {
	if adminPermissionsByRole["admin"]["admin.dns.write"] {
		t.Fatal("the per-tenant admin role holds admin.dns.write again — a customer can set the resolver " +
			"policy (deny/sinkhole/stub) for every organization on this node")
	}
	if !adminPermissionsByRole["super_admin"]["admin.dns.write"] {
		t.Fatal("super_admin lost admin.dns.write — nobody can set the node's DNS policy")
	}
	if !adminPermissionsByRole["admin"]["admin.dns.read"] {
		t.Fatal("a customer can no longer read the DNS policy that applies to them")
	}
	// Retention keeps its scope on BOTH sides, because legal hold shares it and is the customer's own.
	if !adminPermissionsByRole["admin"]["admin.retention.write"] {
		t.Fatal("a customer lost admin.retention.write, which is how they place a legal hold on their own " +
			"organization — the deployment-wide half is gated in the handler, not by taking this away")
	}
}

// ★★ AND THE ONES THAT KEEP THEIR SCOPE ARE GATED IN THE HANDLER (2026-08-18). Two more node-wide acts sit
// under permissions a customer legitimately holds, so the scope cannot move without taking away something
// that IS theirs:
//
//	POST /admin/predefined-catalog/feed            admin.policy.write — the same scope carries the per-tenant
//	POST /admin/predefined-catalog/feed/rollback   overrides beside them, which are a customer's own choice.
//	POST /admin/retention-config                   admin.retention.write — shared with POST /admin/legal-hold.
//
// Applying a feed is signature-verified and version-monotonic. ROLLBACK has neither: it names a version
// already in the history and installs it, so a customer could put the whole deployment back onto an older
// bypass set — the document that decides what is NOT decrypted, for every organization on the node.
//
// The assertion is on the SOURCE, because the gate is a line in a handler rather than a permission: a route
// listed here must ask adminAnswerScope before it acts.
func TestNodeWideActsUnderTenantScopesAskWhoIsAsking(t *testing.T) {
	gated := map[string]string{
		"admin_predefined_catalog_routes.go": "POST /admin/predefined-catalog/feed and /feed/rollback",
		"admin_logs_retention_routes.go":     "POST /admin/retention-config",
	}
	for file, what := range gated {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		body := string(src)
		if !strings.Contains(body, "adminAnswerScope(r)") {
			t.Fatalf("%s no longer asks adminAnswerScope — %s is a deployment-wide act reachable with a "+
				"permission every tenant administrator holds", file, what)
		}
		// The refusal has to be a refusal, not a log line.
		if !strings.Contains(body, "http.StatusForbidden") {
			t.Fatalf("%s asks the question and does not refuse on the answer (%s)", file, what)
		}
	}

	// Positive control: a file with no such gate must be seen as ungated, or the search proves nothing.
	if strings.Contains("package main\n", "adminAnswerScope(r)") {
		t.Fatal("the control string was found in text that does not contain it")
	}
}

// ★★ THE ANSWER TOLD A CUSTOMER THEY COULD DO WHAT IT WOULD THEN REFUSE (2026-08-18, measured as
// Northwind's administrator: GET /admin/pki/certificates carried "retire", and DELETE
// /admin/device-client-cas answers 403 for that same session).
//
// The capabilities list was built from facts about the CERTIFICATE — is it retirable, is a signer rotatable —
// and never from the caller, so the console drew four buttons that could only fail. Telling somebody they may
// act and then refusing is worse than not offering: on this screen a customer cannot tell it from a fault in
// their own account.
//
// renew_all is also operator-only: the renewal cutoff affects the node's fleet,
// despite using the ordinary admin.endpoints.write permission.
func TestTheCertificateInventoryOnlyOffersWhatThisCallerMayDo(t *testing.T) {
	items := []pkiCertificateItem{
		{ID: "edge", Capabilities: []string{"replace", "history", "download"}},
		{ID: "device_client_ca:aa", Capabilities: []string{"download", "retire"}},
		{ID: "interception_intermediate", Capabilities: []string{"rotate_signer"}},
		{ID: "transport_anchor", Capabilities: []string{"download", "acknowledge"}},
		{ID: "interception_root", Capabilities: []string{"download", "renew_all"}},
	}
	got := pkiCapabilitiesForCaller(items)
	if len(got) != len(items) {
		t.Fatalf("the scoping dropped ITEMS, not capabilities: %d of %d", len(got), len(items))
	}
	refused := map[string]bool{"replace": true, "retire": true, "rotate_signer": true, "acknowledge": true, "renew_all": true}
	for _, item := range got {
		for _, c := range item.Capabilities {
			if refused[c] {
				t.Fatalf("%s still offers %q, which answers 403 for a customer", item.ID, c)
			}
		}
	}
	// Read-only capabilities remain available.
	kept := map[string]bool{}
	for _, item := range got {
		for _, c := range item.Capabilities {
			kept[c] = true
		}
	}
	for _, c := range []string{"history", "download"} {
		if !kept[c] {
			t.Fatalf("%q was removed — a customer must still read their PKI", c)
		}
	}
	// An item with nothing left keeps an empty list rather than a nil the screen would have to guess about.
	if got[2].Capabilities == nil {
		t.Fatal("an item whose only capability was removed must carry an empty list, not nil")
	}
}

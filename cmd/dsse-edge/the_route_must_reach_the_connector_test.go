package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ THE ROUTE AN ADMINISTRATOR AUTHORED HAS TO REACH THE CONNECTOR'S OWN ALLOWLIST (2026-09-01, measured on
// a customer's connector in its own VPC).
//
// A connector declares no routes: it is not an authority on what it may reach, and its SSRF guard starts empty
// and fail-closed. The Edge fills it through GET /connectors/{id}/effective-routes. That handler looked the
// connector's registrations up under the bundle THIS EDGE pulled — the operator's, on any deployment with
// customers — so the answer was {} and the guard stayed empty.
//
// The two halves then disagreed in the worst way. The Edge chose the connector:
//
//	connector_route_chosen host="10.60.1.176" connector="conn-c8e4d27798e1" connector_region="osaka"
//
// and the connector refused to dial, because as far as it had been told it may reach nothing. Both components
// behaved correctly and the flow died between them; no log on either side says the route never arrived.
//
// This test reads the handler's source, because the defect is not in a function — it is in which value one
// line hands to the lookup, and every unit test of the pieces passed.
func TestTheEffectiveRoutesAnswerIsScopedToTheConnectorsOrganization(t *testing.T) {
	src := readEdgeSource(t, "main.go")
	i := strings.Index(src, `mux.HandleFunc("GET /connectors/{connector_id}/effective-routes"`)
	if i < 0 {
		t.Fatal("the effective-routes handler moved or was renamed; update this guard deliberately")
	}
	body := src[i:]
	if j := strings.Index(body, "mux.HandleFunc(\"GET /connectors/{connector_id}/tunnel\""); j > 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "registry.Get(cid)") {
		t.Error("the handler does not read the connector's own registration for its organization — on a " +
			"deployment that serves customers it will answer {} and the connector's guard stays deny-all")
	}
	// ★ AND THE FALLBACK IS STILL THERE. A single-tenant deployment, where the node's organization and the
	// connector's are the same, must keep working — the fix is which value is PREFERRED, not removing one.
	if !strings.Contains(body, "tenant := evaluator.PolicyBundle.TenantID") {
		t.Error("the node's own organization is no longer the fallback; a connector this node has never seen " +
			"would then be scoped to nothing at all")
	}
}

// readEdgeSource reads one of this package's own files. Reading the source is the honest tool here: the value
// that was wrong is chosen on one line inside an HTTP handler, and standing the whole Edge up in a unit test
// to observe it would test the harness.
func readEdgeSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

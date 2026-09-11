package main

import (
	"strings"
	"testing"
)

// ★★★ THE FIELD DECIDES WHETHER A FLOW CROSSES A REGION, AND IT ARRIVED FROM THE CLIENT (2026-08-25).
//
// A connector enrolled the supported way — one-time token, --state-dir, no coordinate flags — registered with
// edge_region_id "local", the connector binary's own default. The mesh decision is made on exactly this
// field, so an Edge in region-b asked "is this connector in my region?", compared "local" against "region-b",
// and treated a connector sitting beside it as remote. Measured on the deployment's own connector record:
//
//	"edge_region_id": "local"
//
// This is a source check, not a behaviour test: the handler is inside main() and cannot be called from here,
// so what is pinned is that the assignment exists and is FROM the Edge — the same shape as the tests that
// guard "the tenant comes from the CA, not from the body".
func TestAConnectorsRegionComesFromTheEdgeAndNotTheRequest(t *testing.T) {
	body := readSourceFile(t, "main.go")
	const stamp = "req.EdgeRegionID = strings.TrimSpace(evaluator.EdgeRegionID)"
	if !strings.Contains(body, stamp) {
		t.Fatalf("the connector registration no longer stamps the region from the Edge (%q is gone), so a "+
			"connector can claim any region it likes and the mesh routes on what it claimed", stamp)
	}
	// And it has to happen BEFORE the registry stores it, or the stored value is still the claimed one.
	stampAt := strings.Index(body, stamp)
	registerAt := strings.Index(body, "conn, err := registry.Register(req, time.Now())")
	if registerAt < 0 {
		t.Fatal("the connector registration call is gone — this check now proves nothing")
	}
	if stampAt > registerAt {
		t.Fatal("the region is stamped AFTER the registration is stored, so the stored value is the one the " +
			"connector claimed")
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ THE MATERIAL IS ASKED FOR AT THE REGION LEADERSHIP IS IN, NOT AT THIS MACHINE'S OWN DOOR (2026-09-01,
// measured on a three-region deployment with a control experiment that changed nothing but the SNI).
//
// -audit-ingest-url names the local control-plane door, which forwards to the other regions in TCP
// passthrough — it must, because the request carries a client certificate. So the name that arrives at the far
// region is "dsse-control-plane", which no region doorway serves, and the flow lands on the Edge fleet there:
//
//	remote error: tls: unknown certificate authority
//
// Two of three regions never assembled their customers' organizations and signed every flow under the
// deployment's one shared root instead. Walked through FetchOnce rather than the helper: the endpoint was
// already correct in a field, and wrong at the moment of use.
func TestMaterialIsFetchedFromTheRegionLeadershipIsIn(t *testing.T) {
	asked := make(chan string, 4)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"unchanged":true,"generation":7}`))
	}))
	defer authority.Close()

	// The configured door is this machine's own, and it is NOT where the answer is: pointing it at a closed
	// port is the honest shape, because across a region boundary it does not arrive.
	f := newTenantTransportMaterialFetcher("https://dsse-control-plane:8443/audit-ingest", "tok", nil,
		func() []string { return nil })
	if f == nil {
		t.Fatal("no fetcher")
	}
	f.dataURL = func() string { return authority.URL }

	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("FetchOnce: %v — it did not reach the region leadership is in", err)
	}
	select {
	case path := <-asked:
		if path != "/tenant-edge-material" {
			t.Errorf("asked for %q", path)
		}
	default:
		t.Fatal("the authority for the current region was never asked")
	}

	// ★ AND A SINGLE-REGION DEPLOYMENT KEEPS ITS DOOR. With no per-region list there is nothing to follow, and
	// the configured address is the right one — this must not become a requirement to be multi-region.
	f.dataURL = func() string { return "" }
	if got := f.currentEndpoint(); !strings.HasPrefix(got, "https://dsse-control-plane:8443/") {
		t.Errorf("with no region list the endpoint became %q, want the configured door", got)
	}
}

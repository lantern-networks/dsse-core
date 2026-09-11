package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

func TestParseCPEndpoints(t *testing.T) {
	got := parseCPEndpoints(" region-a=https://cpA:9443 ; region-b=https://cpB:9443 ;; bad ; =x ")
	if len(got) != 2 || got[0].Region != "region-a" || got[0].Endpoint != "https://cpA:9443" || got[1].Region != "region-b" {
		t.Fatalf("parseCPEndpoints = %#v", got)
	}
}

// TestCPEndpointSelectorPicksLeaderAndFailsOver: the Edge selects the CP region whose /leader==200, and fails over
// when that region stops being leader (mirrors the client→Edge selector, pointed at CPs).
func TestCPEndpointSelectorPicksLeaderAndFailsOver(t *testing.T) {
	var aLeader, bLeader atomic.Bool
	leaderHandler := func(is *atomic.Bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if is.Load() {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}
	}
	muxA := http.NewServeMux()
	muxA.HandleFunc("/leader", leaderHandler(&aLeader))
	muxB := http.NewServeMux()
	muxB.HandleFunc("/leader", leaderHandler(&bLeader))
	srvA := httptest.NewServer(muxA)
	defer srvA.Close()
	srvB := httptest.NewServer(muxB)
	defer srvB.Close()

	sel := newCPEndpointSelector(
		[]regionfailover.RegionEndpoint{{Region: "region-a", Endpoint: srvA.URL}, {Region: "region-b", Endpoint: srvB.URL}},
		"region-a", srvA.Client(), 0, 1, // 1 strike = fail over immediately for a deterministic test
	)
	if sel == nil {
		t.Fatal("selector should be built for 2 endpoints")
	}

	// region-a is the leader → selected.
	aLeader.Store(true)
	sel.evaluate()
	if sel.CurrentBaseURL() != srvA.URL {
		t.Fatalf("expected region-a (%s), got %q", srvA.URL, sel.CurrentBaseURL())
	}

	// region-a loses leadership, region-b becomes leader → the Edge fails its control channel over to region-b.
	aLeader.Store(false)
	bLeader.Store(true)
	sel.evaluate()
	if sel.CurrentBaseURL() != srvB.URL {
		t.Fatalf("expected failover to region-b (%s), got %q", srvB.URL, sel.CurrentBaseURL())
	}

	// No region is leader → "" (control channel keeps last config; never crosses the boundary).
	bLeader.Store(false)
	sel.evaluate()
	if sel.CurrentBaseURL() != "" {
		t.Fatalf("expected no CP (fail-closed control channel), got %q", sel.CurrentBaseURL())
	}
}

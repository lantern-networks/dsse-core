package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeshCanceledOriginStillDeliversWithOriginalTerm(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "current"
		if stale {
			name = "old-term"
		}
		t.Run(name, func(t *testing.T) {
			p := &meshSharedTestPersister{}
			o, err := newRevocationMeshOutbox(p)
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer peer.Close()
			e := &cpLeaderElector{}
			e.isLeader.Store(true)
			e.leaderSince.Store(10)
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), cpWriteLeaseKey{}, cpWriteLease{elector: e, epoch: 10}))
			cancel()
			if stale {
				e.leaderSince.Store(11)
			}
			s := revocationMeshSource{outbox: o, client: peer.Client(), secret: "synthetic", originRegion: "origin"}
			s.deliverToPeerContext(ctx, revocationMeshPeer{region: "peer", url: peer.URL}, revocationMeshItem{Identity: "target", Reason: "block", OriginRegion: "origin"})
			if stale {
				if len(o.snapshot()) != 0 || len(meshOutboxLoaded(t, p)) != 0 {
					t.Fatal("old term retained a delivery")
				}
				// The synchronous enqueue must reject this term. The worker also
				// checks the retained lease; current-term delivery is tested below.
				return
			}
			waitUntil(t, 2*time.Second, func() bool { return requests.Load() == 1 && len(o.snapshot()) == 0 }, "canceled origin delivery and ACK")
			if len(meshOutboxLoaded(t, p)) != 0 {
				t.Fatal("ACK not saved")
			}
		})
	}
}

func TestRouteCompleteWireRequiresAllDecisionMaps(t *testing.T) {
	keys := []string{"held", "approved", "seen", "authored"}
	for _, missing := range keys {
		t.Run(missing, func(t *testing.T) {
			receiver := newConnectorRouteGovernance()
			if err := receiver.AddAuthored("a", "site", authoredRoute{FQDN: "keep.test"}); err != nil {
				t.Fatal(err)
			}
			wire := map[string]any{"complete": true, "held": nil, "approved": nil, "seen": nil, "authored": nil}
			delete(wire, missing)
			section, _ := json.Marshal(wire)
			var bundle configBundlePayload
			err := json.Unmarshal(append(append([]byte(`{"route_governance":`), section...), '}'), &bundle)
			if err == nil {
				err = receiver.ImportReceived(context.Background(), bundle.RouteGovernance)
			}
			if err == nil || receiver.CountForTenant("a") != 1 {
				t.Fatal("incomplete snapshot erased bindings", err)
			}
		})
	}
	// Explicit empty snapshots remain a valid deletion, including nil maps emitted
	// by older exporters. Legacy partial snapshots retain their merge behavior.
	for _, wire := range []string{`{"complete":true,"held":null,"approved":null,"seen":null,"authored":null}`, `{"complete":true,"held":{},"approved":{},"seen":{},"authored":{}}`, `{"held":{}}`} {
		var st governancePersistState
		if err := json.Unmarshal([]byte(wire), &st); err != nil {
			t.Fatal("compatible snapshot rejected", err)
		}
	}
}

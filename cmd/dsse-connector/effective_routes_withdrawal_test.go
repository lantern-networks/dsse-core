package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestAuthoritativeEmptyEffectiveRoutesWithdrawsPriorRoutes(t *testing.T) {
	dispatcher := newConnectorTunnelTCPDispatcher(nil, nil, nil)
	dispatcher.SetReachableRoutes(model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}})
	answered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connectors/conn-1/effective-routes" {
			t.Errorf("unexpected effective-routes path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{ "cidrs": [], "fqdn_domains": [] }`)
		answered <- struct{}{}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pollEffectiveRoutes(ctx, server.URL, "conn-1", "", nil, dispatcher)
	}()
	select {
	case <-answered:
	case <-time.After(2 * time.Second):
		t.Fatal("effective-routes GET did not complete")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := dispatcher.reachableRoutes(); len(got.CIDRs) == 0 && len(got.FQDNDomains) == 0 {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("valid empty effective-routes response retained previously authorized destination")
}

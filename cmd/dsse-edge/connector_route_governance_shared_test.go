package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"
)

func TestRouteGovernanceSharedPreservesPeer(t *testing.T) {
	p := &transactionalCAFixture{}
	a := newConnectorRouteGovernanceWithPersister("", true, p)
	b := newConnectorRouteGovernanceWithPersister("", true, p)
	if err := a.AddAuthored("a", "site", authoredRoute{NetworkID: "network-a"}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAuthored("b", "site", authoredRoute{FQDN: "b.example.test"}); err != nil {
		t.Fatal(err)
	}
	fresh := newConnectorRouteGovernanceWithPersister("", true, p)
	if len(fresh.Routes("a", "site", nil, nil)) != 1 || len(fresh.Routes("b", "site", nil, nil)) != 1 {
		t.Fatal("stale binding writer erased peer routes")
	}
}

func TestRouteGovernanceSharedFailureErasureAndDiscovery(t *testing.T) {
	p := &transactionalCAFixture{}
	a := newConnectorRouteGovernanceWithPersister("", true, p)
	b := newConnectorRouteGovernanceWithPersister("", true, p)
	if err := a.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAuthored("b", "site", authoredRoute{FQDN: "b.test"}); err != nil {
		t.Fatal(err)
	}
	if n, err := a.RemoveTenantChecked("a"); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	beforeDiscoveryGen := b.ConfigGeneration()
	if err := b.SeeRoutesContext(context.Background(), "b", "connector", []string{"10.0.0.0/24"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if b.ConfigGeneration() <= beforeDiscoveryGen {
		t.Fatal("discovery adopted peer deletion without advancing bundle generation")
	}
	if err := b.RefreshShared(); err != nil || b.CountForTenant("a") != 0 {
		t.Fatal("discovery resurrected erased peer", err)
	}
	before, _ := p.Load()
	live, _ := json.Marshal(b.Export())
	gen := b.ConfigGeneration()
	p.failCommit = true
	if err := b.RemoveAuthored("b", "site", "fqdn:b.test"); err == nil {
		t.Fatal("uncommitted remove accepted")
	}
	if err := b.SeeRoutesContext(context.Background(), "c", "new", nil, time.Now()); err == nil {
		t.Fatal("uncommitted discovery accepted")
	}
	if n, err := b.RemoveTenantChecked("b"); err == nil || n != 0 {
		t.Fatal("uncommitted erasure accepted")
	}
	after, _ := p.Load()
	got, _ := json.Marshal(b.Export())
	if !bytes.Equal(before, after) || !bytes.Equal(live, got) || b.ConfigGeneration() != gen {
		t.Fatal("failed commit changed state")
	}
	p.failCommit = false
	if err := b.RemoveAuthored("b", "site", "fqdn:b.test"); err != nil {
		t.Fatal(err)
	}
	if err := b.ImportReceived(context.Background(), a.ExportForBundle()); err == nil {
		t.Fatal("shared authority accepted received snapshot")
	}
	for _, bad := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(`{"authored":{}}`), []byte(`broken`)} {
		p.Save(bad)
		if err := b.RefreshShared(); err == nil {
			t.Fatalf("read accepted %q", bad)
		}
		if err := b.AddAuthored("z", "site", authoredRoute{FQDN: "z.test"}); err == nil {
			t.Fatalf("write accepted %q", bad)
		}
		after, _ := p.Load()
		if !bytes.Equal(after, bad) {
			t.Fatal("corrupt state overwritten")
		}
	}
}

func TestRouteGovernanceCompleteDeletionAndRetry(t *testing.T) {
	authority := newConnectorRouteGovernance()
	if err := authority.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	p := &refusingGovernancePersister{Persister: &transactionalCAFixture{}}
	receiver := newConnectorRouteGovernanceWithPersister("", true, p)
	prior := connectorRouteGov
	connectorRouteGov = receiver
	defer func() { connectorRouteGov = prior }()
	source := configBundleSource{tenantID: "a"}
	targets := configApplyTargets{policyStore: policy.NewStore(nil)}
	if _, err := source.apply(configBundlePayload{RouteGovernance: authority.ExportForBundle()}, targets); err != nil {
		t.Fatal(err)
	}
	if receiver.CountForTenant("a") != 1 {
		t.Fatal("received binding absent")
	}
	if _, err := authority.RemoveTenantChecked("a"); err != nil {
		t.Fatal(err)
	}
	empty := authority.ExportForBundle()
	if empty == nil || !empty.Complete {
		t.Fatal("last deletion omitted from bundle")
	}
	p.fail = true
	if _, err := source.apply(configBundlePayload{RouteGovernance: empty}, targets); err == nil {
		t.Fatal("failed deletion cache acknowledged")
	}
	if receiver.CountForTenant("a") != 1 {
		t.Fatal("failed commit changed receiver")
	}
	p.fail = false
	if _, err := source.apply(configBundlePayload{RouteGovernance: empty}, targets); err != nil {
		t.Fatal(err)
	}
	if receiver.CountForTenant("a") != 0 {
		t.Fatal("last deletion did not propagate")
	}
}

func TestPostgresRouteGovernanceRequestTerm(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	blob := d.store.(postgresBlobPersister)
	blob.key = "connector_route_governance"
	g := newConnectorRouteGovernanceWithPersister("", true, blob)
	peer := newConnectorRouteGovernanceWithPersister("", true, blob)
	if err := g.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	if err := peer.AddAuthored("b", "site", authoredRoute{NetworkID: "b-net"}); err != nil {
		t.Fatal(err)
	}
	if err := g.RefreshShared(); err != nil || g.CountForTenant("b") != 1 {
		t.Fatal("peer not refreshed", err)
	}
	old := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	before, _ := blob.Load()
	for _, edit := range []func() error{
		func() error { return g.AddAuthoredContext(old, "c", "site", authoredRoute{FQDN: "c.test"}) },
		func() error { return g.RemoveAuthoredContext(old, "a", "site", "fqdn:a.test") },
		func() error { _, err := g.RemoveTenantContext(old, "a"); return err },
		func() error { return g.SeeRoutesContext(old, "a", "c", nil, time.Now()) },
	} {
		if err := edit(); err == nil {
			t.Fatal("old leader request changed routes")
		}
	}
	after, _ := blob.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("old term changed row")
	}
	// Execute both management handlers with a term change during body reading.
	previous := connectorRouteGov
	connectorRouteGov = g
	defer func() { connectorRouteGov = previous }()
	mux := http.NewServeMux()
	registerConnectorSiteAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, serverConfig{}, testEvaluator(), nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, nil)
	for _, path := range []string{"/admin/sites/site/networks", "/admin/connectors/connector/routes"} {
		req := httptest.NewRequest("POST", path, nil)
		req.Body = &enrolmentTermBody{Reader: strings.NewReader(`{"action":"add","fqdn":"old.test"}`), before: func() { a.release(); b.tick(); b.release(); a.tick() }}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 500 {
			t.Fatalf("old request accepted by %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if n, err := g.RemoveTenantChecked("a"); err != nil || n != 1 {
		t.Fatal("current retry failed", n, err)
	}
	fresh := newConnectorRouteGovernanceWithPersister("", true, blob)
	if fresh.CountForTenant("a") != 0 || fresh.CountForTenant("b") != 1 {
		t.Fatal("reloaded peer/erasure mismatch")
	}
}

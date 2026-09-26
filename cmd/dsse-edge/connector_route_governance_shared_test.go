package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"
)

func TestRouteGovernanceSharedPreservesPeer(t *testing.T) {
	p := &routeTransactionFixture{}
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
	p := &routeTransactionFixture{}
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
	p := &routeRejectingFixture{Persister: &routeTransactionFixture{}}
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

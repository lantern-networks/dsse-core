package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policy"
	"sync"
	"testing"
)

type routeTransactionFixture struct {
	mu         sync.Mutex
	raw        []byte
	failCommit bool
}

func (p *routeTransactionFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.raw), nil
}
func (p *routeTransactionFixture) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = bytes.Clone(b)
	return nil
}
func (p *routeTransactionFixture) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := edit(bytes.Clone(p.raw))
	if err != nil {
		return err
	}
	if p.failCommit {
		return fmt.Errorf("commit rejected")
	}
	p.raw = bytes.Clone(next)
	return nil
}

type routeRejectingFixture struct {
	blobstore.Persister
	fail bool
}

func (p *routeRejectingFixture) Save(b []byte) error {
	if p.fail {
		return fmt.Errorf("test save unavailable")
	}
	return p.Persister.Save(b)
}
func TestRouteDistributionPeerWrites(t *testing.T) {
	p := &routeTransactionFixture{}
	a := newConnectorRouteGovernanceWithPersister("", true, p)
	b := newConnectorRouteGovernanceWithPersister("", true, p)
	if err := a.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAuthored("b", "site", authoredRoute{FQDN: "b.test"}); err != nil {
		t.Fatal(err)
	}
	fresh := newConnectorRouteGovernanceWithPersister("", true, p)
	if fresh.CountForTenant("a") != 1 || fresh.CountForTenant("b") != 1 {
		t.Fatal("peer write lost an existing route")
	}
}
func TestRouteDistributionReceiverSaveFailure(t *testing.T) {
	a := newConnectorRouteGovernance()
	if err := a.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	p := &routeRejectingFixture{Persister: &routeTransactionFixture{}, fail: true}
	receiver := newConnectorRouteGovernanceWithPersister("", true, p)
	prior := connectorRouteGov
	connectorRouteGov = receiver
	defer func() { connectorRouteGov = prior }()
	source := configBundleSource{tenantID: "a"}
	if _, err := source.apply(configBundlePayload{RouteGovernance: a.Export()}, configApplyTargets{policyStore: policy.NewStore(nil)}); err == nil {
		t.Fatal("receiver acknowledged failed persistence")
	}
	if receiver.CountForTenant("a") != 0 {
		t.Fatal("failed persistence published live route")
	}
}
func TestRouteDistributionErasureGeneration(t *testing.T) {
	a := newConnectorRouteGovernance()
	if err := a.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	before := a.ConfigGeneration()
	a.RemoveTenant("a")
	if a.ConfigGeneration() <= before {
		t.Fatal("erasure did not advance bundle generation")
	}
}

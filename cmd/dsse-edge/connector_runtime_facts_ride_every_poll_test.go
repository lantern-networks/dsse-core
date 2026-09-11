package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ MEASURED 0 OF 10. A connector failed over from region-b to region-a; the deployment's database knew and
// so did the node holding its tunnel, but the two Edges of the region it LEFT went on answering "no live
// tunnel" — because they only apply a bundle whose generation advanced, and this fact is kept out of the
// generation ON PURPOSE so a flapping connector cannot move the deployment's version.
func TestWhereAConnectorIsAttachedArrivesWithoutMovingTheVersion(t *testing.T) {
	registry := connector.NewRegistry()
	seed := model.ConnectorRegistration{
		ID: "conn-1", TenantID: "t1", Status: "registered", EdgeRegionID: "region-b",
		PrivateBaseURL: "https://internal.invalid",
	}
	if _, err := registry.Register(seed, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	targets := configApplyTargets{connectors: registry}
	before := registry.ConfigGeneration()

	moved := seed
	moved.AttachedRegionID = "region-a"
	applyConnectorRuntimeFacts(configBundlePayload{
		Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{moved}},
	}, targets)

	got, _ := registry.Get("conn-1")
	if got.AttachedRegionID != "region-a" {
		t.Fatalf("the fact did not arrive: %q", got.AttachedRegionID)
	}
	if after := registry.ConfigGeneration(); after != before {
		t.Fatalf("a runtime fact moved the version: %d -> %d", before, after)
	}
}

// ★ SILENCE IS NOT A REPORT, and arriving is not a runtime fact. An authority that has never been told sends
// an empty field — clearing on that would erase what this node knows on every poll — and a connector this
// node's catalog does not have must wait for a bundle whose version says it exists.
func TestARuntimeFactNeitherErasesNorCreates(t *testing.T) {
	registry := connector.NewRegistry()
	seed := model.ConnectorRegistration{
		ID: "conn-1", TenantID: "t1", Status: "registered", EdgeRegionID: "region-b",
		PrivateBaseURL: "https://internal.invalid",
	}
	if _, err := registry.Register(seed, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := registry.RecordAttachedRegion("conn-1", "region-a"); err != nil {
		t.Fatalf("record: %v", err)
	}
	targets := configApplyTargets{connectors: registry}

	// An empty field must not clear it.
	applyConnectorRuntimeFacts(configBundlePayload{
		Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{seed}},
	}, targets)
	if got, _ := registry.Get("conn-1"); got.AttachedRegionID != "region-a" {
		t.Fatalf("an empty field erased what this node knew: %q", got.AttachedRegionID)
	}

	// A connector this node does not have must not be created by a poll that carries no version.
	stranger := model.ConnectorRegistration{ID: "conn-new", TenantID: "t1", AttachedRegionID: "region-a"}
	applyConnectorRuntimeFacts(configBundlePayload{
		Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{stranger}},
	}, targets)
	if _, known := registry.Get("conn-new"); known {
		t.Fatal("a connector arriving is a configuration change and belongs to the version, not to this path")
	}

	// No catalog section, and no registry, are both no-ops rather than panics.
	applyConnectorRuntimeFacts(configBundlePayload{}, targets)
	applyConnectorRuntimeFacts(configBundlePayload{
		Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{stranger}},
	}, configApplyTargets{})
}

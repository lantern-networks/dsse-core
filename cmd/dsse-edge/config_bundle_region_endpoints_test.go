package main

import "testing"

// The three conditions a bundle section has to meet before it carries anything, each of which has been
// violated at least once by a section added to this file's neighbours:
//
//	1. the section EXISTS on the wire
//	2. it moves the aggregate GENERATION, or it is published in every bundle and applied by nobody
//	3. "there are none" is SAYABLE, or the last removal never propagates

func TestOnlyTheControlPlanePublishesTheRegionMap(t *testing.T) {
	cat, err := parseRegionEndpoints("region-a=https://a.example;region-b=https://b.example")
	if err != nil {
		t.Fatal(err)
	}
	if section := regionEndpointBundleSection(false, cat); section != nil {
		t.Error("an Edge published a region map section — it is not the authority, and a fleet in which every " +
			"node publishes has no authority at all")
	}
	section := regionEndpointBundleSection(true, cat)
	if section == nil || len(section.Endpoints) != 2 {
		t.Fatalf("the control plane did not publish its map: %+v", section)
	}
}

func TestTheControlPlaneCanSayThereAreNoRegions(t *testing.T) {
	// Condition 3. A control plane with no map still publishes a section — otherwise a deployment that stopped
	// being multi-region could never tell its Edges, and they would keep offering devices a region that is
	// gone. That is the direction that fails at the worst moment: a device already failing over, sent to an
	// address nobody serves.
	section := regionEndpointBundleSection(true, nil)
	if section == nil {
		t.Fatal("a control plane with no region map published nothing, so 'there are none' cannot be said")
	}
	if !section.Complete {
		t.Error("an empty map from a control plane that HAS no map is complete, not unreadable")
	}
}

func TestApplyingTheSectionReplacesTheBootValue(t *testing.T) {
	boot, err := parseRegionEndpoints("region-a=https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	regionMap.Set(boot)
	genBefore := regionMap.ConfigGeneration()

	applied, regions := applyRegionEndpointBundleSection(&regionEndpointBundle{
		Endpoints: []regionEndpoint{
			{Region: "region-a", Endpoint: "https://a.example"},
			{Region: "region-b", Endpoint: "https://b.example"},
		}, Complete: true}, nil)
	if !applied || regions != 2 {
		t.Fatalf("the control plane's map was not applied: applied=%v regions=%d", applied, regions)
	}
	if got := regionMap.Catalog().regionIDs(); len(got) != 2 {
		t.Errorf("this node still serves %v — the boot flag outlived the control plane's answer", got)
	}
	// Condition 2: the generation moved, or no Edge would re-pull after a region was added.
	if regionMap.ConfigGeneration() <= genBefore {
		t.Error("applying a different map did not move the generation")
	}

	// Idempotent: the same map applied twice must not move anything, or every poll looks like a change.
	genAfter := regionMap.ConfigGeneration()
	if applied, _ := applyRegionEndpointBundleSection(&regionEndpointBundle{
		Endpoints: []regionEndpoint{
			{Region: "region-b", Endpoint: "https://b.example"},
			{Region: "region-a", Endpoint: "https://a.example"},
		}, Complete: true}, nil); applied {
		t.Error("the same map in a different order was treated as a change")
	}
	if regionMap.ConfigGeneration() != genAfter {
		t.Error("an unchanged map moved the generation")
	}
}

func TestAnEmptySectionClearsAndAnIncompleteOneDoesNot(t *testing.T) {
	seeded, _ := parseRegionEndpoints("region-a=https://a.example;region-b=https://b.example")
	regionMap.Set(seeded)

	// Incomplete: "I could not look" is never "there are none". This is the guard that stops a control plane
	// which lost its own configuration from turning a multi-region deployment into a set of islands.
	if applied, _ := applyRegionEndpointBundleSection(&regionEndpointBundle{Complete: false}, nil); applied {
		t.Error("an incomplete section was applied")
	}
	if len(regionMap.Catalog().regionIDs()) != 2 {
		t.Error("an incomplete section cleared the map")
	}

	// Complete and empty: CLEARS. The deployment is single-region now, and a map still naming a region it does
	// not have sends devices somewhere nobody is serving.
	applied, regions := applyRegionEndpointBundleSection(&regionEndpointBundle{
		Endpoints: []regionEndpoint{}, Complete: true}, nil)
	if !applied || regions != 0 {
		t.Fatalf("a complete empty section did not clear: applied=%v regions=%d", applied, regions)
	}
	if regionMap.Catalog() != nil {
		t.Error("clearing left an empty catalogue rather than none — a device would be handed an empty list " +
			"it cannot tell from a filtered one, instead of being told geo-steering is not configured")
	}
	regionMap.Set(nil)
}

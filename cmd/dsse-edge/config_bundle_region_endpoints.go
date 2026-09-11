package main

import (
	"strings"
	"sync"
	"sync/atomic"
)

// config_bundle_region_endpoints.go — carrying the class-1 region map from the control plane to the Edges.
//
// ★★★ MEASURED BEFORE IT WAS WRITTEN (2026-08-23). The map that tells a device which regions it may fail over
// to was built from -region-endpoints on each node and from NOTHING ELSE. It was not authored on the control
// plane and it did not travel in this bundle, so "give every Edge the region entry list" — the step the
// install order puts after every region exists — was N command-line edits.
//
// An Edge somebody missed is HEALTHY. Measured on the lab by taking one region out of one Edge's list:
//
//	its /healthz            status ok, role edge, configuration applied
//	the lab posture check   BOTH regions PASS — it asks whether each region's ADDRESS is serving, which is a
//	                        different question
//	its devices             handed a valid map that simply does not contain the other region, so they never
//	                        fail over there
//
// Nothing reported it, and the operator who added the region saw every edit they made succeed. It is
// invariant 3 in the small — an answer an Edge holds that the control plane never gave it — and which map a
// device gets depends on which node the front door picked.
//
// ★ THE FLAG BECOMES THE FLOOR, NOT THE AUTHORITY. An Edge still starts with whatever -region-endpoints says,
// because it must be able to answer before its first successful pull; from that pull onwards the control
// plane's map replaces it. Same shape as -policy and -bundle: the boot set, not the truth.
//
// ★ NOT PER ORGANIZATION. Unlike the Site catalogue beside it, this is deployment topology: the regions a
// deployment HAS. Which of them a given organization may use is a separate, per-tenant question answered from
// the tenant model (allowedRegionEndpoints), and that already travels.

// regionEndpointBundle carries the region map as one replace-all unit.
type regionEndpointBundle struct {
	Endpoints []regionEndpoint `json:"endpoints"`
	// Complete says the publisher means it. A control plane that could not read its own map must not publish a
	// section that LOOKS like "there are no regions" — that is the direction that silently turns a multi-region
	// deployment into a set of islands.
	Complete bool `json:"complete"`
}

// regionEndpointAuthority holds the map this node is currently serving, and counts changes so the bundle's
// aggregate generation moves when the map does.
//
// ★ A SECTION THAT DOES NOT MOVE THE GENERATION IS PUBLISHED IN EVERY BUNDLE AND APPLIED BY NOBODY. That is
// the second of the three conditions a section has to meet, and it has been violated at least once per
// section added here.
type regionEndpointAuthority struct {
	mu         sync.RWMutex
	catalog    *regionEndpointCatalog
	generation atomic.Uint64
}

// regionMap is what this node is serving. Named apart from the -region-endpoints FLAG on purpose: the flag is
// the boot value and this is the live one, and a reader that reaches for the wrong one is the defect this
// file exists to remove.
var regionMap = &regionEndpointAuthority{}

// Set installs a map and moves the generation. Called once at start-up from the flag, and again on every
// applied bundle.
func (a *regionEndpointAuthority) Set(cat *regionEndpointCatalog) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.catalog = cat
	a.mu.Unlock()
	a.generation.Add(1)
}

// Catalog is what this node is serving right now.
func (a *regionEndpointAuthority) Catalog() *regionEndpointCatalog {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.catalog
}

// ConfigGeneration feeds the bundle's aggregate generation.
func (a *regionEndpointAuthority) ConfigGeneration() uint64 {
	if a == nil {
		return 0
	}
	return a.generation.Load()
}

// regionEndpointBundleSection builds the section the control plane publishes, or nil on a node that is not the
// control plane.
//
// ★ THE POINTER IS THE ANSWER TO "IS ANYBODY AUTHORING THIS". An Edge publishes no section — it is not the
// authority — and a nil section changes nothing on whoever reads it. Present means the control plane is
// speaking about the region map, including when it says there are none.
func regionEndpointBundleSection(isControlPlane bool, cat *regionEndpointCatalog) *regionEndpointBundle {
	if !isControlPlane {
		return nil
	}
	section := &regionEndpointBundle{Endpoints: []regionEndpoint{}, Complete: true}
	if cat != nil {
		for _, region := range cat.order {
			section.Endpoints = append(section.Endpoints,
				regionEndpoint{Region: region, Endpoint: cat.byRegion[region]})
		}
	}
	return section
}

// applyRegionEndpointBundleSection makes this Edge's map match the control plane's, and reports what changed.
//
// ★★ PRESENT-BUT-EMPTY CLEARS, and that is the safe direction here — unlike the device-CA registry, where
// empty would refuse every device. An empty region map means no geo-steering is offered: a device stays on the
// Edge it reached instead of being handed somewhere to fail over to. Refusing movement, not refusing service.
//
// The dangerous direction is the opposite one, which is why this section exists: a map that still names a
// region the deployment no longer has sends devices to an address nobody is serving, at the moment they are
// already failing over.
func applyRegionEndpointBundleSection(section *regionEndpointBundle,
	logf func(string, ...interface{})) (applied bool, regions int) {
	if section == nil {
		return false, 0
	}
	if !section.Complete {
		if logf != nil {
			logf("config_bundle_region_endpoints_kept_local reason=%q",
				"the control plane did not report a complete region map")
		}
		return false, 0
	}
	next := &regionEndpointCatalog{byRegion: map[string]string{}}
	for _, ep := range section.Endpoints {
		region := strings.ToLower(strings.TrimSpace(ep.Region))
		endpoint := strings.TrimSpace(ep.Endpoint)
		if region == "" || endpoint == "" {
			continue
		}
		if _, dup := next.byRegion[region]; dup {
			continue
		}
		next.byRegion[region] = endpoint
		next.order = append(next.order, region)
	}
	if len(next.byRegion) == 0 {
		// An empty map is nil rather than an empty catalogue, so /steer/region-endpoints answers "geo-steering
		// is not configured" instead of handing a device an empty list it cannot tell from a filtered one.
		next = nil
	}
	before := regionMap.Catalog()
	if before.digest() == next.digest() {
		return false, len(next.regionIDs())
	}
	regionMap.Set(next)
	if logf != nil {
		logf("config_bundle_region_endpoints_applied regions=%d digest=%s was=%s",
			len(next.regionIDs()), next.digest(), before.digest())
	}
	return true, len(next.regionIDs())
}

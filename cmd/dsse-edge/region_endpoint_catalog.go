package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// region_endpoint_catalog.go implements the SERVER half of client-side geo-steering
// . The agent is handed its tenant's ALLOWED-region
// edge endpoints and picks the nearest healthy one client-side; the residency filtering happens HERE, so an
// out-of-boundary region is never even offered — "landing outside the boundary is structurally impossible."
//
// The per-region front door (intra-region LB / GSLB) is separate; this catalog is the class-1 region map
// every edge shares.

// regionEndpoint is one region's externally-reachable edge endpoint (the per-region front-door URL the agent dials
// after it measures latency/health among the allowed set).
type regionEndpoint struct {
	Region   string `json:"region"`
	Endpoint string `json:"endpoint"`
}

// regionEndpointCatalog maps a region id to its edge endpoint. Built from -region-endpoints (class-1 config).
type regionEndpointCatalog struct {
	byRegion map[string]string // region (lower-cased) -> endpoint URL
	order    []string          // region ids in configured order (stable output)
}

// parseRegionEndpoints parses "region=URL;region=URL". Empty -> nil (geo-steering disabled; single-region).
func parseRegionEndpoints(raw string) (*regionEndpointCatalog, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	cat := &regionEndpointCatalog{byRegion: map[string]string{}}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, endpoint, ok := strings.Cut(entry, "=")
		region = strings.ToLower(strings.TrimSpace(region))
		endpoint = strings.TrimSpace(endpoint)
		if !ok || region == "" || endpoint == "" {
			return nil, fmt.Errorf("region endpoint %q must be region=URL", entry)
		}
		if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "wss://") {
			return nil, fmt.Errorf("region endpoint %q URL must be https:// or wss://", entry)
		}
		if _, dup := cat.byRegion[region]; dup {
			return nil, fmt.Errorf("region %q is configured more than once", region)
		}
		cat.byRegion[region] = endpoint
		cat.order = append(cat.order, region)
	}
	return cat, nil
}

// allowedRegionEndpoints returns the residency-filtered, home-anchored endpoint list a tenant's agent may use
// . Rules:
//   - allowedRegions EMPTY -> unpinned: every catalog region (global nearest, client-side).
//   - allowedRegions NON-EMPTY -> only those regions are emitted; an out-of-boundary region is NEVER offered.
//   - homeRegion, when present AND allowed, is placed FIRST as the anchor/tiebreak; the rest follow in catalog
//     order. The agent measures latency among them and picks nearest-healthy — this list IS its failover set.
func (c *regionEndpointCatalog) allowedRegionEndpoints(allowedRegions []string, homeRegion string) []regionEndpoint {
	if c == nil {
		return nil
	}
	allowedSet := map[string]bool{}
	for _, r := range allowedRegions {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			allowedSet[r] = true
		}
	}
	pinned := len(allowedSet) > 0
	home := strings.ToLower(strings.TrimSpace(homeRegion))

	out := make([]regionEndpoint, 0, len(c.order))
	seen := map[string]bool{}
	add := func(region string) {
		if region == "" || seen[region] {
			return
		}
		ep, ok := c.byRegion[region]
		if !ok {
			return
		}
		if pinned && !allowedSet[region] {
			return // residency boundary beats everything — never emit an out-of-boundary endpoint
		}
		out = append(out, regionEndpoint{Region: region, Endpoint: ep})
		seen[region] = true
	}
	add(home) // anchor first (tiebreak / preferred failover target,)
	for _, region := range c.order {
		add(region)
	}
	return out
}

// regionIDs names the regions this node knows about, in configured order.
//
// ★★★ IT EXISTS SO A FLEET CAN BE CHECKED (2026-08-23, found by walking the multi-region install order). The
// install order says to give every Edge the region entry list once every region exists — and that is done by
// editing each node's command line, because this catalogue is built from a flag and from nothing else. An
// Edge that was missed is healthy, answers every route, and hands its devices a SHORTER list; the devices get
// a valid answer that simply does not contain the new region. Until this, no route said which regions a node
// knew about, so "did the list reach every Edge" could not be asked at all.
func (c *regionEndpointCatalog) regionIDs() []string {
	if c == nil {
		return []string{}
	}
	out := make([]string, 0, len(c.order))
	out = append(out, c.order...)
	return out
}

// digest is a stable fingerprint of the whole map — ids AND endpoints — so two nodes can be compared without
// publishing the endpoints on an unauthenticated route.
//
// ★ ORDER-INDEPENDENT ON PURPOSE. Two Edges given the same regions in a different order are configured the
// same, and reporting them as divergent would be a false alarm of exactly the kind that gets a check ignored.
// A differing URL for a matching id is a real divergence and does move this.
func (c *regionEndpointCatalog) digest() string {
	if c == nil || len(c.byRegion) == 0 {
		return ""
	}
	regions := make([]string, 0, len(c.byRegion))
	for region := range c.byRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	h := sha256.New()
	for _, region := range regions {
		fmt.Fprintf(h, "%s=%s;", region, c.byRegion[region])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

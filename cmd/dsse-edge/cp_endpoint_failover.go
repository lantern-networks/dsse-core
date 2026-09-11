package main

import (
	"context"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/regionfailover"
)

// cp_endpoint_failover: the Edge→CP control channel's region failover. Today the Edge reaches its control plane
// through a SINGLE -config-source-url (config pull + fast revocation pull + audit ship all reuse it); if that CP's
// region dies the Edge is stranded on a dead URL. This gives the Edge the SAME treatment the client gives the Edge
// (docs/multi_region_client_region_failover_design.md): a residency-filtered list of per-region CP endpoints, and
// the SAME regionfailover.Selector engine — health-probe each CP's GET /leader (200 = that region hosts the active
// CP leader), pull/ship through the nearest healthy one, fail over on strikes, and (control-channel) simply keep
// the last config while none is reachable. GSLB-free: selection is client-driven + health-probed, not DNS-routed.
// See docs/cross_region_control_plane_failover_design.md.

// cpEndpointSelector maintains the current healthy CP base URL over a residency-filtered CP-endpoint list.
type cpEndpointSelector struct {
	selector *regionfailover.Selector
	client   *http.Client
	interval time.Duration
	mu       sync.RWMutex
	current  string // current CP base URL ("" = no healthy CP right now → keep last config)
	// currentRegion is WHICH region that URL belongs to. The admin plane and the data plane are different
	// addresses of the same region, so anything that has to reach the DATA plane of wherever leadership is
	// needs the region, not the admin URL. See controlChannelCurrentDataURL.
	currentRegion string
	state         string
	// regions is what this node was GIVEN, kept here rather than asked of the selector: the report has to be
	// able to say "one entry" as clearly as it says "connected", and a list of one is the shape that cannot
	// fail over.
	regions []string
}

// newCPEndpointSelector builds the selector from a residency-filtered CP-endpoint list (home = the preferred CP
// region). Returns nil when fewer than one endpoint is given (single-CP mode → callers keep the fixed URL).
func newCPEndpointSelector(endpoints []regionfailover.RegionEndpoint, home string, client *http.Client, interval time.Duration, strikes int) *cpEndpointSelector {
	if len(endpoints) == 0 || client == nil {
		return nil
	}
	sel := regionfailover.New(endpoints, home)
	if strikes > 0 {
		sel.SetUnhealthyStrikes(strikes)
	}
	regions := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		regions = append(regions, ep.Region)
	}
	sort.Strings(regions)
	return &cpEndpointSelector{selector: sel, client: client, interval: interval, regions: regions}
}

// probe measures one CP endpoint: reachable = it answered; admitted = GET /leader == 200 (this region hosts the
// active CP leader). A standby CP (503) is reachable-but-not-leader and is NOT selected, so the Edge always pulls
// from the region that currently holds leadership.
func (c *cpEndpointSelector) probe(ep regionfailover.RegionEndpoint) regionfailover.Health {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(ep.Endpoint, "/")+"/leader", nil)
	if err != nil {
		return regionfailover.Health{}
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return regionfailover.Health{Reachable: false}
	}
	defer resp.Body.Close()
	return regionfailover.Health{Reachable: true, Admitted: resp.StatusCode == http.StatusOK, RTT: rtt}
}

// CurrentBaseURL returns the CP base URL to use right now, or "" when no healthy in-boundary CP is reachable
// (the control channel then keeps the last config / buffers audit — it never crosses the residency boundary).
func (c *cpEndpointSelector) CurrentBaseURL() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// run drives the selection loop until ctx is done.
func (c *cpEndpointSelector) run(ctx context.Context) {
	if c == nil {
		return
	}
	t := time.NewTicker(c.interval)
	defer t.Stop()
	c.evaluate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.evaluate()
		}
	}
}

func (c *cpEndpointSelector) evaluate() {
	d := c.selector.Evaluate(c.probe)
	url := ""
	if d.State == regionfailover.StateConnected {
		url = d.Current.Endpoint
	}
	region := ""
	if d.State == regionfailover.StateConnected {
		region = strings.ToLower(strings.TrimSpace(d.Current.Region))
	}
	c.mu.Lock()
	changed := url != c.current || d.State.String() != c.state
	c.current = url
	c.currentRegion = region
	c.state = d.State.String()
	c.mu.Unlock()
	if changed {
		if d.State == regionfailover.StateConnected {
			log.Printf("cp_endpoint_failover: control channel → CP region %q (%s) — %s", d.Current.Region, d.Current.Endpoint, d.Reason)
		} else {
			log.Printf("cp_endpoint_failover: no in-boundary CP reachable (%s) — keeping last config, buffering audit", d.Reason)
		}
	}
}

// parseCPEndpoints parses "region-a=https://cpA:9443;region-b=https://cpB:9443" into the residency-filtered list.
func parseCPEndpoints(seed string) []regionfailover.RegionEndpoint {
	var out []regionfailover.RegionEndpoint
	for _, part := range strings.Split(seed, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		region, endpoint, ok := strings.Cut(part, "=")
		region = strings.TrimSpace(region)
		endpoint = strings.TrimSpace(endpoint)
		if !ok || region == "" || endpoint == "" {
			continue
		}
		out = append(out, regionfailover.RegionEndpoint{Region: region, Endpoint: endpoint})
	}
	return out
}

// controlChannelStateForReport is what this Edge says about where it takes configuration from, and whether it
// has anywhere else to go.
//
// ★★★ AN EDGE WITH ONE CONTROL PLANE IS NOT VISIBLY DIFFERENT FROM ONE WITH FOUR (2026-08-25). the multi-region install order's control-plane failover step is
// control-plane failover, and the installer generated no endpoint list at all — so every Edge it produced took
// a single URL and had nowhere to go when the region answering it died. It would have kept serving what it
// last applied, indefinitely, looking healthy the whole time. That is exactly the state nobody can see from
// outside, so the Edge says it.
//
// regions is what this node was given; current is where it is pulling from now. A node whose list has one
// entry says so, and a node that has a list and is connected to none says that too — "keeping last config"
// is a real state and it must not read as health.
func (c *cpEndpointSelector) controlChannelStateForReport(fixedURL string) map[string]any {
	if c == nil {
		// Single-CP mode: honest about being the shape that cannot fail over.
		return map[string]any{"failover": false, "regions": []string{}, "current": fixedURL, "state": "fixed"}
	}
	c.mu.RLock()
	current, state := c.current, c.state
	c.mu.RUnlock()
	return map[string]any{"failover": len(c.regions) > 1, "regions": c.regions, "current": current, "state": state}
}

// controlChannelSelector / controlChannelFixedURL are what this process ended up with, recorded once at
// start-up so the health answer can report it without threading the value through every caller.
var (
	controlChannelSelector atomic.Pointer[cpEndpointSelector]
	controlChannelFixedURL atomic.Pointer[string]
)

func setControlChannelState(sel *cpEndpointSelector, fixedURL string) {
	if sel != nil {
		controlChannelSelector.Store(sel)
	}
	u := fixedURL
	controlChannelFixedURL.Store(&u)
}

func controlChannelReport() map[string]any {
	fixed := ""
	if p := controlChannelFixedURL.Load(); p != nil {
		fixed = *p
	}
	return controlChannelSelector.Load().controlChannelStateForReport(fixed)
}

// controlChannelCurrentBaseURL is where this node is currently taking configuration from, or "" when it has
// no list or is connected to none. Read by anything else that has to reach the authority and would otherwise
// hold a fixed address — see admin_session_authority.go.
func controlChannelCurrentBaseURL() string {
	sel := controlChannelSelector.Load()
	if sel == nil {
		return ""
	}
	return sel.CurrentBaseURL()
}

// cpDataEndpoints maps a region to the DATA-plane address of its control plane — the door a node WRITES to
// (what it recorded, who enrolled, which connector joined), as opposed to the admin door it reads from.
//
// ★★★ THE WRITE PATH WAS THE LAST FIXED ADDRESS (2026-08-25, measured with leadership in another region).
// Everything that READS followed leadership by then — the config pull, the fleet report, identity, the
// enrolment-token authority. What a node WRITES still went to one address, so with leadership elsewhere:
//
//	enrolment_report_outbox: delivered=0 still_pending=2   (growing)
//	FAIL the authority counts the connector — registered on an Edge and the control plane does not name it
//
// The outbox meant nothing was lost; it also meant nothing arrived, for as long as leadership stayed away.
// The region is the same region the read path chose — there is one leader — so this is a second ADDRESS for
// the same decision rather than a second decision.
var cpDataEndpoints atomic.Pointer[map[string]string]

func setCPDataEndpoints(seed string) {
	m := map[string]string{}
	for _, part := range strings.Split(seed, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		region, endpoint, ok := strings.Cut(part, "=")
		region, endpoint = strings.ToLower(strings.TrimSpace(region)), strings.TrimSpace(endpoint)
		if !ok || region == "" || endpoint == "" {
			continue
		}
		m[region] = strings.TrimRight(endpoint, "/")
	}
	if len(m) == 0 {
		return
	}
	cpDataEndpoints.Store(&m)
}

// controlChannelCurrentDataURL is the data-plane address of the region leadership is currently in, or "" when
// there is no list, no current leader, or no address for that region — in which case callers keep their
// configured one, which is right for a single-region deployment.
func controlChannelCurrentDataURL() string {
	sel := controlChannelSelector.Load()
	if sel == nil {
		return ""
	}
	sel.mu.RLock()
	region := sel.currentRegion
	sel.mu.RUnlock()
	if region == "" {
		return ""
	}
	m := cpDataEndpoints.Load()
	if m == nil {
		return ""
	}
	return (*m)[region]
}

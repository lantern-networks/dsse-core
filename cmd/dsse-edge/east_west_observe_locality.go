package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// east_west_observe_locality.go — giving plane membership an address to reason about when the destination
// arrived as a name.
//
// ★★ WHY (2026-08-14, from the operator: "an ssh to github is showing up under connector access — that should
// be internet access"). They were right, and the reason is narrower than it looks.
//
// The classification itself was fixed on 2026-08-09 (1267ec4f, "a public address is internet access whatever
// protocol reaches it"): IsEastWestFlow asks the protocol AND the destination locality, and a PUBLIC address is
// refused. What it cannot refuse is a NAME. EastWestLocalityAdmits returns true for everything except Public,
// so LocalityUnknown is admitted — deliberately, and correctly for enforcement: a private destination this Edge
// cannot classify must not fall silently out of lateral governance.
//
// But DestinationIP is never populated on the steer path — the forward proxy blanks it outright — so a
// destination given as a hostname is ALWAYS Unknown. Two of the three public destinations in the lab's
// inventory are bare IPs recorded before that fix; `github.com` is not residue, it is the live shape: any name
// this Edge has not resolved lands in the lateral inventory whether it is a fileserver or a public git host.
// The lab only looked mostly clean because most of its ssh traffic used IP literals.
//
// ★ AND THE INVENTORY IS WHERE THIS MATTERS MOST, not the decision. The operator's next action on this screen
// is "adopt this flow into a lateral rule". Adopting github.com as a lateral rule is not a display defect, it
// is a wrong rule authored from a correct-looking prompt. So the OBSERVATION gate resolves the name and
// classifies the address; ENFORCEMENT is untouched and still admits Unknown, which is the decision this splits
// apart deliberately rather than quietly unifying.
//
// An unresolvable name is still recorded. That is the same reasoning one paragraph up: not knowing is not
// evidence of being public, and the failure that costs something is dropping a private destination.

// observeLocalityTTL is how long a resolved answer is reused. Long enough that a run of flows to one host costs
// a single lookup, short enough that a destination which moves between networks is reclassified the same day.
const observeLocalityTTL = 5 * time.Minute

// observeResolveTimeout bounds the lookup. This runs on the flow-open path, so it is deliberately short: an
// inventory entry is not worth delaying a connection for, and a timeout lands on "record it" — the preserving
// answer — rather than on dropping the flow from the inventory.
const observeResolveTimeout = 250 * time.Millisecond

type observeLocalityEntry struct {
	// ip is the address chosen for this name, or "" when nothing was resolved.
	ip string
	at time.Time
}

// restart-durability: ephemeral — a replay cache for DNS answers. Losing it costs one lookup per lateral
// destination after a restart, and nothing an operator can see: the inventory it gates is itself durable.
//
// populated-by: side_effect — filled by the flow-open path as lateral flows arrive. Being empty off that path
// is the correct state; an Edge carrying no lateral traffic has nothing to classify.
type observeLocalityCache struct {
	mu sync.Mutex
	m  map[string]observeLocalityEntry
}

func newObserveLocalityCache() *observeLocalityCache {
	return &observeLocalityCache{m: map[string]observeLocalityEntry{}}
}

func (c *observeLocalityCache) get(host string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[host]
	if !ok || now.Sub(e.at) > observeLocalityTTL {
		return "", false
	}
	return e.ip, true
}

func (c *observeLocalityCache) put(host string, ip string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Bounded by forgetting everything rather than by evicting cleverly: this holds one boolean per lateral
	// destination seen in five minutes, and a cache that needs an eviction policy to be safe is a cache that
	// will one day need it debugged.
	if len(c.m) > 4096 {
		c.m = map[string]observeLocalityEntry{}
	}
	c.m[host] = observeLocalityEntry{ip: ip, at: now}
}

var observeLocality = newObserveLocalityCache()

// observeResolver is the lookup, replaceable in tests. net.DefaultResolver inside the Edge answers through the
// container's resolver, which is the same view its egress uses.
var observeResolver = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// resolveDestinationForLocality returns req with DestinationResolvedIP filled in when the destination is a
// name this Edge can resolve. Everything else is unchanged, and DestinationIP is never touched.
//
// ★ THE RULE THIS IMPLEMENTS, in the operator's words on 2026-08-14: traffic to a destination that is a
// REGISTERED network is east-west. The wiring already said so — EastWestInternalNetworks is built from the
// connector registry's reachable routes, and east_west_internal_networks.go states outright that destinations
// inside the declared networks are connector-mediated and everything else is internet access. The missing step
// was never the rule, it was that a name has no address to test the rule against.
//
// ★ WHICH ADDRESS, WHEN A NAME HAS SEVERAL. The most INTERNAL one. A name that resolves both inside and
// outside — split horizon, or a service published both ways — is one this Edge may legitimately reach
// laterally, and choosing a public answer would drop it out of lateral governance on the strength of which
// record came back first. Being wrong toward keeping enforcement is the recoverable direction.
func resolveDestinationForLocality(ctx context.Context, req model.DecisionRequest, networks decision.InternalNetworks,
	now time.Time) model.DecisionRequest {
	if !decision.IsEastWestProtocol(req.ServiceFamily) {
		return req // only plane membership reads this, and only these protocols can be east-west at all
	}
	if strings.TrimSpace(req.DestinationIP) != "" {
		return req // the client gave an address; nothing to resolve and nothing to second-guess
	}
	host := strings.TrimSpace(req.FQDN)
	if host == "" {
		host = strings.TrimSpace(req.Destination)
	}
	if host == "" || net.ParseIP(host) != nil {
		return req
	}
	if cached, ok := observeLocality.get(host, now); ok {
		if cached != "" {
			req.DestinationResolvedIP = cached
		}
		return req
	}

	lookupCtx, cancel := context.WithTimeout(ctx, observeResolveTimeout)
	defer cancel()
	ips, err := observeResolver(lookupCtx, host)
	if err != nil || len(ips) == 0 {
		// Not resolvable is not evidence of anything. Left empty, the classifier answers Unknown, which east-west
		// admits — the same preserving answer as before this file existed. Deliberately NOT cached: a transient
		// DNS failure must not pin the answer for the TTL.
		return req
	}

	chosen := ips[0].String()
	for _, ip := range ips {
		probe := req
		probe.DestinationResolvedIP = ip.String()
		if decision.ClassifyDestinationLocality(probe, networks) != decision.LocalityPublic {
			chosen = ip.String()
			break
		}
	}
	observeLocality.put(host, chosen, now)
	req.DestinationResolvedIP = chosen
	return req
}

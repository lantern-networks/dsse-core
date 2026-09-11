package connector

import (
	"net"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// ResolveConnectorForHost is the connector ROUTE layer (reachability): given a flow's destination host and the
// candidate connectors, it returns the id of the connector that FRONTS that host by FQDN-domain match. It is
// separate from policy, which still authorizes the flow (reachable != authorized).
//
// Matching is by NAME (a DNS name is unique even when private IPs overlap across sites, so this needs no
// namespace scoping). A connector route domain "tokyo.corp" matches the apex "tokyo.corp" and any subdomain
// "a.tokyo.corp"; a wildcard "*.tokyo.corp" matches strict subdomains only. The MOST SPECIFIC (longest, by label
// count) matching domain wins; ties break deterministically by connector id, so the result is stable. Returns
// ok=false when no connector fronts the host (the caller then has NO route — fail-closed: no implicit reach).
// CIDR + namespace matching is a later slice; this resolves FQDNDomains only.
func ResolveConnectorForHost(host string, connectors []model.ConnectorRegistration) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", false
	}
	bestID := ""
	bestLen := -1
	for _, c := range connectors {
		for _, domain := range c.ReachableRoutes.FQDNDomains {
			n, ok := fqdnDomainMatchLen(host, domain)
			if !ok {
				continue
			}
			if n > bestLen || (n == bestLen && (bestID == "" || c.ID < bestID)) {
				bestLen, bestID = n, c.ID
			}
		}
	}
	return bestID, bestLen >= 0
}

// ResolveConnectorForDestination is the single route-layer entry point a steered flow takes: it PREFERS name
// routing (ResolveConnectorForHost — unique across sites, no namespace needed) and falls back to IP routing
// (ResolveConnectorForIP, scoped by namespace) when the destination is an IP literal or matches no name route.
// namespace is the flow's site / virtual-network context, consulted only for the IP fallback. Returns ok=false
// when no connector fronts the destination (fail-closed — the edge then has no route and denies). This is the
// reachability decision only; policy still authorizes the flow separately.
func ResolveConnectorForDestination(destination, namespace string, connectors []model.ConnectorRegistration) (string, bool) {
	if id, ok := ResolveConnectorForHost(destination, connectors); ok {
		return id, true
	}
	return ResolveConnectorForIP(destination, namespace, connectors)
}

// fqdnDomainMatchLen reports whether `domain` (optionally a "*.suffix" wildcard) fronts `host`, and the match
// specificity (the domain's label count) so a more specific route wins. host is already normalized.
func fqdnDomainMatchLen(host, domain string) (int, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	wildcard := strings.HasPrefix(domain, "*.")
	base := domain
	if wildcard {
		base = strings.TrimPrefix(domain, "*.")
	}
	if base == "" {
		return 0, false
	}
	if wildcard {
		// strict subdomains of base, not the apex
		if strings.HasSuffix(host, "."+base) {
			return labelCount(base), true
		}
		return 0, false
	}
	// bare domain: the apex or any subdomain
	if host == base || strings.HasSuffix(host, "."+base) {
		return labelCount(base), true
	}
	return 0, false
}

func labelCount(domain string) int {
	if domain == "" {
		return 0
	}
	return strings.Count(domain, ".") + 1
}

// ResolveConnectorForIP is the CIDR side of the route layer, for IP-addressed resources (slice 2). Because
// private ranges overlap across sites (Tokyo's 10.0.0.0/8 != Osaka's, same CIDR), CIDR matching MUST be scoped
// by `namespace` (a site / virtual-network id): only connectors in the
// SAME namespace as the flow are considered, so 10.x in "tokyo" and 10.x in "osaka" resolve to different
// connectors. The LONGEST-PREFIX matching CIDR wins; ties break by connector id (stable); no match => ok=false
// (fail-closed). FQDN routing (ResolveConnectorForHost) is preferred where a name exists, since names need no
// namespace.
func ResolveConnectorForIP(ip, namespace string, connectors []model.ConnectorRegistration) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", false
	}
	bestID := ""
	bestNS := ""
	bestPrefix := -1
	ambiguous := false
	for _, c := range connectors {
		// Namespace scoping is the overlap guarantee. When the caller NAMES a namespace (a flow that carries
		// site context — e.g. an /apps route with a route profile), only that namespace's routes are eligible,
		// so overlapping private ranges across sites can't collide. When the caller passes NO namespace (a raw
		// steered IP flow carries no site context), match across ALL namespaces but treat a same-prefix cover
		// in a DIFFERENT namespace as ambiguous and refuse to guess — mirrors the CIDRCollision.Ambiguous rule
		// (an unscoped CIDR that overlaps is blocked by default). Single-site deployments resolve cleanly.
		if namespace != "" && c.ReachableRoutes.Namespace != namespace {
			continue
		}
		for _, cidr := range c.ReachableRoutes.CIDRs {
			_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil || !network.Contains(parsed) {
				continue
			}
			ones, _ := network.Mask.Size()
			switch {
			case ones > bestPrefix:
				bestPrefix, bestID, bestNS, ambiguous = ones, c.ID, c.ReachableRoutes.Namespace, false
			case ones == bestPrefix:
				if c.ReachableRoutes.Namespace != bestNS {
					ambiguous = true // same-prefix cover from another site, no namespace to disambiguate
				} else if bestID == "" || c.ID < bestID {
					bestID = c.ID
				}
			}
		}
	}
	if ambiguous {
		return "", false
	}
	return bestID, bestPrefix >= 0
}

// CIDRRoute is one CIDR-addressed route in the collision domain (Connector UX Slice 5, docs/connector_ux_design.md
// ). It is the network plus the two dimensions that SCOPE it: Namespace (the site / virtual-network id that lets
// overlapping private ranges coexist) and Site (the connector group). Source is a non-secret human label for the
// existing owner (e.g. the Site / connector that already advertises the CIDR) used only for the UX collision report.
type CIDRRoute struct {
	CIDR      string
	Namespace string
	Site      string
	Source    string
}

// CIDRCollision describes one detected overlap between a candidate CIDR route and an existing route. With is the
// existing CIDR the candidate overlaps; Namespace/Site/Source attribute the existing owner. Relation reports how
// the two networks overlap (equal | contains | contained_by | overlap) so the UX can explain the conflict.
// Ambiguous is true when the candidate carries NO namespace to disambiguate the overlap — the "ambiguous CIDR"
// case that is blocked by default.
type CIDRCollision struct {
	CIDR      string `json:"cidr"`
	With      string `json:"with_cidr"`
	Namespace string `json:"namespace,omitempty"`
	Site      string `json:"site,omitempty"`
	Source    string `json:"source,omitempty"`
	Relation  string `json:"relation"`
	Ambiguous bool   `json:"ambiguous"`
}

// DetectCIDRCollisions reports every existing CIDR route the candidate collides with (Connector UX Slice 5).
//
// Two overlapping CIDRs are SEPARATED (no collision) when EITHER dimension distinguishes them: both carry a
// non-empty namespace that differs, OR both carry a non-empty site that differs. This is the namespace-scoped /
// site-bound guard: a different namespace OR a different site means no collision. Otherwise the overlap is a collision:
//
//   - same namespace + same site (a genuine duplicate within one scope), or
//   - an overlap that cannot be disambiguated because a namespace is missing.
//
// A collision is marked Ambiguous when the CANDIDATE carries no namespace (the "ambiguous CIDR" — blocked by
// default). FQDN/host destinations are not CIDRs and never reach here; the caller passes only CIDR routes. A
// candidate that is not a parseable CIDR yields no collisions (the caller validates the destination separately).
// The result is deterministic: existing routes are scanned in the given order and only overlapping ones are kept.
func DetectCIDRCollisions(candidate CIDRRoute, existing []CIDRRoute) []CIDRCollision {
	_, candNet, err := net.ParseCIDR(strings.TrimSpace(candidate.CIDR))
	if err != nil || candNet == nil {
		return nil
	}
	candNS := strings.TrimSpace(candidate.Namespace)
	candSite := strings.TrimSpace(candidate.Site)
	collisions := []CIDRCollision{}
	for _, route := range existing {
		_, exNet, err := net.ParseCIDR(strings.TrimSpace(route.CIDR))
		if err != nil || exNet == nil {
			continue
		}
		if !cidrNetsOverlap(candNet, exNet) {
			continue
		}
		exNS := strings.TrimSpace(route.Namespace)
		exSite := strings.TrimSpace(route.Site)
		// Separated by a differing namespace (both set) OR a differing site (both set): no collision.
		if candNS != "" && exNS != "" && candNS != exNS {
			continue
		}
		if candSite != "" && exSite != "" && candSite != exSite {
			continue
		}
		collisions = append(collisions, CIDRCollision{
			CIDR:      strings.TrimSpace(candidate.CIDR),
			With:      strings.TrimSpace(route.CIDR),
			Namespace: exNS,
			Site:      exSite,
			Source:    strings.TrimSpace(route.Source),
			Relation:  cidrRelation(candNet, exNet),
			Ambiguous: candNS == "",
		})
	}
	if len(collisions) == 0 {
		return nil
	}
	return collisions
}

// cidrNetsOverlap reports whether two networks intersect: one contains the other's base address. For proper CIDR
// networks (base address already masked) this is exact — equal, subset, or superset all surface as an overlap.
func cidrNetsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// cidrRelation classifies the candidate (a) against the existing (b) network for the UX report.
func cidrRelation(a, b *net.IPNet) string {
	aOnes, _ := a.Mask.Size()
	bOnes, _ := b.Mask.Size()
	switch {
	case aOnes == bOnes && a.IP.Equal(b.IP):
		return "equal"
	case aOnes < bOnes && a.Contains(b.IP):
		return "contains" // candidate is the broader range
	case bOnes < aOnes && b.Contains(a.IP):
		return "contained_by" // candidate falls inside the existing range
	default:
		return "overlap"
	}
}

// ResolveConnectorsForHost is ResolveConnectorForHost returning EVERY connector that fronts the host, most
// specific first and stable within a specificity.
//
// ★★★ A SITE HOLDS MORE THAN ONE CONNECTOR ON PURPOSE (the operator's reminder, 2026-08-26). Route bindings
// are authored on the SITE, so every connector in it fronts the same names — that is what makes the pair an HA
// pair. Picking ONE of them by id order, as the single-winner form does, hands every flow to the same member
// and fails the flow outright when that member is the one this Edge cannot reach: no tunnel here, no mesh link
// to its region. The other member is sitting there, live, holding the same route.
//
// So the route layer offers the caller all of them, in a stable order, and the caller — which is the only
// place that knows what it can actually reach — takes the first that answers. Order is unchanged for a site
// with one connector, so a single-connector deployment behaves exactly as before.
func ResolveConnectorsForHost(host string, connectors []model.ConnectorRegistration) []string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return nil
	}
	type match struct {
		id  string
		len int
	}
	// ★★★ AND A SUBNET COUNTS, WHICH IS WHY AN HA PAIR HAD ONE MEMBER (2026-09-01, measured by stopping one
	// connector of a pair and watching the whole site go dark).
	//
	// This matched FQDN domains only. A private asset is published as a Named Network — a CIDR — so a
	// destination inside one produced NO matches here, the caller fell back to the single-connector resolver,
	// and every flow to that asset had exactly one candidate. The pair existed on the screen and in the
	// catalogue and nowhere in the datapath: losing the one candidate lost the site, with its partner live and
	// holding the identical route.
	//
	// Longest-prefix ordering is kept for CIDRs the way longest-suffix is for names, so a more specific route
	// still wins; members that cover the destination equally are all candidates, which is what makes them a
	// pair.
	address := net.ParseIP(host)
	matches := make([]match, 0, len(connectors))
	for _, c := range connectors {
		best := -1
		for _, domain := range c.ReachableRoutes.FQDNDomains {
			if n, ok := fqdnDomainMatchLen(host, domain); ok && n > best {
				best = n
			}
		}
		if address != nil {
			for _, cidr := range c.ReachableRoutes.CIDRs {
				_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
				if err != nil || !network.Contains(address) {
					continue
				}
				if ones, _ := network.Mask.Size(); ones > best {
					best = ones
				}
			}
		}
		if best >= 0 {
			matches = append(matches, match{id: c.ID, len: best})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].len != matches[j].len {
			return matches[i].len > matches[j].len
		}
		return matches[i].id < matches[j].id
	})
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.id)
	}
	return out
}

package main

import (
	"context"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
)

// east_west_internal_networks.go — tell the decision path what this tenant considers "inside".
//
// East-west plane membership needs the destination, not just the protocol. Private address space is the
// floor and is always internal; this supplies the rest — the CIDRs and DNS suffixes an operator has declared,
// so a destination on a globally routable address that is nonetheless part of the estate stays on the lateral
// plane.
//
// The source is the connectors' ADVERTISED REACHABLE ROUTES, and that is not an arbitrary choice: in this
// product "connector-mediated" and "internal" are the same statement. It is also the operator's own words for
// the model — destinations inside the declared internal networks are connector-mediated, everything else is
// internet access.
//
// Why this is refreshed rather than stored: the routes already have a durable home and their own approval
// workflow (route governance holds a newly advertised CIDR until an operator accepts it). A second persisted
// copy would be a ledger that can disagree with the one that owns the answer, and the disagreement would show
// up as an Edge deciding plane membership from a stale idea of the estate — with no error anywhere.

// refreshEastWestInternalNetworks recomputes a tenant's declared-internal networks from the connector
// registry and pushes them into the policy store, where RuntimeEvaluator picks them up.
//
// Best-effort by design: a registry read that fails leaves the PREVIOUS declaration in place rather than
// clearing it. Clearing would silently shrink the lateral plane — every declared-internal destination on a
// public address would become "internet access" and quietly lose per-hop authorization — which is exactly the
// direction a security control must never fail in. A stale declaration is wrong in the safe direction: it
// keeps enforcing.
func refreshEastWestInternalNetworks(ctx context.Context, store any, registry connectorRegistryStore, tenantID string) {
	// Narrow to the setter rather than to *policy.Store: the Edge holds this as a policy.RuntimeStore
	// interface, and a store that does not implement the setter (a test double, an alternative backend) must
	// degrade to "no declaration" rather than force every caller to type-assert.
	setter, ok := store.(interface {
		SetEastWestInternalNetworks(string, decision.InternalNetworks)
	})
	if !ok || registry == nil {
		return
	}
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		return
	}
	conns, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenant)
	if err != nil {
		logDebugf("east_west_internal_networks: registry read failed for tenant=%q (%v) — keeping the previous declaration", tenant, err)
		return
	}
	views := make([]connectorRegistrationView, 0, len(conns))
	for _, c := range conns {
		views = append(views, connectorRegistrationView{CIDRs: c.ReachableRoutes.CIDRs, FQDNDomains: c.ReachableRoutes.FQDNDomains})
	}
	networks := declaredInternalNetworksFrom(views)
	setter.SetEastWestInternalNetworks(tenant, networks)
	logDebugf("east_west_internal_networks tenant=%q cidrs=%d domains=%d connectors=%d",
		tenant, len(networks.CIDRs), len(networks.Domains), len(conns))
}

// declaredInternalNetworksFrom collects the reachable routes across a tenant's connectors, deduped.
//
// Pure so it can be tested without a registry. Note it does NOT filter by connector health: a connector that
// is offline right now has not stopped its subnet from being part of the estate, and treating it as external
// while it reconnects would flap destinations between planes.
func declaredInternalNetworksFrom(conns []connectorRegistrationView) decision.InternalNetworks {
	seenCIDR := map[string]bool{}
	seenDomain := map[string]bool{}
	out := decision.InternalNetworks{}
	for _, c := range conns {
		for _, cidr := range c.CIDRs {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" || seenCIDR[cidr] {
				continue
			}
			seenCIDR[cidr] = true
			out.CIDRs = append(out.CIDRs, cidr)
		}
		for _, d := range c.FQDNDomains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" || seenDomain[d] {
				continue
			}
			seenDomain[d] = true
			out.Domains = append(out.Domains, d)
		}
	}
	return out
}

// connectorRegistrationView is the slice of a connector registration this file needs. It exists so
// declaredInternalNetworksFrom is testable without constructing full registrations.
type connectorRegistrationView struct {
	CIDRs       []string
	FQDNDomains []string
}

// logDeclaredInternalNetworksAtBoot states the tenant's plane boundary once, at startup, at INFO.
//
// An empty declaration is CORRECT for a flat private estate and WRONG for one that routes public ranges
// internally, and the two are indistinguishable from the outside. Saying which case this deployment is in,
// once, is the difference between "east-west is not firing for that host" being a five-minute answer and a
// day of reading decision logs.
func logDeclaredInternalNetworksAtBoot(networks decision.InternalNetworks, tenantID string) {
	if networks.Empty() {
		log.Printf("east_west_internal_networks tenant=%s DECLARED=none — east-west plane membership is decided by "+
			"private address space alone (RFC1918/loopback/link-local/ULA/CGNAT). Correct for a flat private "+
			"estate; if this tenant reaches internal services on PUBLIC addresses, those flows are internet "+
			"access here and will NOT get per-hop authorization until a connector advertises them", tenantID)
		return
	}
	log.Printf("east_west_internal_networks tenant=%s cidrs=%v domains=%v — these extend the lateral plane "+
		"beyond private address space", tenantID, networks.CIDRs, networks.Domains)
}

package main

// A device may name the destination of a flow instead of giving its address. The macOS agent does: when an
// application connects by name, the flow carries that name. The Windows agent sends the address it resolved.
//
// The route layer matched a name only against routes declared BY NAME. A name that is not declared, but whose
// address lies in a network a Connector route carries by ADDRESS, was therefore not recognised as traffic to a
// registered network: it was decided by Internet Access and dialled from the Edge as a public destination,
// which an Edge outside the private network cannot reach. The same destination given as an address — the
// Windows agent's flow — went through the connector. Traffic to a registered network is Connector Access
// whichever way the device names it.
//
// The address is the Edge's own answer for the name, never one the device supplies: a device that could say
// "this name, at that address" could carry a rule written for one name to any address. First the answer this
// Edge gave the tenant's devices for the name — which for a zone the organization forwards to its internal DNS
// came from that DNS, through the connector — and only when it gave none, its own lookup. A name a Connector
// route declares by name is left as it is — that connector resolves it on its side.

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// nameInsideRegisteredNetworkResolveTimeout bounds the Edge's own lookup on the flow-open path. It is longer than
// the inventory's lookup because the answer decides where the flow goes, not only how it is recorded.
const nameInsideRegisteredNetworkResolveTimeout = 2 * time.Second

// registeredAddressBehindName returns the address a device-named destination stands for when that address lies
// in a network one of the tenant's live connectors carries by address. ok=false leaves the flow as it was:
// the destination is an address already, the tenant has no address routes, the Edge's answers for the name are
// all outside the registered networks, or a Site declares the name and this Edge gave no answer on that Site.
func registeredAddressBehindName(ctx context.Context, registry connectorRegistryStore, answered func(tenantID, name string, now time.Time) []string,
	tenantID, host string, now time.Time) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if name == "" || net.ParseIP(name) != nil || registry == nil {
		return "", false
	}
	live, err := liveConnectorRoutes(ctx, registry, tenantID)
	if err != nil || !anyAddressRoute(live) {
		return "", false
	}
	var candidates []string
	if answered != nil {
		candidates = answered(tenantID, name, now)
	}
	// A name a Site declares is resolved on that Site. It becomes an address flow only when this Edge itself
	// answered the tenant's devices with an address that the SAME Site carries — then a rule written for the
	// application's address applies to it, as it does to the Windows agent's flow to that address. Otherwise
	// the name stays a name and its Site's connector resolves it.
	declaredSite := ""
	if declaredBy, declared := connector.ResolveConnectorForHost(name, live); declared {
		declaredSite = siteOfConnector(live, declaredBy)
		if declaredSite == "" {
			return "", false
		}
	} else if len(candidates) == 0 {
		candidates = edgeAnswersFor(ctx, name, now)
	}
	sort.Strings(candidates)
	for _, ip := range candidates {
		addr := ipv4HostWithoutMapping(ip)
		carriedBy, routed := connector.ResolveConnectorForIP(addr, "", live)
		if !routed {
			continue
		}
		if declaredSite != "" && siteOfConnector(live, carriedBy) != declaredSite {
			continue
		}
		return addr, true
	}
	return "", false
}

func siteOfConnector(live []model.ConnectorRegistration, id string) string {
	for _, c := range live {
		if c.ID == id {
			return strings.TrimSpace(c.ConnectorGroupID)
		}
	}
	return ""
}

func anyAddressRoute(live []model.ConnectorRegistration) bool {
	for _, c := range live {
		if len(c.ReachableRoutes.CIDRs) > 0 {
			return true
		}
	}
	return false
}

// edgeAnswersFor is this Edge's resolution of name, shared with the plane-membership lookup's cache.
func edgeAnswersFor(ctx context.Context, name string, now time.Time) []string {
	if ips, cached := observeLocality.get(name, now); cached {
		return ips
	}
	lookupCtx, cancel := context.WithTimeout(ctx, nameInsideRegisteredNetworkResolveTimeout)
	defer cancel()
	resolved, err := observeResolver(lookupCtx, name)
	if err != nil || len(resolved) == 0 {
		return nil
	}
	ips := make([]string, 0, len(resolved))
	for _, ip := range resolved {
		ips = append(ips, ip.String())
	}
	observeLocality.put(name, ips, now)
	return ips
}

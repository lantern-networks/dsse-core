package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/model"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
)

// connectorDiscoveredInput is one destination a connector DECLARES it can reach (reachable_routes) that is not
// yet published as a private_app — the raw material for a connector-discovered candidate. Non-secret: only the
// declared route destination, the publish-protocol hint, and which connector/site declared it. No private base
// URL, secret, or payload ever flows through here.
type connectorDiscoveredInput struct {
	Destination     string
	PublishProtocol string
	ConnectorID     string
	Site            string
	Namespace       string
	Evidence        []string
}

// connectorDiscoveredCandidateInputs computes the reachable-route destinations a tenant's connectors front that
// are NOT already published as private_app catalog entries (the reachable_routes − published diff). It is PURE
// (no side effects, no scanning): it only reads the connectors' DECLARED reachable_routes and the published
// catalog, so it can never publish or authorize anything. A destination already published (exact, normalized
// match) is skipped so an established Private App is never re-proposed. fqdn_domains map to a web hint, cidrs to
// a network hint; the administrator chooses the real protocol at approve time.
func connectorDiscoveredCandidateInputs(connectors []model.ConnectorRegistration, published []appcatalog.Entry) []connectorDiscoveredInput {
	publishedSet := map[string]bool{}
	for _, entry := range published {
		if !entry.Published {
			continue
		}
		if dest := normalizeConnectorDestination(entry.Destination); dest != "" {
			publishedSet[dest] = true
		}
	}
	seen := map[string]bool{}
	out := []connectorDiscoveredInput{}
	add := func(rawDest, protocol, connectorID, site, namespace, evidence string) {
		dest := normalizeConnectorDestination(rawDest)
		if dest == "" || publishedSet[dest] || seen[dest] {
			return
		}
		seen[dest] = true
		out = append(out, connectorDiscoveredInput{
			Destination:     dest,
			PublishProtocol: protocol,
			ConnectorID:     strings.TrimSpace(connectorID),
			Site:            strings.TrimSpace(site),
			Namespace:       strings.TrimSpace(namespace),
			Evidence:        []string{evidence},
		})
	}
	for _, conn := range connectors {
		site := strings.TrimSpace(conn.ConnectorGroupID)
		namespace := strings.TrimSpace(conn.ReachableRoutes.Namespace)
		for _, fqdn := range conn.ReachableRoutes.FQDNDomains {
			add(fqdn, "web", conn.ID, site, namespace, "declared reachable route (fqdn_domains)")
		}
		for _, cidr := range conn.ReachableRoutes.CIDRs {
			add(cidr, "network", conn.ID, site, namespace, "declared reachable route (cidrs)")
		}
	}
	return out
}

// normalizeConnectorDestination lower-cases + trims a destination so the published/reachable diff and the
// candidate id are stable across casing and trailing dots.
func normalizeConnectorDestination(destination string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(destination)), ".")
}

// refreshConnectorDiscoveredCandidates derives connector-discovered candidates for a tenant from the
// reachable_routes − published diff and upserts each as a PENDING candidate. It never publishes or authorizes
// anything (auto-publish is forbidden): the only side effect is writing pending proposals an administrator must
// approve. Tenant-scoped: it reads only this tenant's connectors and published catalog.
func refreshConnectorDiscoveredCandidates(ctx context.Context, registry connectorRegistryStore, catalog appcatalog.RuntimeStore, store *policycandidate.Store, tenantID string, now time.Time) ([]policycandidate.Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if store == nil {
		return nil, fmt.Errorf("policy candidate store unavailable")
	}
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return nil, err
	}
	var published []appcatalog.Entry
	if catalog != nil {
		resp, err := catalog.List(ctx, tenantID, appcatalog.ListOptions{ApplicationType: "private_app", Limit: 1000})
		if err != nil {
			return nil, err
		}
		published = resp.Applications
	}
	inputs := connectorDiscoveredCandidateInputs(connectors, published)
	out := make([]policycandidate.Candidate, 0, len(inputs))
	for _, input := range inputs {
		cand, err := store.ObserveConnectorDiscovered(ctx, tenantID, input.Destination, 0, input.PublishProtocol, input.ConnectorID, input.Site, input.Namespace, input.Evidence, now)
		if err != nil {
			if errors.Is(err, policycandidate.ErrPersistence) {
				return nil, fmt.Errorf("record connector discovery: %w", err)
			}
			log.Printf("observe connector-discovered candidate: %v", err)
			continue
		}
		out = append(out, cand)
	}
	return out, nil
}

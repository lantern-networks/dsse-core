package main

import (
	"context"
	"fmt"
	"strings"
)

// ★★★ A CONNECTOR'S ORGANIZATION IS THE ONE ITS SITE BELONGS TO, NOT THIS NODE'S (2026-09-01, measured by
// putting a customer's connector in its own VPC and watching every registration answer 403).
//
// This is the same defect fixed for devices this morning, one lane over. The check compared the connector's
// tenant against the policy bundle THIS EDGE pulled, and on a deployment that serves customers that bundle is
// the operator's, because the fleet credential is:
//
//	connector tenant_id tenant_eksuhxrdhdimxjq2mbgqhd6tha does not match edge tenant_id tenant_default
//
// So no customer's connector could ever register, and the site it belongs to stayed "down" with zero
// connectors while the connector itself said, correctly, that its identity had been issued by that
// organization's device CA. Every screen agreed the site was offline.
//
// ★ THE AUTHORITY IS THE SITE CATALOGUE, WHICH IS CONTROL-PLANE AUTHORED. A Site is created by an
// administrator of an organization and travels in the config bundle; asking whether this deployment holds one
// under that organization is repeating that decision, not making a new one. The line immediately below this
// check already asks the same store for the same site — the tenant was the only part answered from the node.
//
// ★★ AND IT IS STILL A REAL BOUNDARY. A connector naming an organization this deployment holds no site for is
// refused, and so is one naming no organization at all. What it can no longer do is refuse every organization
// except the node's own.

// connectorTenantIsAdmitted reports whether this deployment admits the organization a connector names, and
// returns the reason when it does not. siteID is the connector's group (its Site); an empty store means this
// node has no catalogue to answer from, and then the node's own organization is all it can honestly check.
func connectorTenantIsAdmitted(ctx context.Context, store adminSiteStore, connectorTenantID, siteID, nodeTenantID string) error {
	connectorTenantID = strings.TrimSpace(connectorTenantID)
	if connectorTenantID == "" {
		return fmt.Errorf("connector tenant_id is required")
	}
	siteID = strings.TrimSpace(siteID)
	if store != nil && siteID != "" {
		if _, ok, err := store.Get(ctx, connectorTenantID, siteID); err == nil && ok {
			// The deployment holds this Site under this organization: an administrator of that organization
			// created it, and this connector names both. Nothing here is inferred from the node.
			return nil
		}
	}
	// ★ NO CATALOGUE TO ASK, OR NO SUCH SITE. Fall back to the node's own organization, which is the correct
	// answer on a single-tenant deployment and the only one available on a node whose site store is not
	// configured. Said in the error, so a refusal on a multi-tenant deployment names what was actually
	// missing rather than accusing the connector of belonging to the wrong organization.
	if nodeTenantID != "" && connectorTenantID != nodeTenantID {
		return fmt.Errorf("this deployment holds no site %q for organization %s, and this node serves %s — a "+
			"connector is admitted by the Site its organization authored, so either the Site has not reached "+
			"this node yet or it was created under a different organization", siteID, connectorTenantID, nodeTenantID)
	}
	return nil
}

package main

import (
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// connector_is_a_fleet_client.go — a connector connects to the FLEET, not to one Edge.
//
// ★★★ THE OPERATOR'S DECISION (2026-08-26): "a connector, like an agent, does region failover and connects to
// the Edge fleet, so it must not be bound to a single Edge."
//
// It was. Two things tied it to one node, and both were measured on the generated two-region lab, where a
// region has more than one Edge BY DEFAULT and the front door alternates between them:
//
//	the registry   authorisation began by asking whether THIS node's registry knows the connector. A node
//	               that had not seen it register answered "not registered for this tenant".
//	the secret     a runtime secret hash is established on the node a connector registers with, and lives
//	               nowhere else. Half of every connector's requests landed on the other Edge and were refused,
//	               for ever, alternating request by request.
//
// ★ THE CERTIFICATE ALREADY SAYS BOTH THINGS. It names the connector (the identity in the leaf) and it names
// the organization (the CA that issued it — the same rule a device's tenant comes from). Neither fact needs
// this node's registry, and neither changes from Edge to Edge, which is exactly what a fleet-facing credential
// has to mean. So the certificate IS the authentication, and the runtime secret becomes what it always
// actually was: a per-node convenience, verified when a node happens to hold one and never required.
//
// ★ NOTHING IS WIDENED. A caller with no certificate meets exactly the checks it met before, including the
// requirement to present one at all. What changes is that a connector holding the RIGHT certificate is no
// longer refused by an Edge that has simply never met it.

// connectorFleetIdentity is what a certificate establishes about a connector, on any Edge.
type connectorFleetIdentity struct {
	Presented bool   // a verified client certificate was presented at all
	BoundToID bool   // that certificate names THIS connector id
	TenantID  string // the organization whose device CA issued it ("" when this deployment has one CA)
	CertID    string // the identity in the certificate, for a refusal that names what was seen
}

// connectorFleetIdentityFromRequest reads the connector's identity from its certificate.
func connectorFleetIdentityFromRequest(r *http.Request, connectorID string, reg *tenantca.TenantCARegistry) connectorFleetIdentity {
	bound, certID, present := connectorMTLSIdentityBound(r, connectorID)
	out := connectorFleetIdentity{Presented: present, BoundToID: bound, CertID: certID}
	if !present {
		return out
	}
	if tenant, ok := transportTenantFromRequest(r, reg); ok {
		out.TenantID = strings.TrimSpace(tenant)
	}
	return out
}

// authenticatesAnywhere reports whether this certificate authenticates the connector on ANY Edge of the fleet.
//
// A deployment with no tenant CA registry has exactly one CA, so every accepted certificate is this
// deployment's own and the organization needs no separate comparison — the pre-existing reading, kept.
func (i connectorFleetIdentity) authenticatesAnywhere(reg *tenantca.TenantCARegistry) bool {
	if !i.Presented || !i.BoundToID {
		return false
	}
	if reg == nil {
		return true
	}
	return i.TenantID != ""
}

// contradictsRegistry reports that this node's registry holds the connector for a DIFFERENT organization than
// the certificate claims.
//
// ★ THE ONE THING THE LOCAL REGISTRY IS STILL ASKED. It cannot make a connector unknown-here into a refusal
// any more, but a node that HAS a record and disagrees with the certificate about whose connector this is has
// found a real conflict, and answering "fine" to that would let one organization's CA speak for another's
// connector id.
func (i connectorFleetIdentity) contradictsRegistry(registryTenant string) bool {
	registryTenant = strings.TrimSpace(registryTenant)
	if registryTenant == "" || i.TenantID == "" {
		return false
	}
	return !strings.EqualFold(registryTenant, i.TenantID)
}

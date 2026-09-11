package main

import (
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// steerMuxFlowTenant is the organization a steered flow belongs to: the one the device's (T) certificate
// proves, not the one this node happens to be seeded with.
//
// ★★★ EVERY STEERED FLOW WAS THIS NODE'S OWN ORGANIZATION (2026-08-28, measured by putting a second
// organization on the lab and running one flow as one of its devices). The device's IDENTITY was bound from
// the moment the mux handler was written; its ORGANIZATION never was. Three things read the tenant on that
// request — which authority signs the certificate the browser is shown, whose policy is applied, and whose
// flow the record says it was — so for every organization but the operator's, all three were wrong.
//
// Measured: a device of "Suzuran Foods", holding a certificate from Suzuran's own device CA and dialling
// Suzuran's own transport name, was served a leaf for example.com signed by the DEPLOYMENT's interception
// root, while Suzuran's own issuing CA sat loaded on that same Edge.
//
// ★ IT SEEDS THE REQUEST RATHER THAN CORRECTING IT. enrichDecisionRequestWithTransportTenant refuses a
// request whose claimed tenant disagrees with the certificate — correctly; that is a cross-tenant claim — and
// this request would have "claimed" the node's own tenant on every flow. Correcting afterwards would have
// DENIED every organization but the operator's instead of misattributing them.
func steerMuxFlowTenant(r *http.Request, reg *tenantca.TenantCARegistry, nodeTenant, deviceID string) string {
	if bound, ok := transportTenantFromRequest(r, reg); ok && strings.TrimSpace(bound) != "" {
		// ★★★ THE SUCCESS SIDE WAS INVISIBLE, AND THAT IS WHERE THE ANSWER WAS (2026-09-01). Only the FALLBACK
		// said anything, so a deployment attributing every flow to the wrong organization looked identical to
		// one attributing them correctly: no line either way. Hours went into the layers below this one —
		// connector lookup, egress guard, route fields — because the value they were all handed could not be
		// read anywhere. Said once per device, like its unresolved twin.
		logSteerMuxResolvedTenant(deviceID, bound)
		return bound
	}
	if reg != nil {
		logSteerMuxUnresolvedTenant(deviceID, nodeTenant)
	}
	return nodeTenant
}

// logSteerMuxUnresolvedTenant says, once per device, that a steered flow could not be attributed to an
// organization and was keyed to this node's own.
//
// ★ THIS IS THE HALF THAT IS NOT FIXED. The /steer path DENIES an unresolved tenant on a multi-tenant
// production Edge rather than falling back to the seed; doing that here in the same change would turn an
// attribution defect into an outage for every device whose CA is not in the registry. So the fallback stays
// and stops being silent — a number nobody can see is how the attribution itself survived.
//
// Once per device: a busy node must not turn one misconfigured laptop into a log nobody reads.
var steerMuxUnresolvedTenantSaid sync.Map

func logSteerMuxUnresolvedTenant(deviceID, keyedTo string) {
	if _, seen := steerMuxUnresolvedTenantSaid.LoadOrStore(deviceID, true); seen {
		return
	}
	log.Printf("steer_mux_tenant_unresolved device=%q keyed_to=%q — this flow's organization could not be "+
		"proved from the device's certificate, so its decision, its inspection authority and its record all "+
		"belong to this node's own organization. A device of another organization must present a certificate "+
		"from a CA this deployment has registered for it", deviceID, keyedTo)
}

var steerMuxResolvedTenantSaid sync.Map

// logSteerMuxResolvedTenant says, once per device, which organization a steered flow was proved to belong to.
// Its twin below says when that proof failed; between them, every device's attribution is readable.
func logSteerMuxResolvedTenant(deviceID, tenantID string) {
	if _, seen := steerMuxResolvedTenantSaid.LoadOrStore(deviceID, true); seen {
		return
	}
	log.Printf("steer_mux_tenant_resolved device=%q tenant=%q — this flow's organization was proved from the "+
		"device's certificate; its decision, its inspection authority and its record belong there",
		deviceID, tenantID)
}

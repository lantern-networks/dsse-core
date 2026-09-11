package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE ORGANIZATION A DEVICE IS RECORDED INTO IS THE DEVICE'S, NOT THE PULLER'S (2026-09-01, measured on a
// three-region deployment with a real Windows box, on the first walk that had a customer organization in it).
//
// The device store compares a device's tenant against the policy bundle it is handed, and every device route
// on this Edge handed it evaluator.PolicyBundle — the bundle THIS NODE pulled. On a deployment that serves
// customers that bundle is the operator's, because the fleet credential is the operator's. So registration,
// heartbeat and rehydration all refused with
//
//	device tenant_id tenant_… does not match policy bundle tenant_id tenant_default
//
// and the device heartbeated into a 404 for ever while its traffic was carried, decrypted and enforced. It
// was not a device the deployment refused; it was a comparison that asks a question about the NODE and
// answers it about the DEVICE.
//
// ★ THE AUTHORITY IS THE ENROLLED INVENTORY, KEYED BY THE IDENTITY THE TRANSPORT PROVED. Not the request
// body — that would let a device choose its own organization, which is the thing the whole admission lane
// exists to prevent. The ledger is control-plane authored and is what decides admission in the first place,
// so naming its tenant here repeats the authority rather than overriding it.
//
// ★★ AND IT IS NOT GATED ON THIS EDGE ALREADY HOLDING RULES FOR THAT ORGANIZATION. The bundle carries every
// tenant's enforcement config, but a newly created organization has no policies authored yet — gating on
// their presence would refuse exactly the devices of the customer who just signed up, which is this same
// defect wearing a different hat.
//
// When nothing was proven, or the ledger does not name an organization, the bundle is returned untouched: the
// refusal stays where it already is rather than being softened here.
func bundleForTheDevicesOrganization(ledger *enrolledinventory.Ledger, bundle model.PolicyBundle,
	proven, reported string) model.PolicyBundle {

	proven, reported = strings.TrimSpace(proven), strings.TrimSpace(reported)
	if ledger == nil || proven == "" || reported == "" || !strings.EqualFold(proven, reported) {
		return bundle
	}
	entry, ok := ledger.EntryFor(reported)
	if !ok {
		return bundle
	}
	tenant := strings.TrimSpace(entry.TenantID)
	if tenant == "" {
		return bundle
	}
	bundle.TenantID = tenant
	return bundle
}

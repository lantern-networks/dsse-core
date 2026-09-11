// update_plan_sync.go — the rollout plan courier: WHEN this device may install, and whether the fleet is
// halted.
//
// The twin of the manifest courier, and deliberately the same machinery (signedDocCourier) rather than a
// second implementation. Only the path, the destination file and the plausibility rule differ.
//
// ★ WHY THAT SHARING MATTERS MORE HERE THAN FOR THE MANIFEST. The plan carries the FREEZE, which is the only
// way to stop a release on devices that already hold its manifest. Deletion-lifting-the-halt is already the
// named residual gap; a plan courier that had grown its own delete path — on a 404, on a parse failure, on
// anything — would widen it from "an administrator can delete the file" to "a misdirected Edge path can".
// Sharing the type means the plan cannot acquire a delete path without the manifest acquiring one too, which
// is not a change anyone makes by accident.
//
// The document is written UNOPENED, same as the manifest. The updater verifies it against a pin, and the pins
// are DIFFERENT — the plan by the agent-policy key, the manifest by the update key — because an Edge may
// decide when a fleet updates and must never be able to decide what it runs. This file touches neither key,
// which is what keeps that separation structural rather than merely stated.
//
// ★ THE TYPE CHECK IS CONDITIONAL, AND HALF OF WHY HAS CHANGED. My first version required no type at all,
// on two reasons read out of the Edge. One of them is now gone and one is not:
//
//   - GONE: the plan used to be signed with the generic steer-policy type, so there was nothing plan-shaped
//     to compare against. It has its own type now (agentupdate.RolloutPlanEnvelopeType), and checking it is
//     worth more here than for the manifest — this is the document that carries a FREEZE, and without a type
//     of its own it was indistinguishable from an exclusion policy signed by the same key.
//   - STANDS: an Edge with no agent-policy signer still serves the plan payload UNSIGNED — a bare JSON
//     object, not an envelope. That branch is in the route today and it is a supported deployment.
//
// So a body that IS an envelope must carry the plan type, and a body that is not an envelope at all is
// accepted as the unsigned form. Requiring the type unconditionally would break every unsigned deployment,
// and break it in the worst direction: the previous plan stays on disk, and if it said frozen the fleet
// remains halted while the courier reports only a transport error.
//
// What neither branch gives up is the case the check exists for — a captive-portal HTML page or a truncated
// proxy response reaching the updater, where an unverifiable plan means FREEZE and a proxy error page would
// halt the fleet.
package main

import "github.com/lantern-networks/dsse-core/agentupdate"

// newPlanCourier builds the rollout-plan courier.
//
// The write function is injected by the caller, as for the manifest, so the atomic-rename dance stays in one
// Windows-only place.
func newPlanCourier(c *signedDocCourier) *signedDocCourier {
	c.name = "update-plan"
	c.path = updatePlanPath + "?platform=" + manifestPlatform + "&arch=" + manifestArch()
	c.envelopeType = agentupdate.RolloutPlanEnvelopeType
	// Signed OR unsigned: a body with no envelope type at all is the unsigned form this endpoint still serves
	// when the Edge has no agent-policy signer — and it has to say so, by carrying the plan's own schema name.
	// Naming the schema rather than setting a flag is what stops any JSON object at all being taken for the
	// unsigned form; see unsignedSchema in update_courier.go.
	c.unsignedSchema = agentupdate.RolloutPlanSchema
	return c
}

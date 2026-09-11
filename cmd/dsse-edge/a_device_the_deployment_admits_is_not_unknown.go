package main

import (
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// a_device_the_deployment_admits_is_not_unknown.go — an Edge that forgot a device must not answer 404 for one
// the deployment still admits.
//
// ★★★ MEASURED ON REAL HARDWARE (2026-08-26, win-dev-1 letter 113). A Windows box enrolled into this
// deployment heartbeated every fifteen seconds for two hours and was refused every time:
//
//	heartbeat: device "skusanagi-win10" is unknown to the Edge and --device-tenant is unset;
//	           refusing to self-register into an empty tenant.
//
// Meanwhile the SAME identity was in the deployment's enrolled inventory — durable, in Postgres, visible from
// all three control planes and from both enforcing Edges. Two stores, one authoritative and one not, and the
// one that answers the heartbeat is the one that is not.
//
// ★★ AND THE RUNTIME STORE IS memory BY DEFAULT, which is what makes this ordinary rather than rare. A
// generated deployment passes no -device-store, so every Edge restart empties it. The device is still
// admitted at the transport — its certificate is valid and the ledger admits it — so its traffic is carried
// and DECRYPTED while its heartbeat is refused. From the operator's side that machine does not exist; from
// the machine's side it is being inspected. Both are true and neither is visible from the other.
//
// ★ THE LEDGER IS THE AUTHORITY ON ADMISSION, AND THIS STORE IS A CACHE OF PRESENCE. So the answer is not to
// let the agent self-register — that would let a device choose its own organization, which is why the agent
// correctly refuses — but for the Edge to rebuild the cache entry from the record the deployment already
// holds. Nothing is decided here; the tenant and group come from the ledger.
//
// ★★ IT IS GATED ON A PROVEN IDENTITY. This runs only when the request arrived over the transport with a
// verified device certificate whose name IS the device being reported. Without that guard it would be
// self-registration wearing a different hat: anything that could reach the endpoint could conjure a device
// into an organization by naming it.

// rehydrateAdmittedDevice rebuilds the runtime record for a device the deployment admits, and reports whether
// it did. proven is the identity the transport verified, or empty when the caller did not present one.
func rehydrateAdmittedDevice(ledger *enrolledinventory.Ledger, store deviceRuntimeStore, proven, reported string,
	bundle model.PolicyBundle, now time.Time) (model.Device, bool) {

	proven, reported = strings.TrimSpace(proven), strings.TrimSpace(reported)
	if ledger == nil || store == nil || proven == "" || reported == "" || !strings.EqualFold(proven, reported) {
		return model.Device{}, false
	}
	if !ledger.IsAdmitted(reported) {
		// Not admitted is a real 404, and it must stay one: a device the deployment has removed is refused
		// here whatever certificate it still holds.
		return model.Device{}, false
	}
	entry, ok := ledger.EntryFor(reported)
	if !ok || strings.TrimSpace(entry.TenantID) == "" {
		// ★ AN ADMITTED DEVICE WITH NO ORGANIZATION IS NOT REBUILT INTO ONE. Guessing the node's tenant here
		// is how a device of one customer becomes a device of another.
		return model.Device{}, false
	}
	// The group is the ledger's — CP-authoritative, the same value cpAuthoritativeGroup reads — and it
	// selects the steer-exclusion set, so it must never come from the device.
	group, _ := ledger.GroupFor(reported)
	// The organization is the ledger's, not this node's: see the_organization_is_the_devices_not_the_pullers.go,
	// which the register and heartbeat handlers call for the same reason. The entry is already in hand here.
	forThisDevicesOrganization := bundleForTheDevicesOrganization(ledger, bundle, proven, reported)
	dev, err := store.Register(model.Device{
		ID:       reported,
		TenantID: strings.TrimSpace(entry.TenantID),
		Status:   "active",
		Metadata: map[string]any{"group": strings.TrimSpace(group)},
	}, forThisDevicesOrganization, now)
	if err != nil {
		log.Printf("device_rehydrate_failed device=%q tenant=%q: %v — this device is admitted by the "+
			"deployment and this Edge cannot record it, so its heartbeats will go on being refused",
			reported, entry.TenantID, err)
		return model.Device{}, false
	}
	// ★ SAID OUT LOUD, ONCE PER DEVICE. It means this Edge had lost its runtime record — which on a
	// deployment whose device store is in memory is every restart — and an operator watching a fleet go
	// quiet after a rebuild has otherwise nothing to read.
	log.Printf("device_rehydrated device=%q tenant=%q group=%q — this Edge had no runtime record for a device "+
		"the deployment admits (its enrolled inventory is the authority); rebuilt from it rather than "+
		"refusing the heartbeat", reported, dev.TenantID, strings.TrimSpace(group))
	return dev, true
}

// adminEnrolledDeviceCount is how many devices this organization HAS — the durable roster, which is what a
// licence counts and what an operator means by the word.
//
// ★ IT FALLS BACK TO PRESENCE RATHER THAN TO ZERO. A node with no ledger cannot answer the roster question,
// and answering it with 0 would say "this organization has no devices" — the very failure this replaces. The
// runtime count is at least a true statement about something.
func adminEnrolledDeviceCount(ledger *enrolledinventory.Ledger, tenantID string, present int) int {
	if ledger == nil {
		return present
	}
	return ledger.CountAdmitted(tenantID)
}

// adminEnrolledEndpointCount is the same number with the CONNECTORS taken out — the answer to "how many
// devices do I have", as opposed to "how many agents does this organization run".
//
// ★★★ THE TILE SAID 3 ABOUT ONE LAPTOP (2026-09-06). A connector enrols like a device and belongs in the
// ledger, so a count of the ledger counts it; the tile beside it counted the same two machines again as
// connectors, and the fleet breakdown filed them under "not reporting" and "Platform: Unknown", because a
// connector has no user, no OS and no steering state to report. One screen, two readings of the same
// machines, one of them alarming.
//
// The licence is deliberately NOT changed: it counts agents, a connector is an agent, and the number on the
// invoice must keep meaning what it means. This is the endpoint count, and only the endpoint count.
func adminEnrolledEndpointCount(ledger *enrolledinventory.Ledger, tenantID string, present int,
	connectors map[string]bool) int {
	admitted := adminEnrolledDeviceCount(ledger, tenantID, present)
	if ledger == nil || len(connectors) == 0 {
		return admitted
	}
	n := 0
	for _, e := range ledger.List() {
		if !e.Enabled {
			continue
		}
		if tenantID != "" && !strings.EqualFold(strings.TrimSpace(e.TenantID), strings.TrimSpace(tenantID)) {
			continue
		}
		if isConnectorIdentity(connectors, e.Identity) {
			n++
		}
	}
	if n > admitted {
		return admitted
	}
	return admitted - n
}

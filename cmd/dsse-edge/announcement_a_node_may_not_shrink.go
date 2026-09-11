package main

import (
	"strings"
)

// announcement_a_node_may_not_shrink.go — a node that is not on the per-organization material path may add to
// the fleet's announcement and may never remove from it.
//
// ★★★ TWO ANCHORS FLAPPED IN AND OUT OF THE SIGNED DISTRIBUTION, ALL DAY (2026-08-20, measured on the lab).
//
// region-a and region-b share one transport trust store — the same file, by design, because they are one
// fleet serving one set of devices. Only region-a fetches each organization's transport material from the
// control plane. So:
//
//	region-a: announcement gains tenant_reference_lab=7a4b2577 and tenant_northwind=ca15a827  (serial +1)
//	region-b: recomputes from what IT holds, both are absent, drops them                       (serial +1)
//	region-a: adds them back                                                                   (serial +1)
//
// Devices were told to trust their organization's new authority, then to stop, then to trust it again. The
// serial climbed on every restart with nothing actually changing. And the promotion gate that closes roadmap
// D's overlap measures adoption AT THE CURRENT SERIAL, so every flap threw away the evidence below it: the
// gate could never open, and the reason looked like slow devices.
//
// The fleet-promise guard admits region-b correctly — it holds an anchor for each organization, just the older
// one, which is the middle of an overlap and not a fault. The defect is not admission, it is that a node
// which cannot know what the fleet holds gets to say what the fleet holds.
//
// A node not on the material path cannot tell "this organization has no second authority" from "I was never
// given it". Absence of knowledge is not a withdrawal — the rule this repository has now applied to a device
// ledger, a tenant store, a revocation list and a trust bundle. So it keeps what it cannot produce.
//
// A withdrawal still works, and still comes from the node that CAN see the whole answer: on a node that
// fetches from the control plane, a fingerprint that is gone is gone, the announcement shrinks, the serial
// advances, and devices are told.
// sharedAnchorWithdrawnMarker is how an organization's bundle says it no longer names the deployment-wide
// anchor. It is a per-organization FACT, not a fingerprint, and only a node on the material path can produce
// it — which is why the keep-filter below has to carry it like one.
const sharedAnchorWithdrawnMarker = "shared-anchor-withdrawn"

func announcementKeepingWhatThisNodeCannotSee(computed []string, previouslyAnnounced string,
	thisNodeSeesEveryAuthority bool) []string {
	if thisNodeSeesEveryAuthority || strings.TrimSpace(previouslyAnnounced) == "" {
		return computed
	}
	have := map[string]bool{}
	for _, token := range computed {
		have[strings.TrimSpace(token)] = true
	}
	kept := append([]string{}, computed...)
	for _, token := range strings.Split(previouslyAnnounced, ",") {
		token = strings.TrimSpace(token)
		// Only the per-organization anchor tokens ("tenant=fingerprint"). Everything else in the string — the
		// names, the recovery SNI, the endpoint, the policy keyring — is this node's own answer about itself,
		// and the fleet-promise guard already refuses a node that cannot keep those.
		name, value, ok := strings.Cut(token, "=")
		value, name = strings.TrimSpace(value), strings.TrimSpace(name)
		if !ok || name == "" || strings.Contains(name, "@") || have[token] {
			continue
		}
		// ★★★ AND THE WITHDRAWAL, WHICH IS NOT 64 CHARACTERS LONG (2026-08-21, measured — a scale-out Edge
		// started for thirty minutes and roadmap D went backwards).
		//
		// The filter kept per-organization ANCHORS by testing for a 64-hex fingerprint. An organization that
		// has stopped naming the deployment-wide anchor says so with "tenant=shared-anchor-withdrawn", which
		// is twenty-two characters, so the test dropped it — and a node that cannot see the material erased a
		// withdrawal the fleet had already made. Measured on the running lab: win-dev-1 went from one anchor
		// to two and the serial advanced, because a temporary Edge existed for half an hour.
		//
		// This is the same lesson the export download tokens needed the night before, in a third place: a
		// merge may add what it does not know and must never undo what it was told to forget. Absence of
		// knowledge is not a withdrawal — and it is not an UN-withdrawal either.
		if len(value) != 64 && value != sharedAnchorWithdrawnMarker {
			continue
		}
		kept = append(kept, token)
	}
	return kept
}

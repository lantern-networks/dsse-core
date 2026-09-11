package main

// connector_runtime_facts_ride_every_poll.go — the facts about a connector that must reach the fleet without
// moving the deployment's config version.
//
// ★★★ THE VERSION DELIBERATELY DOES NOT MOVE FOR THESE, AND NOTHING ELSE CARRIED THEM (2026-08-26, measured).
// A connector failed over from region-b to region-a. The deployment's database knew. The node holding its
// tunnel knew. The two Edges of the region it LEFT went on answering "fronts this destination but has no live
// tunnel" — 0 of 10 flows to a private destination — because they only apply a bundle whose generation has
// advanced, and this fact is kept OUT of the generation on purpose.
//
// Keeping it out is right: a connector flapping between regions must not move the deployment's aggregate
// version, and a version that never settles closes every gate that waits for one. But "does not move the
// version" cannot also mean "never arrives".
//
// So the split is by AUTHORITY, not by convenience. The version governs configuration — what exists, what is
// authored, who may do what — and a bundle that does not advance it may change none of that. What rides every
// poll adds nothing, removes nothing, and renames nothing: it only updates where something ALREADY in this
// node's catalog is currently answering.

import "log"

// applyConnectorRuntimeFacts updates the runtime-only fields of connectors this node already has, from a
// bundle whose generation did not advance. A connector the catalog does not carry is ignored: arriving is a
// configuration change and belongs to the version.
func applyConnectorRuntimeFacts(payload configBundlePayload, t configApplyTargets) {
	if payload.Connectors == nil || t.connectors == nil {
		return
	}
	for _, conn := range payload.Connectors.Connectors {
		if conn.AttachedRegionID == "" {
			// ★ SILENCE IS NOT A REPORT. An authority that has never been told where a connector is attached
			// sends an empty field, and clearing on that would erase what this node already knows every time
			// it polls.
			continue
		}
		if _, known := t.connectors.Get(conn.ID); !known {
			continue
		}
		moved, err := t.connectors.RecordAttachedRegion(conn.ID, conn.AttachedRegionID)
		if err != nil {
			log.Printf("config-bundle sync: could not record where connector %s is attached (%s): %v",
				conn.ID, conn.AttachedRegionID, err)
			continue
		}
		if moved {
			log.Printf("connector_attached_region_learned connector=%s region=%s — the authority says this "+
				"connector is answering there now, so flows for what it fronts are routed there from here",
				conn.ID, conn.AttachedRegionID)
		}
	}
}

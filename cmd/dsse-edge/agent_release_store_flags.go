package main

import "flag"

// Where a control plane keeps what it has PUBLISHED and what each organization has been TOLD to run — in a
// sibling file because main.go's decomposition ratchet holds its flag count frozen.
//
// ★★★ THESE TWO HAD NO FLAG AT ALL, AND A DEPLOYMENT WITH TWO CONTROL PLANES NEEDS ONE (2026-08-28, measured
// on the two-region lab). Both were derived from -state-dir alone, so they were files on whichever node served
// the write: region-a's control plane held the catalogue, region-b's had no file, and an Edge polling the pair
// through the front door was answered 1 target, then 0, then 1. The operator had no way to move them, and the
// migration line durableStorePath prints named a flag that did not exist.
type agentReleaseStoreFlags struct {
	updates *string
	rollout *string
}

func registerAgentReleaseStoreFlags() agentReleaseStoreFlags {
	return agentReleaseStoreFlags{
		updates: flag.String("agent-updates-store", "",
			"durable store for the releases this control plane has PUBLISHED (the deployment's catalogue, plus "+
				"any per-organization shelf). `postgres` shares it across every control plane, which a deployment "+
				"with more than one requires: otherwise the node that served the publish is the only one that can "+
				"answer for it, and a fleet polling the front door reads \"nothing published\" every other minute. "+
				"postgres+import:<file> migrates a node that has been publishing to a file. A path keeps it on this "+
				"node. Empty = follow -state-dir"),
		rollout: flag.String("agent-rollout-store", "",
			"durable store for each organization's rollout plan — its desired version, its wave schedule and its "+
				"incident freeze. `postgres` shares it across every control plane; without that a halt reaches only "+
				"the node that was told, and an edge polling the pair is answered \"frozen\", then \"not frozen\", "+
				"which it cannot tell from the halt being lifted. A path keeps it on this node. Empty = follow "+
				"-state-dir"),
	}
}

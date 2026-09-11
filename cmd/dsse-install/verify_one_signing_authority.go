package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verify_one_signing_authority.go — does this deployment sign under ONE authority?
//
// ★★★ THE DEPLOYMENT THAT SILENTLY BECAME TWO (2026-08-25, measured).
//
// A second region was carried from the first and stood up. Everything a person looks at said it was fine:
// containers up, front door answering on 443, four Edges reporting to the control plane and agreeing on both
// regions. What it was actually doing, every ten seconds, was
//
//	config-bundle sync: pull failed (keeping config): config bundle signature verification failed
//	(rejecting tampered/untrusted config): verify against 1 accepted signing key(s)
//
// and applying nothing the control plane authored. The cause: the agent-policy signing key was not minted by
// the installer, it was minted by whichever node booted first, into the directory they share. Carried to
// another region before that happened, the copy had a hole — and the Edge's loader fills a hole by MINTING,
// so region B invented its own signing authority and announced it as enabled.
//
// The installer now mints that key with the deployment's other authorities, and -region refuses a carry that
// lacks it. This is the check for the deployment that is already running, and for the case neither of those
// covers: a node that was rebuilt, or given a key by hand, or pointed at the wrong directory.
//
// ★ IT COUNTS DISTINCT VALUES, NOT MISMATCHES AGAINST A CHOSEN ONE. Picking region A's key as the reference
// would make this a check on region B; the question is about the deployment, and the answer is a number.
//
// ★ AND A NODE THAT SIGNS NOTHING IS ITS OWN FINDING, not agreement. An operator who ran with
// -allow-unsigned-agent-policy has an Edge whose steer exclusions are not tamper-resistant; folding that into
// "one authority" would report the most permissive node in the fleet as a clean result.
func verifyOneSigningAuthority(client *http.Client, cpAdmin, token string) []verifyResult {
	out := []verifyResult{}
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, verifyResult{name: name, ok: ok, note: fmt.Sprintf(format, args...)})
	}

	code, raw, err := get(client, strings.TrimRight(cpAdmin, "/")+"/admin/fleet/config-status", token)
	if err != nil || code != 200 {
		// ★ SAID OUT LOUD RATHER THAN RETURNED EMPTY. A check that produces no line when it could not run
		// reads, in a list of forty, exactly like a check that passed — and this is the check whose whole
		// subject is a deployment that looks fine.
		add("the deployment signs under one authority", false,
			"could not read the fleet view at %s (%d, %v) — this question was NOT measured",
			strings.TrimRight(cpAdmin, "/"), code, err)
		return out
	}
	var fleet struct {
		// ★ THE DENOMINATOR COMES WITH THE ANSWER (2026-08-25). A control plane that has just been promoted
		// holds only the reports that reached it since; measured fifteen seconds after a failover, the view
		// carried two of four Edges and called them in sync. Asking "does the deployment sign under ONE
		// authority" of half a fleet answers yes for the wrong reason, which is what this check did on its
		// first run.
		Formed *bool `json:"fleet_view_formed"`
		Edges  []struct {
			RegionID   string `json:"region_id"`
			ClusterID  string `json:"cluster_id"`
			NodeID     string `json:"node_id"`
			SigningKey string `json:"policy_signing_key"`
		} `json:"edges"`
	}
	if json.Unmarshal(raw, &fleet) != nil {
		add("the deployment signs under one authority", false,
			"the fleet view at %s did not parse — this question was NOT measured", strings.TrimRight(cpAdmin, "/"))
		return out
	}
	if fleet.Formed != nil && !*fleet.Formed {
		add("the deployment signs under one authority", false,
			"the authority's view of the fleet is still forming (it has %d node(s) so far), so a node that "+
				"has not reported is indistinguishable from one that is gone — this question was NOT "+
				"measured. Ask again shortly", len(fleet.Edges))
		return out
	}
	if len(fleet.Edges) == 0 {
		// No node has reported yet. Not a failure — there is nothing to disagree — but it must not be
		// counted as agreement either, so it says which it is.
		add("the deployment signs under one authority", true,
			"no Edge has reported to the authority yet, so there is nothing to compare")
		return out
	}
	// The narrowed projection a customer receives carries no node facts, so it cannot answer this. Saying so
	// is the point: a check that silently reports nothing looks the same as a check that passed.
	if !operatorScopedSigning(raw) {
		add("the deployment signs under one authority", false,
			"this answer carries no node facts, so which authority each Edge signs under was NOT measured — "+
				"ask with an operator credential")
		return out
	}

	byKey := map[string][]string{}
	unsigned := []string{}
	for _, n := range fleet.Edges {
		where := strings.TrimSpace(n.RegionID + "/" + n.ClusterID)
		if where == "/" || where == "" {
			where = n.NodeID
		}
		key := strings.ToLower(strings.TrimSpace(n.SigningKey))
		if key == "" {
			unsigned = append(unsigned, where)
			continue
		}
		byKey[key] = append(byKey[key], where)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	switch {
	case len(keys) == 0:
		add("the deployment signs under one authority", false,
			"%d Edge(s) sign agent policy with NO key at all (%s) — their steer exclusions are not "+
				"tamper-resistant, and they accept an unsigned config bundle",
			len(unsigned), strings.Join(unsigned, ", "))
	case len(keys) == 1 && len(unsigned) == 0:
		add("the deployment signs under one authority", true,
			"%d Edge(s) all sign under %s…", len(byKey[keys[0]]), shortKey(keys[0]))
	case len(keys) == 1:
		add("the deployment signs under one authority", false,
			"%d Edge(s) sign under %s… but %d sign NOTHING (%s) — those hand out steer exclusions no device "+
				"can verify", len(byKey[keys[0]]), shortKey(keys[0]), len(unsigned), strings.Join(unsigned, ", "))
	default:
		// ★★★ THIS IS THE ONE. Two authorities means the config bundle one half authors is refused by the
		// other half, and a device enrolled on the wrong side is served policy signed by a key it has never
		// pinned. Both halves report healthy, so the message has to say what to DO.
		parts := []string{}
		for _, k := range keys {
			nodes := byKey[k]
			sort.Strings(nodes)
			parts = append(parts, fmt.Sprintf("%s… ← %s", shortKey(k), strings.Join(nodes, ", ")))
		}
		add("the deployment signs under one authority", false,
			"★★★ THIS DEPLOYMENT HAS %d SIGNING AUTHORITIES: %s. One of them authors the config bundle and "+
				"the others REFUSE it, applying nothing, while every view reports healthy. Carry "+
				"agent-policy-signing.key from the region that holds the authority the control plane signs "+
				"with, replace it on the others, and restart their Edges — a device already enrolled on a "+
				"minority key must re-pin",
			len(keys), strings.Join(parts, " | "))
	}
	return out
}

func shortKey(hexKey string) string {
	if len(hexKey) <= 16 {
		return hexKey
	}
	return hexKey[:16]
}

// operatorScopedSigning reports whether this answer carried node facts at all — the same distinction
// who_depends.go draws, and for the same reason: a customer's projection is deliberately silent about nodes,
// and silence must not be read as agreement.
//
// ★ IT READS THE BODY THE SERVER SENT, NOT THE STRUCT WE DECODED INTO. Re-marshalling the decoded value
// answers a question about this file's own field tags: node_id is present there whatever arrived, so the
// check would pass on every answer including the one it exists to catch.
func operatorScopedSigning(raw []byte) bool {
	return strings.Contains(string(raw), `"node_id"`) || strings.Contains(string(raw), `"cluster_id"`)
}

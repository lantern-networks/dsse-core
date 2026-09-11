package agentupdate

// key_separation.go — the key that authorises RUNNING CODE must not also authorise the rollout plan.

import "strings"

// SeparatePlanKeys drops any plan-signing key that is also an update-signing key, and reports what it dropped.
//
// ★★ WHY IT IS HERE AND NOT IN A CLIENT (2026-08-13, thirty-first review #9). The rule existed in ONE lane of
// ONE platform: macOS applied it to keys ADOPTED from the trust bundle. Three ways past it remained open —
// --plan-pin skipped the check entirely, a config-supplied plan key was never compared against a flag-supplied
// update key, and Windows did not implement the rule at all — so `--update-pin X --plan-pin X` was still
// expressible on both agents. Two previous rounds recorded this pairing as closed.
//
// What it costs to get wrong: the plan carries the FREEZE. One key for both means the party a halt exists to
// stop is the party who signs the halt, so a compromised release key can publish a bad build AND lift the
// stop. That is the whole reason these are two keys.
//
// ★ THE PLAN KEY IS DROPPED, NOT THE UPDATE KEY, and the asymmetry is deliberate. Refusing the update key
// would leave a device unable to update at all, which is the state this product spent weeks escaping; dropping
// the plan key leaves the device unable to VERIFY a plan, which LoadRollout already has an answer for. And a
// device left with no plan key at all is a state the caller already reports.
func SeparatePlanKeys(updateKeys, planKeys []string) (kept []string, refused []string) {
	for _, p := range planKeys {
		if containsFold(updateKeys, p) {
			refused = append(refused, p)
			continue
		}
		kept = append(kept, p)
	}
	return kept, refused
}

func containsFold(xs []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, x := range xs {
		if strings.EqualFold(strings.TrimSpace(x), want) {
			return true
		}
	}
	return false
}

package decision

import "github.com/lantern-networks/dsse-core/model"

// PolicyTraceEntry is one policy in the precedence-ordered decision basis for a request: whether it matched,
// whether it won, and — if it matched but did not win — that it was shadowed by a higher-precedence policy.
// It is the per-policy row of an Effective-Policy ("Why") view: the operator can see not only the winner but
// every authored rule and built-in policy that competed, in the exact order the engine evaluates them.
type PolicyTraceEntry struct {
	PolicyID          string   `json:"policy_id"`
	Name              string   `json:"name,omitempty"`
	Priority          int      `json:"priority"`
	Decision          string   `json:"decision"`
	Status            string   `json:"status"`
	Matched           bool     `json:"matched"`
	MatchedConditions []string `json:"matched_conditions,omitempty"`
	Winner            bool     `json:"winner"`               // first match in precedence order
	Shadowed          bool     `json:"shadowed"`             // matched, but a higher-precedence policy won
	CreatedBy         string   `json:"created_by,omitempty"` // authored-by attribution when present (provenance tagging is layered above)
}

// DecisionExplanation is the precedence-ordered policy basis for a request: every policy in evaluation order,
// which matched, which won, and the authoritative final decision. FinalDecision may differ from the winning
// policy's decision when a runtime overlay (e.g. an authentication-max-age step-up)
// changes it — so a caller can see both "which policy won the precedence race" and "what the edge ultimately
// decided". This is the engine primitive behind the Effective-Policy view and per-flow "Why does this flow get
// decision X?" explanation; provenance tagging (authored / built-in / hardcoded) is layered above this in the
// edge, which knows where each policy came from.
type DecisionExplanation struct {
	ActorType      string             `json:"actor_type"`
	Trace          []PolicyTraceEntry `json:"trace"`
	WinnerPolicyID string             `json:"winner_policy_id"` // empty when no policy matched (default deny)
	WinnerDecision string             `json:"winner_decision"`
	FinalDecision  string             `json:"final_decision"`
	FinalPolicyID  string             `json:"final_policy_id"`
}

// OrderedPolicies returns a copy of the full policy set in the exact precedence order the engine evaluates
// them (lowest priority number first; ties broken by restrictiveness then ID). This is the standing "all
// policies" basis behind a full Effective-Policy listing — every policy, authored or built-in, surfaced rather
// than discoverable only per-destination.
func (e Evaluator) OrderedPolicies() []model.Policy {
	return e.orderedPolicies()
}

// ExplainDecision returns the precedence-ordered policy basis for a request without changing how Evaluate
// decides: it walks the SAME ordered policy set Evaluate uses (orderedPolicies) and reports, for each policy,
// whether it matched and whether it won, marking shadowed matches (matched but out-precedenced). The request is
// enriched with SaaS context first so matching mirrors Evaluate exactly (e.g. saas_application_id
// classification). FinalDecision/FinalPolicyID come from a real Evaluate call, so any runtime overlay that
// overrides the winning policy is reflected. Read-only.
func (e Evaluator) ExplainDecision(req model.DecisionRequest) DecisionExplanation {
	enriched := e.decisionRequestWithSaaSContext(req)
	actorType := valueOrDefault(enriched.ActorType, "human")

	ordered := e.orderedPolicies()
	exp := DecisionExplanation{ActorType: actorType, Trace: make([]PolicyTraceEntry, 0, len(ordered))}
	winnerFound := false
	for _, policy := range ordered {
		matched, names := matchPolicy(policy, enriched, actorType)
		entry := PolicyTraceEntry{
			PolicyID:          policy.ID,
			Name:              policy.Name,
			Priority:          policy.Priority,
			Decision:          policy.Action.Decision,
			Status:            policy.Status,
			Matched:           matched,
			MatchedConditions: names,
		}
		if policy.CreatedBy != nil {
			entry.CreatedBy = *policy.CreatedBy
		}
		if matched {
			if !winnerFound {
				entry.Winner = true
				winnerFound = true
				exp.WinnerPolicyID = policy.ID
				exp.WinnerDecision = policy.Action.Decision
			} else {
				entry.Shadowed = true
			}
		}
		exp.Trace = append(exp.Trace, entry)
	}

	final := e.Evaluate(req)
	exp.FinalDecision = final.Decision
	exp.FinalPolicyID = final.PolicyID
	return exp
}

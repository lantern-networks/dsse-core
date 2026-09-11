package dlp

// Action is the enforcement action a DLP rule applies when its identifiers are present.
type Action string

const (
	// ActionObserve records a dlp_match event but never alters or blocks traffic.
	ActionObserve Action = "observe"
	// ActionWarn records a match as WARNED — the upload is still allowed (non-interrupting), but the finding is
	// flagged as "would be blocked". It is the middle rung of the reversible ramp observe → warn → block: an
	// operator watches what a block WOULD stop before turning it on. Non-interrupting, like observe.
	ActionWarn Action = "warn"
	// ActionBlock denies the request before the detected secret leaves the perimeter (hold-before-release).
	ActionBlock Action = "block"
	// ActionAuthenticate interrupts the upload for step-up authentication before the secret leaves.
	ActionAuthenticate Action = "authenticate"
)

// KnownAction reports whether a is a supported DLP action (used to validate policy input).
func KnownAction(a Action) bool {
	switch a {
	case ActionObserve, ActionWarn, ActionBlock, ActionAuthenticate:
		return true
	default:
		return false
	}
}

// interrupts reports whether an action must hold the stream (block/authenticate both prevent the secret from
// being released; observe and warn do not).
func (a Action) interrupts() bool { return a == ActionBlock || a == ActionAuthenticate }

// Rule is one per-tenant DLP rule: if the body contains at least MinCount of ANY listed identifier, Action
// applies. Scope (optional app/destination/group narrowing) is reserved for the handler layer; the engine
// evaluates content only.
type Rule struct {
	ID          string           `json:"id"`
	Name        string           `json:"name,omitempty"`
	Identifiers []IdentifierType `json:"identifiers"`
	MinCount    int              `json:"min_count,omitempty"`
	Action      Action           `json:"action"`
}

// threshold is the effective per-identifier count at which the rule fires (MinCount<1 means 1).
func (r Rule) threshold() int {
	if r.MinCount < 1 {
		return 1
	}
	return r.MinCount
}

// Policy is a tenant's DLP rule set.
type Policy struct {
	TenantID string `json:"tenant_id"`
	Version  string `json:"version,omitempty"`
	Rules    []Rule `json:"rules"`
}

// actionRank orders actions by strength so the strongest triggered action wins.
func actionRank(a Action) int {
	switch a {
	case ActionBlock:
		return 4
	case ActionAuthenticate:
		return 3
	case ActionWarn:
		return 2
	case ActionObserve:
		return 1
	default:
		return 0
	}
}

// Decide returns the strongest action triggered by the given per-identifier counts and the id of the rule
// that triggered it. If no rule fires it returns ("", ""). A rule fires when counts[id] >= its threshold for
// any of its identifiers.
func (p Policy) Decide(counts map[IdentifierType]int) (Action, string) {
	best := Action("")
	bestRule := ""
	for _, rule := range p.Rules {
		th := rule.threshold()
		fired := false
		for _, id := range rule.Identifiers {
			if counts[id] >= th {
				fired = true
				break
			}
		}
		if fired && actionRank(rule.Action) > actionRank(best) {
			best = rule.Action
			bestRule = rule.ID
		}
	}
	return best, bestRule
}

// TripThresholds returns, for identifiers governed by an interrupting rule (block/authenticate), the smallest
// count at which the stream must be held. A GuardReader uses this to stop before a secret is released. An
// empty result means no rule interrupts and observe (tee) is sufficient. Only identifiers whose STRONGEST
// applicable action interrupts are included, so an observe rule can't force a needless hold.
func (p Policy) TripThresholds() map[IdentifierType]int {
	strongest := map[IdentifierType]Action{}
	// minInterruptCount is the smallest threshold among the INTERRUPTING rules only. Taking the min over
	// ALL rules (incl. observe/warn) let a low-threshold observe rule drag the guard's trip point below the
	// interrupting rule's own threshold — so the GuardReader held (over-blocked) a stream at a count the
	// operator only chose to OBSERVE, not block (review #19). The guard must trip at the interrupting
	// rule's threshold, never an observe rule's.
	minInterruptCount := map[IdentifierType]int{}
	for _, rule := range p.Rules {
		th := rule.threshold()
		interrupts := rule.Action.interrupts()
		for _, id := range rule.Identifiers {
			if actionRank(rule.Action) > actionRank(strongest[id]) {
				strongest[id] = rule.Action
			}
			if interrupts {
				if cur, ok := minInterruptCount[id]; !ok || th < cur {
					minInterruptCount[id] = th
				}
			}
		}
	}
	trip := map[IdentifierType]int{}
	for id, act := range strongest {
		if act.interrupts() {
			trip[id] = minInterruptCount[id]
		}
	}
	return trip
}

// Interrupts reports whether the policy has any block/authenticate rule (i.e. needs a GuardReader).
func (p Policy) Interrupts() bool { return len(p.TripThresholds()) > 0 }

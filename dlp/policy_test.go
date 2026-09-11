package dlp

import "testing"

func TestPolicyDecidePrecedence(t *testing.T) {
	p := Policy{Rules: []Rule{
		{ID: "observe-cc", Identifiers: []IdentifierType{CreditCard}, Action: ActionObserve},
		{ID: "block-mynum", Identifiers: []IdentifierType{MyNumber}, Action: ActionBlock},
		{ID: "auth-key", Identifiers: []IdentifierType{APIKey}, Action: ActionAuthenticate},
	}}

	// Block wins over authenticate/observe when several fire.
	act, rule := p.Decide(map[IdentifierType]int{MyNumber: 1, APIKey: 1, CreditCard: 1})
	if act != ActionBlock || rule != "block-mynum" {
		t.Errorf("Decide = (%q,%q), want (block, block-mynum)", act, rule)
	}
	// Authenticate wins over observe.
	if act, _ := p.Decide(map[IdentifierType]int{APIKey: 1, CreditCard: 1}); act != ActionAuthenticate {
		t.Errorf("Decide = %q, want authenticate", act)
	}
	// Nothing fires.
	if act, _ := p.Decide(map[IdentifierType]int{}); act != "" {
		t.Errorf("Decide = %q, want empty", act)
	}
}

func TestKnownAction(t *testing.T) {
	for _, a := range []Action{ActionObserve, ActionWarn, ActionBlock, ActionAuthenticate} {
		if !KnownAction(a) {
			t.Errorf("KnownAction(%q) = false, want true", a)
		}
	}
	if KnownAction(Action("nope")) {
		t.Errorf("KnownAction(nope) = true, want false")
	}
}

func TestPolicyWarnIsNonInterruptingButBeatsObserve(t *testing.T) {
	// Warn allows the upload (does NOT interrupt) but outranks observe, so a warn rule is recorded as "warn".
	p := Policy{Rules: []Rule{
		{ID: "obs", Identifiers: []IdentifierType{Email}, Action: ActionObserve},
		{ID: "warn", Identifiers: []IdentifierType{MyNumber}, Action: ActionWarn},
	}}
	if act, rule := p.Decide(map[IdentifierType]int{MyNumber: 1, Email: 1}); act != ActionWarn || rule != "warn" {
		t.Fatalf("warn must win over observe; got %q/%q", act, rule)
	}
	if p.Interrupts() {
		t.Fatalf("a warn/observe-only policy must NOT interrupt (no GuardReader / no hold)")
	}
	if len(p.TripThresholds()) != 0 {
		t.Fatalf("warn must not contribute a trip threshold (it never holds the stream)")
	}
}

func TestPolicyDecideThreshold(t *testing.T) {
	p := Policy{Rules: []Rule{{ID: "r", Identifiers: []IdentifierType{CreditCard}, MinCount: 3, Action: ActionBlock}}}
	if act, _ := p.Decide(map[IdentifierType]int{CreditCard: 2}); act != "" {
		t.Errorf("below threshold fired: %q", act)
	}
	if act, _ := p.Decide(map[IdentifierType]int{CreditCard: 3}); act != ActionBlock {
		t.Errorf("at threshold did not fire: %q", act)
	}
}

func TestPolicyTripThresholds(t *testing.T) {
	p := Policy{Rules: []Rule{
		{ID: "observe-cc", Identifiers: []IdentifierType{CreditCard}, Action: ActionObserve},
		{ID: "block-mynum", Identifiers: []IdentifierType{MyNumber}, MinCount: 2, Action: ActionBlock},
	}}
	trip := p.TripThresholds()
	if _, ok := trip[CreditCard]; ok {
		t.Errorf("observe-only identifier must not force a hold")
	}
	if trip[MyNumber] != 2 {
		t.Errorf("my_number trip = %d, want 2", trip[MyNumber])
	}
	if !p.Interrupts() {
		t.Errorf("Interrupts = false, want true")
	}
	if (Policy{Rules: []Rule{{Identifiers: []IdentifierType{MyNumber}, Action: ActionObserve}}}).Interrupts() {
		t.Errorf("observe-only policy must not interrupt")
	}
}

// Review #19: the guard's trip point must be the INTERRUPTING rule's threshold, never a lower-threshold
// observe/warn rule on the same identifier. Taking the min over all rules made the GuardReader hold a stream
// at a count the operator only chose to observe.
func TestPolicyTripThresholdsIgnoresLowerObserveThreshold(t *testing.T) {
	p := Policy{Rules: []Rule{
		// A low-threshold OBSERVE rule and a higher-threshold BLOCK rule on the same identifier.
		{ID: "observe-cc-1", Identifiers: []IdentifierType{CreditCard}, MinCount: 1, Action: ActionObserve},
		{ID: "block-cc-5", Identifiers: []IdentifierType{CreditCard}, MinCount: 5, Action: ActionBlock},
	}}
	trip := p.TripThresholds()
	if trip[CreditCard] != 5 {
		t.Fatalf("trip = %d, want 5 (the interrupting rule's threshold, not the observe rule's 1)", trip[CreditCard])
	}
	// Below the block threshold the policy must NOT block, even though the observe rule fired at 1.
	if act, _ := p.Decide(map[IdentifierType]int{CreditCard: 3}); act.interrupts() {
		t.Fatalf("count 3 must not interrupt (block threshold is 5), got %q", act)
	}
	if act, _ := p.Decide(map[IdentifierType]int{CreditCard: 5}); act != ActionBlock {
		t.Fatalf("count 5 must block, got %q", act)
	}
}

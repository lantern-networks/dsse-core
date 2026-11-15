package decision

import (
	"encoding/json"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// A flow to a registered network — one a Connector route carries — is Connector Access in every posture. The
// posture says what Connector Access does with the flow; it does not hand the flow to the Internet Access rules.

func connectorFlow() model.DecisionRequest {
	req := eastWestRequest("u1", "app.internal.example", "https")
	req.DestinationPort = 443
	req.ConnectorRouteVerified = true
	req.ConnectorFlowFromDevice = true
	return req
}

func internetRuleThatDeniesEverything() model.Policy {
	return model.Policy{
		ID: "internet-deny-all", TenantID: "tenant_test", Name: "deny all", Status: "active", Priority: 1,
		Action: model.PolicyAction{Decision: "deny"},
	}
}

func TestWhileObservingAConnectorFlowIsDecidedAndRecordedByConnectorAccess(t *testing.T) {
	e := eastWestEvaluator(false)
	e.Policies = append(e.Policies, internetRuleThatDeniesEverything())

	// The control: the Internet Access rule does decide a flow no Connector route carries.
	if dec := e.Evaluate(eastWestRequest("u1", "example.com", "https")); dec.Decision != "deny" || dec.PolicyID != "internet-deny-all" {
		t.Fatalf("the Internet Access rule did not decide an internet flow: %s via %q — this test would prove nothing", dec.Decision, dec.PolicyID)
	}

	dec := e.Evaluate(connectorFlow())
	if dec.Decision != "allow" {
		t.Fatalf("observing: decision = %s (%v), want allow", dec.Decision, dec.ReasonCodes)
	}
	if dec.PolicyID != EastWestPolicyClassID {
		t.Fatalf("observing: the row names %q, want Connector Access (%q)", dec.PolicyID, EastWestPolicyClassID)
	}
	if !hasReasonCode(dec.ReasonCodes, "east_west_observe") {
		t.Fatalf("observing: reason codes = %v, want east_west_observe", dec.ReasonCodes)
	}
	if !IsConnectorAccessDecision(dec) {
		t.Fatalf("observing: the decision does not say Connector Access made it: %v", dec.Metadata)
	}
	if logged, _ := dec.Metadata["log_traffic"].(bool); !logged {
		t.Fatalf("observing: an allowed connection to a private application asks for no access-log row: %v", dec.Metadata)
	}
	if got := dec.Metadata["east_west_posture"]; got != "observe" {
		t.Fatalf("posture recorded as %v, want observe", got)
	}
}

func TestWhileObservingALateralProtocolNoConnectorCarriesStaysWithTheInternetAccessRules(t *testing.T) {
	e := eastWestEvaluator(false)
	e.Policies = append(e.Policies, internetRuleThatDeniesEverything())
	dec := e.Evaluate(eastWestRequest("u1", "10.9.8.7", "ssh"))
	if dec.Decision != "deny" || dec.PolicyID != "internet-deny-all" {
		t.Fatalf("an operator's rule stopped applying because Connector Access is only observing: %s via %q", dec.Decision, dec.PolicyID)
	}
}

// Observing lets through what an enrolled device sends. A browser asking the Portal for a published application
// has not been identified as any device, and while Connector Access observes, the application's own policy
// admits it or nothing does.
func TestWhileObservingABrowsersRequestForAPublishedApplicationIsNotLetThrough(t *testing.T) {
	e := eastWestEvaluator(false)
	req := connectorFlow()
	req.ConnectorFlowFromDevice = false
	if dec := e.Evaluate(req); dec.Decision == "allow" || IsConnectorAccessDecision(dec) {
		t.Fatalf("a visitor was let into a private application because Connector Access is observing: %s via %q %v", dec.Decision, dec.PolicyID, dec.ReasonCodes)
	}
	e.Policies = append(e.Policies, model.Policy{ID: "app-policy", TenantID: "tenant_test", Status: "active", Priority: 1, Action: model.PolicyAction{Decision: "allow"}})
	if dec := e.Evaluate(req); dec.Decision != "allow" || dec.PolicyID != "app-policy" {
		t.Fatalf("the application's own policy did not decide: %s via %q", dec.Decision, dec.PolicyID)
	}
}

func TestAConnectorAccessRowNamesTheRuleThatDecided(t *testing.T) {
	rule := EastWestRule{ID: "rule-finance-app", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: EastWestModeAllow}
	e := eastWestEvaluator(true, rule)
	if dec := e.Evaluate(connectorFlow()); dec.Decision != "allow" || dec.PolicyID != "rule-finance-app" {
		t.Fatalf("matched rule: %s via %q, want allow via the rule's own id", dec.Decision, dec.PolicyID)
	}
	other := connectorFlow()
	other.Destination = "other.internal.example"
	if dec := e.Evaluate(other); dec.Decision != "deny" || dec.PolicyID != EastWestPolicyClassID {
		t.Fatalf("no rule matched: %s via %q, want deny via %q", dec.Decision, dec.PolicyID, EastWestPolicyClassID)
	}
}

func TestARequestInsideAConnectionThatSignedInIsNotAskedToSignInAgain(t *testing.T) {
	authenticate := EastWestRule{ID: "rule-signin", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: EastWestModeAuthenticate, MaxAgeSecondsSet: true}
	e := eastWestEvaluator(true, authenticate)

	atOpen := e.Evaluate(connectorFlow())
	if atOpen.Decision != "authenticate_required" {
		t.Fatalf("when the connection opens the rule must ask for sign-in; got %s", atOpen.Decision)
	}
	inside := connectorFlow()
	inside.ConnectorSignInDoneForRule = "rule-signin"
	dec := e.Evaluate(inside)
	if dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_connection_authenticated") || dec.PolicyID != "rule-signin" {
		t.Fatalf("inside the connection: %s %v via %q", dec.Decision, dec.ReasonCodes, dec.PolicyID)
	}
	if len(dec.Actions) != 0 {
		t.Fatalf("an allowed request still carries a sign-in action: %+v", dec.Actions)
	}

	// A rule that denies is not softened by the connection having been opened.
	deny := EastWestRule{ID: "rule-deny", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: EastWestModeDeny}
	if dec := eastWestEvaluator(true, deny).Evaluate(inside); dec.Decision != "deny" {
		t.Fatalf("a deny rule let a request through inside an open connection: %s", dec.Decision)
	}
	// Nor is the default when nothing matches.
	if dec := eastWestEvaluator(true).Evaluate(inside); dec.Decision != "deny" {
		t.Fatalf("full enforcement let an unmatched request through inside an open connection: %s", dec.Decision)
	}
}

func TestARequestBodyCannotClaimAConnectorMark(t *testing.T) {
	var req model.DecisionRequest
	body := `{"tenant_id":"t","ConnectorRouteVerified":true,"connector_route_verified":true,"ConnectorSignInDoneForRule":"r","connector_sign_in_done_for_rule":"r","ConnectorFlowFromDevice":true,"connector_flow_from_device":true}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.ConnectorRouteVerified || req.ConnectorSignInDoneForRule != "" || req.ConnectorFlowFromDevice {
		t.Fatalf("a client moved its request to Connector Access by claiming it: %+v", req)
	}
}

// Review finding (2026-11-14): "the connection was let through" was taken as "the sign-in was done". A device
// connects by address under a plain allow; its first request names a host a different rule guards with a
// sign-in. Nothing has been proved about that rule.
func TestAConnectionLetThroughByOneRuleHasNotSignedInForAnother(t *testing.T) {
	allowByAddress := EastWestRule{ID: "rule-allow-address", Priority: 10, Destinations: []string{"10.20.30.40"}, Mode: EastWestModeAllow}
	signInForHost := EastWestRule{ID: "rule-signin-host", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: EastWestModeAuthenticate, RequiredAMR: []string{"phishing_resistant"}}
	e := eastWestEvaluator(true, allowByAddress, signInForHost)

	atOpen := connectorFlow()
	atOpen.Destination = "10.20.30.40"
	opened := e.Evaluate(atOpen)
	if opened.Decision != "allow" || opened.PolicyID != "rule-allow-address" {
		t.Fatalf("the connection by address: %s via %q", opened.Decision, opened.PolicyID)
	}
	if got := ConnectorSignInDoneForRule(opened); got != "" {
		t.Fatalf("a plain allow is reported as a completed sign-in for %q", got)
	}
	firstRequest := connectorFlow() // names the host
	firstRequest.ConnectorSignInDoneForRule = ConnectorSignInDoneForRule(opened)
	if dec := e.Evaluate(firstRequest); dec.Decision != "authenticate_required" || dec.PolicyID != "rule-signin-host" {
		t.Fatalf("the first request for the guarded host: %s %v via %q, want the sign-in asked for", dec.Decision, dec.ReasonCodes, dec.PolicyID)
	}
	// Evidence for one rule is not evidence for another either.
	firstRequest.ConnectorSignInDoneForRule = "rule-some-other-signin"
	if dec := e.Evaluate(firstRequest); dec.Decision != "authenticate_required" {
		t.Fatalf("a sign-in for another rule satisfied this one: %s", dec.Decision)
	}
	// And observing proves nothing.
	observed := eastWestEvaluator(false).Evaluate(connectorFlow())
	if got := ConnectorSignInDoneForRule(observed); got != "" {
		t.Fatalf("an observed flow is reported as a completed sign-in for %q", got)
	}
	// What does count: the decision that asked for this rule's sign-in, for a flow then let through.
	asked := eastWestEvaluator(true, signInForHost).Evaluate(connectorFlow())
	if got := ConnectorSignInDoneForRule(asked); got != "rule-signin-host" {
		t.Fatalf("the rule whose sign-in was asked for is reported as %q", got)
	}
}

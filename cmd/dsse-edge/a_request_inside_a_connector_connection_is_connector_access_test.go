package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// A flow to a registered network is Connector Access, and so is each request read out of it after decryption.
// The handler that decides those requests used to ask the Internet Access rules, so one visit to a private
// application was decided by two planes and its rows named an Internet Access rule.
func TestARequestReadOutOfAConnectorConnectionIsDecidedByConnectorAccess(t *testing.T) {
	const tenant = "tenant-connector-plane"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	visit := func(t *testing.T, insideAConnectorConnection bool) (int, model.AccessDecision) {
		t.Helper()
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		decisions := newAccessDecisionStore()
		handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				PolicyBundle: model.PolicyBundle{TenantID: tenant},
				// Connector Access is observing (the posture a new organization starts in), and the only
				// Internet Access rule denies everything.
				Policies: []model.Policy{{ID: "internet-deny-all", TenantID: tenant, Status: "active", Priority: 1,
					Action: model.PolicyAction{Decision: "deny"}}},
			},
			Writer: writer, DecisionStore: decisions, InspectionEvents: newInspectionEventStore(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			DeviceAuthenticatedInProcess: true,
		})
		req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://app.internal.example/")
		if insideAConnectorConnection {
			req = req.WithContext(edgeplane.WithConnectorAccessAtOpen(req.Context()))
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		made := decisions.SnapshotByTenant(tenant)
		if len(made) != 1 {
			t.Fatalf("status %d: %d decision(s) recorded, want 1", rec.Code, len(made))
		}
		return rec.Code, made[0]
	}

	t.Run("a request in any other connection is decided by the Internet Access rules", func(t *testing.T) {
		code, dec := visit(t, false)
		if code == http.StatusOK || dec.Decision != "deny" || dec.PolicyID != "internet-deny-all" {
			t.Fatalf("status %d, %s via %q — the Internet Access rule is not deciding, so the case below proves nothing", code, dec.Decision, dec.PolicyID)
		}
	})
	t.Run("a request inside a connector connection is decided by Connector Access", func(t *testing.T) {
		code, dec := visit(t, true)
		if code != http.StatusOK {
			t.Fatalf("status %d (%s via %q), want the request forwarded", code, dec.Decision, dec.PolicyID)
		}
		if dec.Decision != "allow" || dec.PolicyID != decision.EastWestPolicyClassID || !decision.IsConnectorAccessDecision(dec) {
			t.Fatalf("%s via %q %v, want allow by Connector Access", dec.Decision, dec.PolicyID, dec.ReasonCodes)
		}
	})
}

// Review finding (2026-11-14): the request was given the flow organization's name and judged by this node's
// Connector Access settings. A customer's connection, allowed when it opened by the customer's rule, was
// refused at its first request by "nothing matched" in the node's own organization.
func TestARequestInsideAConnectorConnectionIsJudgedByItsOwnOrganizationsRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore(nil)
	for _, tenant := range []string{"node", "customer"} {
		store.SetEastWestEnabled(tenant, true) // full enforcement in both
	}
	store.SetCompiledEastWestRules("customer", []decision.EastWestRule{{
		ID: "customer-allow", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: decision.EastWestModeAllow,
	}})
	visit := func(t *testing.T, flowTenant string) (int, model.AccessDecision) {
		t.Helper()
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		decisions := newAccessDecisionStore()
		handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
			Evaluator:   decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "node"}},
			PolicyStore: store,
			Writer:      writer, DecisionStore: decisions, InspectionEvents: newInspectionEventStore(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			DeviceAuthenticatedInProcess: true,
		})
		req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://app.internal.example/")
		req = req.WithContext(edgeplane.WithConnectorAccessAtOpen(edgeplane.WithFlowTenant(req.Context(), flowTenant)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		made := decisions.SnapshotByTenant(flowTenant)
		if len(made) != 1 {
			t.Fatalf("status %d: %d decision(s) recorded for %s, want 1", rec.Code, len(made), flowTenant)
		}
		return rec.Code, made[0]
	}
	// The control: this node's own organization has no rule for the application, and full enforcement denies.
	if code, dec := visit(t, "node"); code == http.StatusOK || dec.Decision != "deny" {
		t.Fatalf("the node's organization: status %d, %s via %q — nothing here distinguishes the two organizations", code, dec.Decision, dec.PolicyID)
	}
	code, dec := visit(t, "customer")
	if code != http.StatusOK || dec.Decision != "allow" || dec.PolicyID != "customer-allow" {
		t.Fatalf("the customer's request: status %d, %s via %q %v — want its own rule to allow it", code, dec.Decision, dec.PolicyID, dec.ReasonCodes)
	}
}

// Review finding (2026-11-14), through the handler: a connection opened under a plain allow carries no
// completed sign-in, so its first request for a host a sign-in rule guards is not let through.
func TestARequestForAGuardedHostIsNotLetThroughBecauseItsConnectionWasOpened(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstreamHits++; w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	store := policy.NewStore(nil)
	store.SetEastWestEnabled("customer", true)
	store.SetCompiledEastWestRules("customer", []decision.EastWestRule{
		{ID: "allow-address", Priority: 10, Destinations: []string{"10.20.30.40"}, Mode: decision.EastWestModeAllow},
		{ID: "signin-host", Priority: 1, Destinations: []string{"app.internal.example"}, Mode: decision.EastWestModeAuthenticate, RequiredAMR: []string{"phishing_resistant"}},
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	decisions := newAccessDecisionStore()
	handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "customer"}}, PolicyStore: store,
		Writer: writer, DecisionStore: decisions, InspectionEvents: newInspectionEventStore(),
		ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
		DeviceAuthenticatedInProcess: true,
	})
	// The route as the tunnel entrance builds it for a flow a plain allow let through.
	opened := decision.Evaluator{EastWestEnabled: true, EastWestRules: []decision.EastWestRule{{ID: "allow-address", Priority: 10, Destinations: []string{"10.20.30.40"}, Mode: decision.EastWestModeAllow}}}.
		Evaluate(model.DecisionRequest{TenantID: "customer", ActorType: "human", Destination: "10.20.30.40", DestinationPort: 443, ConnectorRouteVerified: true, ConnectorFlowFromDevice: true})
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "10.20.30.40", Port: 443, TenantID: "customer",
		ConnectorAccess: decision.IsConnectorAccessDecision(opened), ConnectorSignInDoneForRule: decision.ConnectorSignInDoneForRule(opened)}
	if !route.ConnectorAccess || route.ConnectorSignInDoneForRule != "" {
		t.Fatalf("the opened route: connector access %t, sign-in done for %q", route.ConnectorAccess, route.ConnectorSignInDoneForRule)
	}
	in := httptest.NewRequest(http.MethodGet, "https://app.internal.example/", nil)
	forward, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(in, route)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, forward)
	made := decisions.SnapshotByTenant("customer")
	if rec.Code == http.StatusOK || upstreamHits != 0 {
		t.Fatalf("status %d, upstream reached %d time(s): a host guarded by a sign-in was served without one", rec.Code, upstreamHits)
	}
	if len(made) != 1 || made[0].Decision != "authenticate_required" || made[0].PolicyID != "signin-host" {
		t.Fatalf("decisions: %+v", made)
	}
}

// Second review (2026-11-14): after the sign-in a held flow waited for is verified, the Edge rewrites the
// decision — allow, with "authentication_satisfied" — and builds the route from that. The first fix did not
// recognise the rewritten decision, so a flow that had just signed in carried no evidence of it: its first
// request was asked to sign in again, and a rule that binds the sign-in to one held connection answered 403.
// This goes the whole way the tunnel entrance goes: evaluate, rewrite as verified, build the route, forward,
// handle.
func TestAFlowThatJustSignedInIsNotAskedAgainInsideItsConnection(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { upstreamHits++; w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	signInOnce := decision.EastWestRule{ID: "signin-once", Priority: 1, Destinations: []string{"app.internal.example"},
		Mode: decision.EastWestModeAuthenticate, MaxAgeSecondsSet: true} // max_age=0: one held connection
	store := policy.NewStore(nil)
	store.SetEastWestEnabled("customer", true)
	store.SetCompiledEastWestRules("customer", []decision.EastWestRule{signInOnce})

	atOpen := decision.Evaluator{EastWestEnabled: true, EastWestRules: []decision.EastWestRule{signInOnce}}.
		Evaluate(model.DecisionRequest{TenantID: "customer", ActorType: "human", Destination: "app.internal.example", DestinationPort: 443, ConnectorRouteVerified: true, ConnectorFlowFromDevice: true})
	if atOpen.Decision != "authenticate_required" {
		t.Fatalf("at open: %s", atOpen.Decision)
	}
	visit := func(t *testing.T, forwardedWith model.AccessDecision) int {
		t.Helper()
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		handler := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "customer"}}, PolicyStore: store,
			Writer: writer, DecisionStore: newAccessDecisionStore(), InspectionEvents: newInspectionEventStore(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			DeviceAuthenticatedInProcess: true,
		})
		route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "app.internal.example", Port: 443, TenantID: "customer",
			ConnectorAccess: decision.IsConnectorAccessDecision(forwardedWith), ConnectorSignInDoneForRule: decision.ConnectorSignInDoneForRule(forwardedWith)}
		forward, err := edgeplane.BuildNetworkExtensionLabTLSForwardRequest(httptest.NewRequest(http.MethodGet, "https://app.internal.example/", nil), route)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, forward)
		return rec.Code
	}
	// What the tunnel entrance forwards with once the sign-in has been verified.
	verified := decisionAllowedByAuthentication(atOpen)
	if got := decision.ConnectorSignInDoneForRule(verified); got != "signin-once" {
		t.Fatalf("the decision as rewritten after a verified sign-in names %q as the completed rule, want signin-once (reasons %v)", got, verified.ReasonCodes)
	}
	if code := visit(t, verified); code != http.StatusOK || upstreamHits != 1 {
		t.Fatalf("the first request after signing in: status %d, upstream reached %d time(s)", code, upstreamHits)
	}
	// And a flow that an ordinary rule let through is still asked: rewriting is the only way to get here.
	plain := atOpen
	plain.Decision, plain.ReasonCodes = "allow", []string{"east_west_policy_allow"}
	if got := decision.ConnectorSignInDoneForRule(plain); got != "" {
		t.Fatalf("a plain allow is taken for a completed sign-in for %q", got)
	}
	if code := visit(t, plain); code == http.StatusOK || upstreamHits != 1 {
		t.Fatalf("a request with no completed sign-in was served: status %d, upstream reached %d time(s)", code, upstreamHits)
	}
}

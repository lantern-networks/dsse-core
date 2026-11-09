package main

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestABrowserIsShownAPageWhenPolicyRefusesASite(t *testing.T) {
	user, reason := "someone@example.test", "Request denied by policy pol_internal_7."
	dec := model.AccessDecision{ID: "dec_ref_123", Decision: "deny", TenantID: "tenant_secret_id",
		UserID: &user, PolicyID: "pol_internal_7", Reason: &reason}
	r := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "ja,en;q=0.5")
	w := httptest.NewRecorder()
	writeSWGPolicyRefusal(w, r, "example.org", dec)
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("a browser got %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, want := range []string{"このサイトはブロックされています", "example.org", "dec_ref_123"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, leak := range []string{"tenant_secret_id", "someone@example.test", "pol_internal_7", "\"decision\""} {
		if strings.Contains(body, leak) {
			t.Errorf("the page shows the internal value %q to the person at the browser", leak)
		}
	}

	api := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
	api.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	writeSWGPolicyRefusal(w, api, "example.org", dec)
	if !strings.Contains(w.Body.String(), "\"decision\":\"deny\"") || !strings.Contains(w.Body.String(), "\"reference\":\"dec_ref_123\"") {
		t.Fatalf("a non-browser client lost the decision or the reference it reads: %s", w.Body.String())
	}
	// Acceptance C, fourth walk: the JSON carried the organization's id, the user name and the matched rule to
	// whatever program on the device made the request.
	for _, leak := range []string{"tenant_secret_id", "someone@example.test", "pol_internal_7", "policy_id", "user_id", "tenant_id"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("a non-browser client is handed the internal value %q: %s", leak, w.Body.String())
		}
	}
}

// Review R2 (2026-11-08): a client that refuses HTML keeps the decision JSON it reads.
func TestAClientThatRefusesHTMLKeepsTheJSON(t *testing.T) {
	user, reason := "u", "r"
	dec := model.AccessDecision{ID: "dec_1", Decision: "deny", UserID: &user, Reason: &reason}
	for _, tc := range []struct {
		accept string
		html   bool
	}{
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", true}, // a browser
		{"application/json, text/html;q=0", false},
		{"application/json, text/html;q=0.5", false},
		{"text/html;q=0.9, application/json;q=0.5", true},
		{"*/*", false},
		{"", false},
		{"text/html;q=bogus", false},
		{"application/json;q=0.9, application/xhtml+xml;q=1, text/html;q=0", false}, // XHTML is not the page served
		{"application/xhtml+xml", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
		if tc.accept != "" {
			r.Header.Set("Accept", tc.accept)
		}
		if got := acceptsHTMLPage(r); got != tc.html {
			t.Errorf("Accept %q: HTML=%t, want %t", tc.accept, got, tc.html)
		}
		w := httptest.NewRecorder()
		writeSWGPolicyRefusal(w, r, "example.org", dec)
		isHTML := strings.HasPrefix(w.Header().Get("Content-Type"), "text/html")
		if isHTML != tc.html {
			t.Errorf("Accept %q: served HTML=%t, want %t", tc.accept, isHTML, tc.html)
		}
		// The upstream-failure page decides the same way.
		w = httptest.NewRecorder()
		writeSWGUpstreamFailure(w, r, "example.org", x509.UnknownAuthorityError{})
		isHTML = strings.HasPrefix(w.Header().Get("Content-Type"), "text/html")
		if isHTML != tc.html {
			t.Errorf("Accept %q: upstream failure served HTML=%t, want %t", tc.accept, isHTML, tc.html)
		}
	}
}

// Found 2026-11-08 on acceptance C: the page said "UTC" to a person in an organization set to Asia/Tokyo. The
// time is stated in the organization's zone, as every Console screen states it, and the zone is named.
func TestTheRefusalPageStatesTheTimeInTheOrganizationsZone(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("no zone database on this machine")
	}
	prior := organizationZone
	t.Cleanup(func() { organizationZone = prior })
	asked := ""
	organizationZone = func(tenantID string) *time.Location { asked = tenantID; return tokyo }
	dec := model.AccessDecision{ID: "dec_1", Decision: "deny", TenantID: "tenant_tokyo"}
	r := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "ja")
	w := httptest.NewRecorder()
	writeSWGPolicyRefusal(w, r, "example.org", dec)
	if asked != "tenant_tokyo" {
		t.Fatalf("the page asked for the zone of %q, not the organization the decision belongs to", asked)
	}
	if body := w.Body.String(); !strings.Contains(body, " JST") || strings.Contains(body, " UTC") {
		t.Fatalf("the page does not state the organization's zone: %s", body)
	}
}

// Review of the fourth-walk fixes (2026-11-08): the first reduction copied the decision's sentence, and the real
// evaluator's sentence for "no rule matched" names the nearest rule and two identities. This test uses the real
// evaluator, not a hand-written decision, so the sentence is the one the product writes.
func TestANonBrowserRefusalDoesNotCarryTheEvaluatorsDiagnosis(t *testing.T) {
	evaluator := decision.Evaluator{Policies: []model.Policy{{
		ID: "private_rule_accounting_only", TenantID: "tenant_fixture_a", Status: "active", Priority: 10,
		Conditions: map[string]any{"user_id": "finance_approver@example.invalid"},
		Action:     model.PolicyAction{Decision: "allow"},
	}}}
	dec := evaluator.Evaluate(model.DecisionRequest{TenantID: "tenant_fixture_a", UserID: "ordinary_employee@example.invalid", ActorType: "human"})
	if dec.Decision != "deny" || dec.Reason == nil {
		t.Fatalf("the fixture did not produce the deny it exists for: %+v", dec)
	}
	for _, s := range []string{"private_rule_accounting_only", "finance_approver@example.invalid", "ordinary_employee@example.invalid"} {
		if !strings.Contains(*dec.Reason, s) {
			t.Fatalf("the evaluator's sentence no longer names %q, so this test no longer exercises the diagnosis: %s", s, *dec.Reason)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "https://destination.invalid/", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	writeSWGPolicyRefusal(w, r, "destination.invalid", dec)
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(body, "\"decision\":\"deny\"") || !strings.Contains(body, "\"reference\":\""+dec.ID+"\"") {
		t.Fatalf("the client lost the decision or the reference: %d %s", w.Code, body)
	}
	for _, s := range []string{"private_rule_accounting_only", "finance_approver@example.invalid", "ordinary_employee@example.invalid", "closest rule"} {
		if strings.Contains(body, s) {
			t.Errorf("the client is handed the administrator's diagnosis %q: %s", s, body)
		}
	}
	// A sign-in decision is told to sign in, and nothing of the request either.
	user, reason := "someone@example.test", "Request matched a policy that requires re-authentication."
	w = httptest.NewRecorder()
	writeSWGPolicyRefusal(w, r, "destination.invalid", model.AccessDecision{ID: "dec_2", Decision: "require_reauthentication",
		UserID: &user, Reason: &reason, PolicyID: "pol_x"})
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "sign in") || strings.Contains(w.Body.String(), "pol_x") {
		t.Fatalf("a sign-in decision: %d %s", w.Code, w.Body.String())
	}
}

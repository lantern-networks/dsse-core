package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func batchTokenMux(t *testing.T, policy enrolltoken.Policy) (*http.ServeMux, *enrolltoken.Store) {
	t.Helper()
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	registerAdminEnrolmentTokenEndpoints(mux, tokens, policy,
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil,
		// No account directory in this harness, so the label is simply absent — the same shape a deployment
		// sees once the approving account has been deleted.
		func(_, _ string) string { return "" }, "tenant_test",
		// No lifecycle store in this harness: a nil store means "I cannot read the registry", which the
		// suspension check treats as NOT suspended — the same asymmetry adminTenantIsGone uses, so an
		// unreadable registry never invents a refusal.
		nil,
		// This node issues for nobody in this harness, which is the shape that produces the warning.
		nil,
		// Empty config source: this harness IS the register, so an absence would be authoritative here.
		"",
		// No operator organization in this harness, so the "a device does not belong to the operator" gate is off.
		"")
	return mux, tokens
}

func issueBatch(t *testing.T, mux *http.ServeMux, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/admin/enrolment-tokens", strings.NewReader(body))
	// The tenant and the issuing admin come from the session in the real path; both are required, and a token
	// with no identified issuer is refused on purpose — an unattributable approval is not an approval.
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "adm_alice", TenantID: "tenant_test"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Kitting is the ordinary case. Making an admin repeat a dialog fifty times is the friction that ends with
// somebody going back to one shared secret for the whole batch.
func TestABatchIssuesOneTokenPerDevice(t *testing.T) {
	mux, tokens := batchTokenMux(t, enrolltoken.DefaultPolicy())
	code, body := issueBatch(t, mux, `{"label":"Osaka batch","expires_in_hours":168,"count":50}`)
	if code != http.StatusOK {
		t.Fatalf("batch issue: %d %+v", code, body)
	}
	rows, _ := body["tokens"].([]any)
	if len(rows) != 50 {
		t.Fatalf("want 50 tokens, got %d", len(rows))
	}
	// Each must be distinct and usable exactly once — a batch is a convenience for the person, not a weaker
	// credential.
	seen := map[string]bool{}
	now := time.Now().UTC()
	for i, raw := range rows {
		row := raw.(map[string]any)
		secret := row["secret"].(string)
		if seen[secret] {
			t.Fatalf("token %d repeats an earlier secret", i)
		}
		seen[secret] = true
		if _, err := tokens.Consume(secret, "tenant_test", "device-"+string(rune('a'+i%26)), now); err != nil {
			t.Fatalf("token %d must work: %v", i, err)
		}
	}
	// Labels are numbered so a list of fifty is still readable months later.
	first := rows[0].(map[string]any)["token"].(map[string]any)
	if !strings.Contains(first["label"].(string), "1/50") {
		t.Fatalf("batch labels must be numbered, got %q", first["label"])
	}
}

// A batch that does not fit must be refused WHOLE. Minting thirty of fifty leaves an operator holding a partial
// set they have to reconcile against a kitting list, with live credentials already created.
func TestABatchThatDoesNotFitIsRefusedBeforeAnythingIsMinted(t *testing.T) {
	mux, tokens := batchTokenMux(t, enrolltoken.Policy{MaxLifetime: 30 * 24 * time.Hour, MaxOutstanding: 10})
	if code, _ := issueBatch(t, mux, `{"label":"first","expires_in_hours":24,"count":8}`); code != http.StatusOK {
		t.Fatalf("the first batch fits")
	}
	code, body := issueBatch(t, mux, `{"label":"second","expires_in_hours":24,"count":5}`)
	if code != http.StatusConflict {
		t.Fatalf("a batch past the cap must be refused, got %d", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "only 2 more") {
		t.Fatalf("the refusal must say how many WOULD fit, got %q", msg)
	}
	if n := tokens.Outstanding("tenant_test", time.Now().UTC()); n != 8 {
		t.Fatalf("nothing may be minted by a refused batch: outstanding %d, want 8", n)
	}
}

// A mistyped figure must not mint thousands of live credentials in one keystroke.
func TestAnAbsurdBatchIsRefused(t *testing.T) {
	mux, _ := batchTokenMux(t, enrolltoken.DefaultPolicy())
	if code, _ := issueBatch(t, mux, `{"label":"oops","expires_in_hours":24,"count":100000}`); code != http.StatusBadRequest {
		t.Fatalf("an absurd count must be refused, got %d", code)
	}
}

// Single issuance keeps its original response shape, so nothing that already calls this has to change.
func TestASingleIssuanceStillReturnsOneSecret(t *testing.T) {
	mux, _ := batchTokenMux(t, enrolltoken.DefaultPolicy())
	code, body := issueBatch(t, mux, `{"label":"one laptop","expires_in_hours":24}`)
	if code != http.StatusOK {
		t.Fatalf("single issue: %d", code)
	}
	if _, ok := body["secret"].(string); !ok {
		t.Fatalf("a single issuance must still carry `secret`: %+v", body)
	}
	// And a single one is NOT numbered — "(1/1)" on one laptop is noise.
	tok := body["token"].(map[string]any)
	if strings.Contains(tok["label"].(string), "/") {
		t.Fatalf("a single issuance must not be numbered, got %q", tok["label"])
	}
}

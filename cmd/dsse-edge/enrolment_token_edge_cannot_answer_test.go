package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// ★★★ AN EDGE THAT ASKS THE AUTHORITY MUST NOT ANSWER FOR IT. Measured on the two-region lab (2026-08-25):
// forty-six approvals were outstanding on the control plane while an Edge answered "0 outstanding, no tokens"
// with HTTP 200 — the same answer a deployment with none would give, to an operator who would then go looking
// for a problem that does not exist.
func TestAnEdgeThatForwardsSpendingRefusesToListRatherThanAnsweringEmpty(t *testing.T) {
	mux := http.NewServeMux()
	remote := newRemoteEnrolmentTokenAuthority("https://cp.example:9443", "tok", http.DefaultClient)
	if remote == nil {
		t.Fatal("the harness did not build a remote authority")
	}
	registerAdminEnrolmentTokenEndpoints(mux, remote, enrolltoken.DefaultPolicy(),
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil,
		func(_, _ string) string { return "" }, "tenant_test", nil, nil, "", "")

	for _, path := range []string{"GET /admin/enrolment-tokens", "POST /admin/enrolment-tokens"} {
		parts := strings.SplitN(path, " ", 2)
		r := httptest.NewRequest(parts[0], parts[1], strings.NewReader(`{"count":1}`))
		r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "adm_alice", TenantID: "tenant_test"})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s answered 200 from a node that holds no tokens: %s", path, rec.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		msg, _ := body["error"].(string)
		// The refusal has to say where to ask, or it is just a different way to strand the operator.
		if !strings.Contains(msg, "control plane") {
			t.Fatalf("%s refused without saying where the tokens are: %d %q", path, rec.Code, msg)
		}
	}
}

// The guard: a deployment whose Edge IS the authority — a single node with no control plane above it — keeps
// answering, so the refusal above is about forwarding and not about the surface being switched off.
func TestANodeThatHoldsTheTokensStillAnswers(t *testing.T) {
	mux, _ := batchTokenMux(t, enrolltoken.DefaultPolicy())
	r := httptest.NewRequest(http.MethodGet, "/admin/enrolment-tokens", nil)
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "adm_alice", TenantID: "tenant_test"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("a node holding its own tokens stopped answering: %d %s", rec.Code, rec.Body.String())
	}
}

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// Which administrator approved a machine is the whole point of the record, and an id answers it only while
// that account exists. Approvals outlive the people who granted them — that is the ordinary end of the story,
// not an edge case — so the name is written down at the moment of the act.
func TestApproverNameIsRecordedAtIssuance(t *testing.T) {
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	registerAdminEnrolmentTokenEndpoints(mux, tokens, enrolltoken.DefaultPolicy(),
		func(_ string, h http.HandlerFunc) http.HandlerFunc {
			// Stand in for the admin gate, supplying the identity the authority would have introspected.
			return func(w http.ResponseWriter, r *http.Request) {
				h(w, requestWithAdminIdentity(r, adminIdentity{
					PrincipalID: "adm_alice", PrincipalLabel: "alice@example.com",
					TenantID: "tenant_a", AuthMethod: "admin_session",
				}))
			}
		}, nil,
		// The local lookup must NOT be what answers here: on a real deployment the accounts live on the
		// authority and this returns nothing, which is how the first implementation recorded an empty label
		// while looking perfectly correct.
		func(_, _ string) string { return "" }, "tenant_test",
		// No lifecycle store in this harness: a nil store means "I cannot read the registry", which the
		// suspension check treats as NOT suspended — the same asymmetry adminTenantIsGone uses, so an
		// unreadable registry never invents a refusal.
		nil,
		// This node issues for nobody in this harness.
		nil,
		// Empty config source: this harness IS the register, so an absence would be authoritative here.
		"",
		// No operator organization in this harness, so the "a device does not belong to the operator" gate is off.
		"")

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"label":"kitting","count":1,"expires_in_hours":8}`)
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/enrolment-tokens", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("issue: HTTP %d — %s", rec.Code, rec.Body.String())
	}

	var listed struct {
		Tokens []enrolltoken.Token `json:"tokens"`
	}
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/admin/enrolment-tokens", nil))
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Tokens) != 1 {
		t.Fatalf("want one token, got %d", len(listed.Tokens))
	}
	got := listed.Tokens[0]
	if got.IssuedBy != "adm_alice" {
		t.Fatalf("IssuedBy = %q, want the principal id", got.IssuedBy)
	}
	if got.IssuedByLabel != "alice@example.com" {
		t.Fatalf("IssuedByLabel = %q — the approver's name must be recorded with the approval, not resolved later", got.IssuedByLabel)
	}
}

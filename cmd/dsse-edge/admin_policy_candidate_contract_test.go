package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminPolicyCandidateOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    PolicyCandidate:",
		"    PolicyCandidateList:",
		"    PolicyCandidateReviewRequest:",
		"  /admin/policy-candidates:",
		"  /admin/policy-candidates/{candidate_id}:",
		"  /admin/policy-candidates/{candidate_id}/review:",
		"admin.policy_candidates.read",
		"admin.policy_candidates.write",
		"admin.policy_candidates.review",
		`$ref: "#/components/schemas/PolicyCandidateList"`,
		`$ref: "#/components/schemas/PolicyCandidate"`,
		`$ref: "#/components/schemas/PolicyCandidateReviewRequest"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminPolicyCandidateAPIUpsertListDetailAndReview(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"candidate_id":"pc_allow_001",
		"tenant_id":"tenant_lab_001",
		"candidate_type":"allow_policy",
		"source":"policy_learning",
		"proposed_action":"allow",
		"application_id":"app_candidate_001",
		"service_family":"ssh",
		"reason_codes":["default_deny_deferred","operator_review_required"]
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created policycandidate.Candidate
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created candidate: %v", err)
	}
	if created.CandidateID != "pc_allow_001" || created.Status != "pending" || created.UpdatedAt == nil {
		t.Fatalf("created candidate = %#v, want pending candidate", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/policy-candidates?status=pending&limit=10", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list policycandidate.ListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode candidate list: %v", err)
	}
	if list.Count != 1 || len(list.Candidates) != 1 || list.Candidates[0].CandidateID != created.CandidateID {
		t.Fatalf("candidate list = %#v, want created pending candidate", list)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/policy-candidates/pc_allow_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}

	reviewReq := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates/pc_allow_001/review", strings.NewReader(`{"decision":"approved","review_reason_code":"least_privilege_exception"}`))
	reviewRec := httptest.NewRecorder()
	handler.ServeHTTP(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusOK {
		t.Fatalf("review status = %d, want %d, body=%s", reviewRec.Code, http.StatusOK, reviewRec.Body.String())
	}
	var reviewed policycandidate.Candidate
	if err := json.Unmarshal(reviewRec.Body.Bytes(), &reviewed); err != nil {
		t.Fatalf("decode reviewed candidate: %v", err)
	}
	if reviewed.Status != "approved" || reviewed.ReviewReasonCode != "least_privilege_exception" || reviewed.ReviewedAt == nil {
		t.Fatalf("reviewed candidate = %#v, want approved review", reviewed)
	}
	if len(outbox.insertedAudits) != 2 || outbox.insertedAudits[0].EventType != "admin_policy_candidate_upserted" || outbox.insertedAudits[1].EventType != "admin_policy_candidate_reviewed" {
		t.Fatalf("outbox inserted audits = %#v, want candidate upsert/review", outbox.insertedAudits)
	}
	for _, audit := range outbox.insertedAudits {
		if audit.SourceIP != nil || audit.ActorUserID == nil || *audit.ActorUserID == "" {
			t.Fatalf("candidate audit must identify its administrator without raw source fields: %#v", audit)
		}
	}
}

func TestAdminPolicyCandidateAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"candidate_id":"pc_other_001","tenant_id":"tenant_other_001","candidate_type":"allow_policy","source":"policy_learning","proposed_action":"allow","application_id":"app_candidate_001","service_family":"ssh"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminPolicyCandidateAPIRequiresReviewScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_candidate_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_candidate_reader_001",
		Email:     "candidate-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_candidate_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "candidate-reader-token",
		TokenHash:                 adminTokenHash("raw-candidate-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.policy_candidates.read"},
		CreatedByAdminPrincipalID: "admin_candidate_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	store := policycandidate.NewStore()
	_, err := store.Upsert(nil, policycandidate.Candidate{
		CandidateID:    "pc_scope_denied_001",
		TenantID:       "tenant_lab_001",
		CandidateType:  "allow_policy",
		Source:         "policy_learning",
		ProposedAction: "allow",
		ApplicationID:  "app_candidate_001",
		ServiceFamily:  "ssh",
	}, "tenant_lab_001", time.Now())
	if err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:            testEvaluator(),
		Registry:             connector.NewRegistry(),
		AdminAuth:            adminAuth,
		PolicyCandidateStore: store,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/policy-candidates/pc_scope_denied_001/review", strings.NewReader(`{"decision":"approved","review_reason_code":"scope_denied_fixture"}`))
	req.Header.Set("authorization", "Bearer raw-candidate-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.policy_candidates.review is required") {
		t.Fatalf("status = %d body=%s, want review scope denial", rec.Code, rec.Body.String())
	}
}

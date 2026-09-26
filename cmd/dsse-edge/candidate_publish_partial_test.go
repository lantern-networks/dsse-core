package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCandidatePrivatePublishReportsReviewFailure(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	tenant := testEvaluator().PolicyBundle.TenantID
	p := &publicationNthPersister{}
	candidates := policycandidate.NewStore()
	if e := candidates.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	c, e := candidates.ObserveConnectorDiscovered(ctx, tenant, "internal.example", 443, "web", "conn", "site", "ns", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	apps := appcatalog.NewStore()
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	out := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: newAdminAuthStore(), ApplicationCatalogStore: apps, PolicyCandidateStore: candidates, AdminAuditOutbox: out})
	p.failAt = p.calls + 1
	call := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/policy-candidates/"+c.CandidateID+"/approve-private-app", strings.NewReader(`{}`)))
		return w
	}
	w := call()
	if w.Code != 500 {
		t.Fatalf("review save failure returned %d: %s", w.Code, w.Body)
	}
	var body map[string]any
	if e = json.Unmarshal(w.Body.Bytes(), &body); e != nil || body["partial"] != true || body["failed_stage"] != "candidate_review" {
		t.Fatal(body, e)
	}
	if strings.Contains(w.Body.String(), "/private/") {
		t.Fatal("storage details disclosed")
	}
	app, found, e := apps.Get(ctx, tenant, c.CandidateID)
	if e != nil || !found || !app.Published {
		t.Fatal("confirmed app missing", e)
	}
	current, _, _ := candidates.Get(ctx, tenant, c.CandidateID)
	if current.Status != "pending" {
		t.Fatal(current)
	}
	if len(out.insertedAudits) != 2 {
		t.Fatal(out.insertedAudits)
	}
	for _, a := range out.insertedAudits {
		if stringPtrValue(a.ActorUserID) == "" {
			t.Fatal("actor missing", a)
		}
		if a.EventType == "admin_policy_candidate_reviewed" && (stringPtrValue(a.Result) != "partial" || a.Metadata["candidate_saved"] != false || a.Metadata["application_saved"] != true) {
			t.Fatal("false success audit", a)
		}
	}
	if w = call(); w.Code != 200 {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	current, _, _ = candidates.Get(ctx, tenant, c.CandidateID)
	if current.Status != "approved" {
		t.Fatal(current)
	}
}

type publicationNthPersister struct {
	data          []byte
	calls, failAt int
}

func (p *publicationNthPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *publicationNthPersister) Save(b []byte) error {
	p.calls++
	if p.calls == p.failAt {
		return errors.New("/private/candidate-state: write refused")
	}
	p.data = bytes.Clone(b)
	return nil
}

type failingCandidatePolicyStore struct {
	*policy.Store
	fail bool
}

func (s *failingCandidatePolicyStore) Upsert(c context.Context, p model.Policy, tenant string, now time.Time) (model.Policy, error) {
	if s.fail {
		return model.Policy{}, errors.New("private policy failure")
	}
	return s.Store.Upsert(c, p, tenant, now)
}
func TestCandidateAllowAdoptionReportsFailureAndRetries(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	tenant := testEvaluator().PolicyBundle.TenantID
	candidates := policycandidate.NewStore()
	c, e := candidates.ObserveUnmatchedFlow(ctx, tenant, "internal.example", "", 443, "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = candidates.Review(ctx, tenant, c.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); e != nil {
		t.Fatal(e)
	}
	ps := &failingCandidatePolicyStore{Store: policy.NewStore(nil), fail: true}
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	out := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: newAdminAuthStore(), PolicyCandidateStore: candidates, PolicyStore: ps, AdminAuditOutbox: out})
	call := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/policy-candidates/"+c.CandidateID+"/materialize", strings.NewReader(`{}`)))
		return w
	}
	w := call()
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"failed_stage":"allow_policy"`) {
		t.Fatalf("policy refusal %d %s", w.Code, w.Body)
	}
	if len(out.insertedAudits) != 1 || stringPtrValue(out.insertedAudits[0].Result) != "partial" {
		t.Fatal(out.insertedAudits)
	}
	audit := out.insertedAudits[0]
	if stringPtrValue(audit.ActorUserID) == "" || audit.Metadata["failed_stage"] != "allow_policy" || audit.Metadata["candidate_saved"] != true || audit.Metadata["policy_save_confirmed"] != false {
		t.Fatal("partial adoption audit is incomplete", audit)
	}
	if strings.Contains(w.Body.String(), "private policy failure") {
		t.Fatal("storage details disclosed", w.Body)
	}
	if _, ok, _ := ps.Get(ctx, tenant, "adopted-"+c.CandidateID); ok {
		t.Fatal("failed policy published")
	}
	ps.fail = false
	if w = call(); w.Code != 200 {
		t.Fatalf("retry %d %s", w.Code, w.Body)
	}
	if _, ok, _ := ps.Get(ctx, tenant, "adopted-"+c.CandidateID); !ok {
		t.Fatal("retry policy absent")
	}
}

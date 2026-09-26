package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/logs"
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

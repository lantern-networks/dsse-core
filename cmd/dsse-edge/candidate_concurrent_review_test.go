package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type reviewDuringPublication struct {
	*appcatalog.Store
	review func()
}

func (s *reviewDuringPublication) CreateOrMatch(ctx context.Context, e appcatalog.Entry, tenant string, now time.Time) (appcatalog.Entry, error) {
	result, err := s.Store.CreateOrMatch(ctx, e, tenant, now)
	if err == nil {
		s.review()
	}
	return result, err
}
func TestCandidatePublicationPreservesConcurrentReview(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	tenant := testEvaluator().PolicyBundle.TenantID
	candidates := policycandidate.NewStore()
	c, err := candidates.ObserveConnectorDiscovered(ctx, tenant, "concurrent.example", 443, "web", "conn", "site", "ns", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	apps := &reviewDuringPublication{Store: appcatalog.NewStore()}
	if err = apps.SetStatePath(filepath.Join(t.TempDir(), "apps.json")); err != nil {
		t.Fatal(err)
	}
	apps.review = func() {
		if _, _, e := candidates.Review(ctx, tenant, c.CandidateID, policycandidate.ReviewRequest{Decision: "suppressed", ReviewReasonCode: "parallel_review"}, now.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	out := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: newAdminAuthStore(), ApplicationCatalogStore: apps, PolicyCandidateStore: candidates, AdminAuditOutbox: out})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admin/policy-candidates/"+c.CandidateID+"/approve-private-app", strings.NewReader(`{}`)))
	got, _, _ := candidates.Get(ctx, tenant, c.CandidateID)
	if w.Code != 500 || got.Status != "suppressed" {
		t.Fatalf("concurrent review overwritten: status=%d candidate=%s body=%s", w.Code, got.Status, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"partial":true`) {
		t.Fatal(w.Body)
	}
	if _, found, _ := apps.Get(ctx, tenant, c.CandidateID); !found {
		t.Fatal("confirmed app discarded")
	}
	for _, a := range out.insertedAudits {
		if a.EventType == "admin_policy_candidate_reviewed" && stringPtrValue(a.Result) != "partial" {
			t.Fatal("false approval audit", a)
		}
	}
}

func TestPostgresCandidatePublicationPreservesPeerReview(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "policy_candidates"
	a, b := policycandidate.NewStore(), policycandidate.NewStore()
	if e := a.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	ctx := captureCPWriteLease(context.Background())
	now := time.Now()
	c, e := a.ObserveConnectorDiscovered(ctx, "own", "peer-review.example", 443, "web", "conn", "site", "ns", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = b.Review(ctx, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "suppressed"}, now); e != nil {
		t.Fatal(e)
	}
	before, _ := p.Load()
	if _, _, e = a.ApprovePublication(ctx, c, "published", now); !errors.Is(e, policycandidate.ErrPublicationChanged) {
		t.Fatal("peer review overwritten", e)
	}
	after, _ := p.Load()
	if string(before) != string(after) {
		t.Fatal("conditional refusal rewrote row")
	}
	got, _, e := a.Get(ctx, "own", c.CandidateID)
	if e != nil || got.Status != "suppressed" {
		t.Fatal(got, e)
	}
	if _, e = b.RemoveTenantContext(ctx, "own"); e != nil {
		t.Fatal(e)
	}
	if _, found, e := a.ApprovePublication(ctx, c, "published", now); e != nil || found {
		t.Fatal("erased candidate recreated", found, e)
	}
	c, e = a.ObserveConnectorDiscovered(ctx, "other", "live.example", 443, "web", "conn", "site", "ns", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.ObserveConnectorDiscovered(ctx, "other", "live.example", 443, "web", "conn", "site", "ns", nil, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	got, found, e := a.ApprovePublication(ctx, c, "published", now)
	if e != nil || !found || got.Status != "approved" || got.LastObserved == nil || *got.LastObserved == *c.LastObserved {
		t.Fatal("observation lost or approval rejected", got, e)
	}
	fresh := policycandidate.NewStore()
	if e = fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	got, _, e = fresh.Get(ctx, "other", c.CandidateID)
	if e != nil || got.Status != "approved" {
		t.Fatal(got, e)
	}
}

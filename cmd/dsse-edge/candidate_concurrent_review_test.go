package main

import (
	"context"
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

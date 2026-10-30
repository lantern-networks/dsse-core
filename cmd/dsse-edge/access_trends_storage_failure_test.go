package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/accessdecision"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
)

type accessTrendsReviewStore struct {
	hotstore.Store
	err error
}

func (s accessTrendsReviewStore) ExportRows(context.Context, hotstore.SearchQuery, hotstore.RowHandler) (hotstore.ExportResult, error) {
	return hotstore.ExportResult{}, s.err
}

func TestAccessTrendsDoesNotPresentStorageFailureAsLocalOrZeroTotals(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		hot                       hotstore.Store
		wantStatus, wantDecisions int
	}{
		{"storage failure", accessTrendsReviewStore{err: errors.New("database unavailable")}, http.StatusServiceUnavailable, 0},
		{"authoritative empty storage", accessTrendsReviewStore{}, http.StatusOK, 0},
		{"standalone without storage", nil, http.StatusOK, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := accessdecision.NewStore(10)
			local.Upsert(model.AccessDecision{ID: "local-only", TenantID: "tenant-a", Decision: "deny", Timestamp: time.Now().UTC().Format(time.RFC3339)})
			mux := http.NewServeMux()
			registerAIOpsRoutes(mux, func(_ string, handler http.HandlerFunc) http.HandlerFunc { return handler }, testEvaluator(), nil, local, tc.hot)
			req := httptest.NewRequest(http.MethodGet, "/admin/ai-ops/access-trends", nil)
			req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{TenantID: "tenant-a"}))
			resp := httptest.NewRecorder()
			mux.ServeHTTP(resp, req)
			if resp.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d; storage failure must not become a successful local report", resp.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK {
				var body struct {
					WindowDecisions int `json:"window_decisions"`
				}
				if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.WindowDecisions != tc.wantDecisions {
					t.Fatalf("decisions=%d, want %d", body.WindowDecisions, tc.wantDecisions)
				}
			}
		})
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/inspection"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failingDLPFindingsHotStore struct {
	hotstore.Store
	failed atomic.Bool
}

func (s *failingDLPFindingsHotStore) Search(ctx context.Context, q hotstore.SearchQuery) (hotstore.SearchResult, error) {
	if s.failed.Load() {
		return hotstore.SearchResult{}, errors.New("PRIVATE backend address and credentials")
	}
	return s.Store.Search(ctx, q)
}
func findingsTestHandler(t *testing.T, writer *logs.Writer, hot hotstore.Store, events *inspection.Store) http.Handler {
	t.Helper()
	tenant := testEvaluator().PolicyBundle.TenantID
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "reader", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "reader-session", TenantID: tenant, AdminPrincipalID: "reader", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	mux := http.NewServeMux()
	registerDLPRoutes(mux, newAdminEndpointMiddleware(testEvaluator(), writer, nil, auth, "", true, nil, nil, nil), testEvaluator(), hot, nil, nil, nil, nil, nil, nil, events, "")
	return mux
}
func findingsTestRead(h http.Handler, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/admin/dlp-findings"+query, nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "reader-session"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
func TestAdminDLPFindingsStoreFailureDoesNotMasqueradeAsEmpty(t *testing.T) {
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	hot := &failingDLPFindingsHotStore{Store: hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap())}
	hot.failed.Store(true)
	for _, localCount := range []int{0, 1} {
		events := newInspectionEventStore()
		if localCount > 0 {
			events.Upsert(model.InspectionEvent{ID: "cached", TenantID: testEvaluator().PolicyBundle.TenantID, Timestamp: time.Now().UTC().Format(time.RFC3339), FindingType: stringPtr("dlp_match"), Metadata: map[string]any{"dlp_action": "observe", "dlp_identifier_types": []string{"email"}}})
		}
		h := findingsTestHandler(t, writer, hot, events)
		rec := findingsTestRead(h, "")
		if rec.Code != 503 || strings.Contains(rec.Body.String(), "PRIVATE") {
			t.Fatalf("aggregate failure: %d %s", rec.Code, rec.Body.String())
		}
		hot.failed.Store(false)
		rec = findingsTestRead(h, "")
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
		var body struct {
			Findings []any `json:"findings"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Findings) != 0 {
			t.Fatal("successful empty aggregate must be authoritative", err)
		}
		hot.failed.Store(true)
		// The intentional standalone path still reads its local event store.
		h = findingsTestHandler(t, writer, nil, events)
		rec = findingsTestRead(h, "")
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Findings) != localCount {
			t.Fatal("standalone local findings changed", err)
		}
	}
}

func TestAdminDLPFindingsScannedEventsFiltersAndRestart(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { writer.Close() }()
	tenant := testEvaluator().PolicyBundle.TenantID
	config := edgeSWGHTTPEgressHandlerConfig{Writer: writer, InspectionEvents: newInspectionEventStore()}
	for i, item := range []struct{ tenant, body string }{{tenant, `{"card":"4111111111111111","email":"PRIVATE@example.test"}`}, {tenant, `{"email":"PRIVATE@example.test"}`}, {"other", `{"card":"4242424242424242"}`}, {tenant, `{"note":"safe text"}`}} {
		dec := dlpDecWithInspect(string(rune('a'+i)), item.tenant, "app", "observe", "email", "credit_card")
		req := httptest.NewRequest("POST", "https://upload.example.test/", strings.NewReader(item.body))
		req.Header.Set("Content-Type", "application/json")
		hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
		sent, err := io.ReadAll(req.Body)
		if err != nil || string(sent) != item.body {
			t.Fatal("observe changed body", err)
		}
		hook.finalizeObserve(context.Background())
	}
	verify := func() {
		h := findingsTestHandler(t, writer, hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()), newInspectionEventStore())
		for _, tc := range []struct {
			query                        string
			total, returned, email, card int
		}{{"", 2, 2, 2, 1}, {"?limit=1", 2, 1, 2, 1}, {"?identifier=credit_card", 1, 1, 1, 1}, {"?identifier=phone", 0, 0, 0, 0}, {"?action=block", 0, 0, 0, 0}, {"?action=observe&severity=warning", 2, 2, 2, 1}} {
			rec := findingsTestRead(h, tc.query)
			if rec.Code != 200 {
				t.Fatal(rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "PRIVATE@example.test") || strings.Contains(rec.Body.String(), "4111111111111111") || strings.Contains(rec.Body.String(), "4242424242424242") {
				t.Fatal("matched value exposed")
			}
			var got struct {
				Tenant   string `json:"tenant_id"`
				Findings []struct {
					Decision string `json:"access_decision_id"`
				} `json:"findings"`
				Summary struct {
					Total, Returned, Blocked int
					ByIdentifier             map[string]int `json:"by_identifier"`
				} `json:"summary"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Tenant != tenant || got.Summary.Total != tc.total || got.Summary.Returned != tc.returned || len(got.Findings) != tc.returned || got.Summary.Blocked != 0 || got.Summary.ByIdentifier["email"] != tc.email || got.Summary.ByIdentifier["credit_card"] != tc.card {
				t.Fatalf("query %s: %s", tc.query, rec.Body.String())
			}
			for _, row := range got.Findings {
				if row.Decision != "a" && row.Decision != "b" {
					t.Fatal("foreign or nonmatching event exposed")
				}
			}
		}
	}
	verify()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err = logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	verify()
}

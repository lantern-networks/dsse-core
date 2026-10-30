package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/hotstore"
)

// A failed log search used to answer 400 with the store's own error: the
// ClickHouse URL with every bound search parameter, or ClickHouse's exception
// text. These tests stop the store in the two ways it fails in a deployment
// and read what the caller receives.

func logStoreFailureMux(t *testing.T, store hotstore.Store) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerLogsRetentionRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, nil, nil, newLegalHoldStore(nil), newRetentionOverrideStore(nil))
	return mux
}

func logStoreFailureRequest(t *testing.T, mux *http.ServeMux, path string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "operator", TenantID: "customer"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func closedLocalEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}

func requireLogStoreAnswer(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantMessage string, mustNotContain ...string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status %d, want %d: %s", rec.Code, wantStatus, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the JSON error shape: %v: %s", err, rec.Body.String())
	}
	if len(body) != 1 || body["error"] != wantMessage {
		t.Fatalf("response %q, want only error %q", rec.Body.String(), wantMessage)
	}
	for _, s := range mustNotContain {
		if strings.Contains(rec.Body.String(), s) {
			t.Fatalf("response repeats %q: %s", s, rec.Body.String())
		}
	}
}

func TestUnreachableClickHouseAnswersUnavailableWithoutItsAddressOrSearchTerms(t *testing.T) {
	endpoint := closedLocalEndpoint(t)
	host := strings.TrimPrefix(endpoint, "http://")
	_, port, _ := net.SplitHostPort(host)
	mux := logStoreFailureMux(t, hotstore.NewClickHouseStore(endpoint, "reader", "store-password", "dsse", "events"))
	query := url.Values{"q": {"quarterly-plan"}, "user_id": {"someone@example.test"}}
	for _, path := range []string{"/admin/logs/access", "/admin/logs/access/export"} {
		rec := logStoreFailureRequest(t, mux, path, query)
		requireLogStoreAnswer(t, rec, http.StatusServiceUnavailable, "log store unavailable",
			host, port, "127.0.0.1", "param_", "quarterly-plan", "someone@example.test", "store-password", "dsse")
	}
}

func TestClickHouseErrorAnswersWithoutTheStoresMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Code: 60. DB::Exception: Table dsse.events does not exist. (UNKNOWN_TABLE) SELECT count() FROM dsse.events WHERE tenant_id = {tenant:String}")
	}))
	defer server.Close()
	mux := logStoreFailureMux(t, hotstore.NewClickHouseStore(server.URL, "", "", "dsse", "events"))
	rec := logStoreFailureRequest(t, mux, "/admin/logs/access", url.Values{"q": {"quarterly-plan"}})
	requireLogStoreAnswer(t, rec, http.StatusBadGateway, "log store request failed",
		"DB::Exception", "UNKNOWN_TABLE", "dsse.events", "SELECT", strings.TrimPrefix(server.URL, "http://"), "quarterly-plan")
}

func TestLogSearchStillExplainsTheCallersOwnMistakes(t *testing.T) {
	// The store is never reached for these; a request error must not be
	// reported as a store failure.
	mux := logStoreFailureMux(t, hotstore.NewClickHouseStore(closedLocalEndpoint(t), "", "", "dsse", "events"))
	if rec := logStoreFailureRequest(t, mux, "/admin/logs/access", url.Values{"from": {"yesterday"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "parse from") {
		t.Fatalf("bad time range: %d %s", rec.Code, rec.Body.String())
	}
	if rec := logStoreFailureRequest(t, mux, "/admin/logs/access", url.Values{"cursor": {"not-a-cursor"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "search cursor") {
		t.Fatalf("bad cursor: %d %s", rec.Code, rec.Body.String())
	}
	if rec := logStoreFailureRequest(t, mux, "/admin/logs/no-such-stream", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown stream: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLogSearchWithoutAStoreSaysSo(t *testing.T) {
	mux := logStoreFailureMux(t, nil)
	rec := logStoreFailureRequest(t, mux, "/admin/logs/access", nil)
	requireLogStoreAnswer(t, rec, http.StatusServiceUnavailable, "hot store is not configured")
}

func TestUnrecognizedLogSearchFailureIsNotEchoed(t *testing.T) {
	status, public := adminLogSearchResponseError(errors.New("dial tcp 10.0.0.5:5432: password authentication failed for user dsse"))
	if status != http.StatusInternalServerError || public.Error() != "log search failed" {
		t.Fatalf("got %d %v", status, public)
	}
}

func TestEveryAdminRouteHidesAWrappedStoreFailure(t *testing.T) {
	// writeError is shared by every admin route, so a route that wraps a
	// store failure in its own message still answers with the fixed text.
	_, err := hotstore.NewClickHouseStore(closedLocalEndpoint(t), "", "", "dsse", "events").Search(t.Context(), hotstore.SearchQuery{TenantID: "customer", Stream: "dlp_findings", Text: "salary"})
	if !errors.Is(err, hotstore.ErrUnavailable) {
		t.Fatalf("transport failure is not classified: %v", err)
	}
	for _, wrapped := range []error{err, fmt.Errorf("dlp findings: %w", err), fmt.Errorf("export: %w", &hotstore.ClickHouseHTTPError{StatusCode: 500, Message: "DB::Exception"})} {
		rec := httptest.NewRecorder()
		writeError(rec, http.StatusBadRequest, wrapped)
		if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d for %v", rec.Code, wrapped)
		}
		if body := rec.Body.String(); strings.Contains(body, "127.0.0.1") || strings.Contains(body, "salary") || strings.Contains(body, "DB::Exception") {
			t.Fatalf("response repeats store detail: %s", body)
		}
	}
}

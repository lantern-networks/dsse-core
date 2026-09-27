package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
)

func TestClickHouseRetentionDoesNotPromiseUnenforcedProtection(t *testing.T) {
	holds := newLegalHoldStore(nil)
	retention := newRetentionOverrideStore(nil)
	if err := holds.Set("customer", "operator", "existing", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := retention.Set("audit", 365); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerLogsRetentionRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, hotstore.NewClickHouseStore("http://unused", "", "", "dsse", "events"), nil, nil, holds, retention)
	for _, op := range []struct{ method, path, body string }{
		{"GET", "/admin/legal-hold", ""},
		{"GET", "/admin/retention-config", ""},
		{"POST", "/admin/legal-hold", `{"active":false}`},
		{"POST", "/admin/legal-hold", `{"active":true}`},
		{"POST", "/admin/retention-config", `{"stream":"audit","days":1}`},
		{"POST", "/admin/retention-config", `{"stream":"audit","clear":true}`},
	} {
		req := httptest.NewRequest(op.method, op.path, strings.NewReader(op.body))
		req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "operator", TenantID: "customer"})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "not enforced for ClickHouse") {
			t.Fatalf("%s %s: %d %s", op.method, op.path, rec.Code, rec.Body.String())
		}
	}
	if d, ok := retention.Get("audit"); !ok || d != 365 {
		t.Fatal("unsupported request changed retention")
	}
	if !holds.IsHeld("customer") {
		t.Fatal("unsupported request changed hold")
	}
}

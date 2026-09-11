package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// Phase 1 write-path inversion (design / 1c): an Edge that PULLS its config from a control plane
// (ConfigSourceURL set) must REJECT writes to the bundle-distributed config resources with 409 — config has
// ONE source of truth (the CP), and a node-local write would be overwritten by the next pull. Reads stay
// open. An authoritative-local Edge (no source) still accepts the writes.
func TestConfigWritePathInversionRejectsOnPuller(t *testing.T) {
	mk := func(sourceURL string) http.Handler {
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}
		return newServerWithConfig(serverConfig{
			Evaluator:       testEvaluator(),
			Writer:          writer,
			Registry:        connector.NewRegistry(),
			AdminAuth:       newAdminAuthStore(),
			ConfigSourceURL: sourceURL,
		})
	}
	call := func(h http.Handler, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	puller := mk("https://controlplane:9443")
	authoritative := mk("")

	// Every bundle-distributed config WRITE is rejected with 409 on a puller Edge.
	writes := []struct{ path, body string }{
		{"/admin/policies", `{"id":"p1","tenant_id":"t","priority":1,"conditions":{"service_family":"ssh"},"action":{"decision":"deny"},"status":"active"}`},
		{"/admin/east-west", `{"enabled":true}`},
		{"/admin/server-initiated", `{"enabled":true}`},
		{"/admin/legacy-exceptions", `{"id":"lx1","status":"active"}`},
		{"/admin/enrolled-devices", `{"identity":"dev-x"}`},
		{"/admin/vlan-objects", `{"id":"o1","class":"server","cidrs":["10.0.0.0/24"]}`},
		{"/admin/vlan-boundary-policies", `{"id":"p1","source_class":"server","dest_class":"server","mode":"deny"}`},
	}
	for _, wr := range writes {
		if code := call(puller, http.MethodPost, wr.path, wr.body); code != http.StatusConflict {
			t.Fatalf("puller POST %s: want 409, got %d", wr.path, code)
		}
	}

	// DNS policy is a PUT (separate store, also bundle-distributed) — rejected on a puller too.
	if code := call(puller, http.MethodPut, "/admin/dns-policy", `{"deny":["evil.example"]}`); code != http.StatusConflict {
		t.Fatalf("puller PUT /admin/dns-policy: want 409, got %d", code)
	}

	// Reads are NOT gated on a puller (debugging stays available).
	if code := call(puller, http.MethodGet, "/admin/east-west", ""); code != http.StatusOK {
		t.Fatalf("puller GET /admin/east-west should stay open: got %d", code)
	}

	// The same writes are ACCEPTED on an authoritative-local Edge (server-initiated is tenant-agnostic and
	// needs no extra setup, so it's the clean positive case).
	if code := call(authoritative, http.MethodPost, "/admin/server-initiated", `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("authoritative POST /admin/server-initiated: want 200, got %d", code)
	}
}

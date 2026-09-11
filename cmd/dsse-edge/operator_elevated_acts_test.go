package main

import (
	"net/http"
	"strings"
	"testing"
)

// The list has to match the routes that actually exist. A pattern that matches nothing is a rule everybody
// believes is in force and nothing enforces — the shape this repository keeps paying for.
func TestEveryElevatedActNamesARouteThatExists(t *testing.T) {
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore()})
	mux, ok := handler.(*http.ServeMux)
	if !ok {
		t.Skip("the admin handler is not a mux in this build")
	}
	for _, act := range operatorElevatedActs {
		// A concrete path built from the pattern, with each wildcard filled by a plausible value.
		concrete := strings.ReplaceAll(act.Path, "*", "probe")
		req, err := http.NewRequest(act.Method, concrete, nil)
		if err != nil {
			t.Fatalf("%s %s: %v", act.Method, concrete, err)
		}
		if _, pattern := mux.Handler(req); strings.TrimSpace(pattern) == "" {
			t.Fatalf("%s %s is on the elevated list and no route serves it — the rule is inert",
				act.Method, act.Path)
		}
		if strings.TrimSpace(act.Why) == "" {
			t.Fatalf("%s %s is on the list with no reason; a list nobody can argue with only grows",
				act.Method, act.Path)
		}
	}
}

// And the matcher must not classify the daily work as destructive, nor miss the destructive act because the
// path carried a different organization id.
func TestTheElevatedListSeparatesTheDailyWorkFromTheDestructiveAct(t *testing.T) {
	destructive := []struct{ method, path string }{
		{http.MethodPost, "/admin/interception-intermediate/tenant_northwind/revoke"},
		{http.MethodPost, "/admin/interception-intermediate/tenant_acme"},
		{http.MethodDelete, "/admin/tenant-cas/tenant_northwind/728acc9d"},
		{http.MethodDelete, "/admin/tenant-cas/tenant_northwind"},
		{http.MethodPost, "/admin/transport-admission/revoke"},
	}
	for _, act := range destructive {
		if why, needs := operatorActNeedsElevation(act.method, act.path); !needs || why == "" {
			t.Fatalf("%s %s is not classified as needing elevation", act.method, act.path)
		}
	}

	daily := []struct{ method, path string }{
		{http.MethodPost, "/admin/tenant-cas"},                             // registering a CA, not withdrawing one
		{http.MethodGet, "/admin/tenant-cas"},                              // reading
		{http.MethodPost, "/admin/policies"},                               // ordinary policy work
		{http.MethodPost, "/admin/transport-admission/restore"},            // undoing a kill-switch is not one
		{http.MethodPost, "/admin/enrolled-devices/nw-laptop-001/disable"}, // reversible, one device
		{http.MethodGet, "/admin/interception-intermediate/tenant_acme"},   // reading the same path
	}
	for _, act := range daily {
		if _, needs := operatorActNeedsElevation(act.method, act.path); needs {
			t.Fatalf("%s %s was classified as destructive; the daily work would need ceremony every time",
				act.method, act.path)
		}
	}
}

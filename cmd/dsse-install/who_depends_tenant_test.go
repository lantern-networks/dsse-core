package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWhoDependsCountsSameIdentityInDifferentTenants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/tenants":
			w.Write([]byte(`{"tenants":[{"tenant_id":"Acme"},{"tenant_id":"acme"}]}`))
		case "/admin/enrolled-devices":
			if r.URL.Query().Get("tenant_id") == "Acme" {
				w.Write([]byte(`{"devices":[{"identity":"shared","kind":"endpoint"}]}`))
			} else {
				w.Write([]byte(`{"devices":[{"identity":"shared","kind":"connector"}]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result := verifyWhoDepends(server.Client(), server.URL, "test-token")
	if len(result) == 0 || !result[0].ok || !strings.Contains(result[0].note, "2 enrolled identity(ies), of which 1 are endpoints") {
		t.Fatalf("tenants collapsed in stop-safety report: %+v", result)
	}
}

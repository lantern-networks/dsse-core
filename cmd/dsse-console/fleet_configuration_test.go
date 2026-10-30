package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleDoesNotProxyFleetSecrets(t *testing.T) {
	calls := 0
	h := withoutFleetConfigurationProxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	for _, path := range []string{"/admin/config-bundle", "/admin/authentication-grants", "/control/admin/config-bundle", "/control/admin/authentication-grants", "/admin/./config-bundle", "/control/admin/authentication-grants/", "/admin/%63onfig-bundle"} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, path+"?tenant_id=operator", nil))
			if w.Code != 404 || calls != 0 {
				t.Fatal("fleet snapshot reached Console upstream", method, path, w.Code)
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/policies", nil))
	if w.Code != 204 || calls != 1 {
		t.Fatal("ordinary tenant API was blocked")
	}
}

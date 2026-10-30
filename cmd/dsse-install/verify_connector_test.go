package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyConnectorRejectsSuccessfulEnrollmentWithoutCertificate(t *testing.T) {
	var removedDevice, removedSite bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/admin/sites":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/enrollment-command"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"bootstrap_secret":"test-only-secret","tenant_id":"tenant-a"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/enroll":
			var request struct {
				Tenant string `json:"tenant"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode enrollment request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if request.Tenant != "tenant-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// An HTTP success alone is not an issued identity.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/admin/enrolled-devices/"):
			removedDevice = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/admin/sites/"):
			removedSite = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected verification request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	results := verifyConnector(server.Client(), t.TempDir(), server.URL, server.URL, server.URL, "test-token", "tenant-a")
	var enrollmentFailed, placementFailed bool
	for _, result := range results {
		switch result.name {
		case "a connector can enrol through the Edge":
			enrollmentFailed = !result.ok
		case "the connector can take its place":
			placementFailed = !result.ok
		}
	}
	if !enrollmentFailed || !placementFailed {
		t.Fatalf("HTTP 200 without an issued certificate passed verification: %+v", results)
	}
	if !removedDevice || !removedSite {
		t.Fatalf("verification artifacts were not removed: device=%t site=%t", removedDevice, removedSite)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublishedReleasesComparePeersWhenFirstIsEmpty(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/agent-updates" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"envelopes":{},"pending":{}}`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/agent-updates" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"envelopes":{"darwin/arm64":{"payload_sha256":"test-digest"}},"pending":{}}`))
	}))
	defer second.Close()
	results := verifyPublishedReleasesAreShared(first.Client(), []string{first.URL, second.URL}, "test-token")
	if len(results) != 1 || results[0].ok || !strings.Contains(results[0].note, "offers 0 release") {
		t.Fatalf("different release catalogs were reported shared: %+v", results)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMuxOnlyProfileRejectsLegacySocketSessions(t *testing.T) {
	legacyCalls := 0
	legacy := func(w http.ResponseWriter, _ *http.Request) {
		legacyCalls++
		w.WriteHeader(http.StatusNoContent)
	}
	request := httptest.NewRequest(http.MethodPost, "/network-extension/runtime-copy/session", nil)
	blocked := httptest.NewRecorder()
	legacySessionRoute(true, legacy)(blocked, request)
	if blocked.Code != http.StatusUpgradeRequired || legacyCalls != 0 {
		t.Fatalf("mux-only profile used a legacy socket session: HTTP %d, calls %d", blocked.Code, legacyCalls)
	}
	ordinary := httptest.NewRecorder()
	legacySessionRoute(false, legacy)(ordinary, request)
	if ordinary.Code != http.StatusNoContent || legacyCalls != 1 {
		t.Fatalf("existing profile changed: HTTP %d, calls %d", ordinary.Code, legacyCalls)
	}
}

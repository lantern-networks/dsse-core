package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// the ledger admits only enrolled AND enabled identities; enroll/disable/enable/remove mutate it.
func TestEnrolledInventoryLedger(t *testing.T) {
	l := enrolledinventory.NewLedger()
	l.SeedFromStatic(map[string]struct{}{"Mac-Dev-1": {}}, "t0")

	if !l.IsAdmitted("mac-dev-1") || !l.IsAdmitted("MAC-DEV-1") {
		t.Fatal("seeded identity should be admitted (case-insensitive)")
	}
	if l.IsAdmitted("rogue") {
		t.Fatal("unknown identity must not be admitted")
	}
	// Disable = manual revocation: stays on the list but denied.
	if _, ok := l.SetEnabled("mac-dev-1", false, "t1"); !ok || l.IsAdmitted("mac-dev-1") {
		t.Fatal("disabled identity must be denied")
	}
	// Re-enable.
	if _, ok := l.SetEnabled("mac-dev-1", true, "t2"); !ok || !l.IsAdmitted("mac-dev-1") {
		t.Fatal("re-enabled identity must be admitted")
	}
	// Enroll a new one.
	if _, err := l.Enroll("win-dev-2", "tnt", "note", "t3"); err != nil || !l.IsAdmitted("win-dev-2") {
		t.Fatalf("enroll: err=%v admitted=%v", err, l.IsAdmitted("win-dev-2"))
	}
	if _, err := l.Enroll("   ", "tnt", "", "t3"); err == nil {
		t.Fatal("empty identity enroll must fail")
	}
	// Remove.
	if !l.Remove("win-dev-2", "2026-08-24T00:00:00Z") || l.IsAdmitted("win-dev-2") {
		t.Fatal("removed identity must be denied")
	}
	if l.Remove("ghost", "2026-08-24T00:00:00Z") {
		t.Fatal("removing absent identity should report false")
	}
	if names := l.List(); len(names) != 1 || names[0].Identity != "mac-dev-1" {
		t.Fatalf("list should hold only mac-dev-1, got %+v", names)
	}
}

// the (T) admission gate consults the ledger LIVE — a Console disable denies the next handshake
// with no restart (hot-apply).
func TestTransportAdmissionConsultsLedgerHotApply(t *testing.T) {
	l := enrolledinventory.NewLedger()
	l.SeedFromStatic(map[string]struct{}{"mac-dev-1": {}}, "t0")
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr:              "127.0.0.1:0",
		LabAutoCert:             true,
		LabMode:                 true,
		RequireEnrolledIdentity: true,
		EnrolledLedger:          l,
	})
	if err != nil {
		t.Fatalf("buildSecureTransportTLSConfig: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("expected admission gate")
	}
	// Enrolled + enabled -> admitted.
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err != nil {
		t.Fatalf("enrolled+enabled should be admitted: %v", err)
	}
	// Disable via the ledger -> the SAME cfg now denies (live consult, no rebuild).
	l.SetEnabled("mac-dev-1", false, "t1")
	if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err == nil {
		t.Fatal("disabled identity must be denied at the next handshake (hot-apply)")
	}
	// Unknown identity denied.
	if err := cfg.VerifyConnection(csWithCN("rogue")); err == nil {
		t.Fatal("unenrolled identity must be denied")
	}
}

// the admin ledger endpoints enroll/list/disable/enable/remove (API-first / ).
func TestAdminEnrolledDevicesEndpoints(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		EnrolledLedger: enrolledinventory.NewLedger(),
		Writer:         writer,
		Registry:       connector.NewRegistry(),
		AdminAuth:      newAdminAuthStore(),
	})
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Enroll -> list reflects it.
	if rec := do(http.MethodPost, "/admin/enrolled-devices", `{"identity":"win-dev-9","note":"laptop"}`); rec.Code != http.StatusOK {
		t.Fatalf("enroll: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/admin/enrolled-devices", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "win-dev-9") {
		t.Fatalf("list must include win-dev-9: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Disable -> entry shows enabled:false.
	if rec := do(http.MethodPost, "/admin/enrolled-devices/win-dev-9/disable", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("disable: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Enable -> back to enabled:true.
	if rec := do(http.MethodPost, "/admin/enrolled-devices/win-dev-9/enable", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("enable: code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Remove -> gone; enable on a removed identity is 404.
	if rec := do(http.MethodDelete, "/admin/enrolled-devices/win-dev-9", ""); rec.Code != http.StatusOK {
		t.Fatalf("remove: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodPost, "/admin/enrolled-devices/win-dev-9/enable", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("enable on removed identity must be 404; got %d", rec.Code)
	}
	// Missing identity on enroll -> 400.
	if rec := do(http.MethodPost, "/admin/enrolled-devices", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty identity must be 400; got %d", rec.Code)
	}
}

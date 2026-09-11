package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

func TestNormalizeAssetPlatform(t *testing.T) {
	cases := map[string]string{
		"macOS":      "macos",
		"macOS 14.5": "macos",
		"Mac OS X":   "macos",
		"Windows":    "windows",
		"Windows 11": "windows",
		"windows":    "windows",
		"  macOS  ":  "macos",
		"":           "",
		"Linux":      "",
		"iOS":        "", // lowercases to "ios" — contains neither "mac" nor "win"
	}
	for in, want := range cases {
		if got := normalizeAssetPlatform(in); got != want {
			t.Errorf("normalizeAssetPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

// An enrolled device auto-appears in the product edge's asset catalog as a steered endpoint (no manual
// entry), and a dynamic group resolves it — end-to-end through the real /admin/assets/* handlers.
func TestAdminAssetCatalogAutoPopulatesEnrolledAndResolvesGroup(t *testing.T) {
	devices := devicestore.NewStore()
	now := time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC)
	if _, err := devices.Register(model.Device{
		ID:                  "dev_asset_seed_001",
		TenantID:            "tenant_lab_001",
		UserID:              "user_lab_001",
		Hostname:            "alice-mac.local",
		OS:                  "macos",
		OSVersion:           "15.5",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Status:              "healthy",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
	}, testEvaluator().PolicyBundle, now); err != nil {
		t.Fatalf("register seed device: %v", err)
	}
	// The device is enrolled — the authoritative source the catalog auto-populates from. The device
	// store enriches its hostname/OS.
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("dev_asset_seed_001", testEvaluator().PolicyBundle.TenantID, "", now.Format("2006-01-02T15:04:05Z07:00")); err != nil {
		t.Fatalf("enroll device: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:      testEvaluator(),
		Registry:       connector.NewRegistry(),
		AdminAuth:      newAdminAuthStore(),
		DeviceStore:    devices,
		EnrolledLedger: ledger,
	})

	// The enrolled device is present in the catalog as a steered macOS endpoint with no manual entry.
	var eps []assetcatalog.Endpoint
	if rec := doAdmin(t, handler, http.MethodGet, "/admin/assets/endpoints", ""); rec.Code != http.StatusOK {
		t.Fatalf("list endpoints status = %d, body=%s", rec.Code, rec.Body.String())
	} else if err := json.Unmarshal(rec.Body.Bytes(), &eps); err != nil {
		t.Fatalf("decode endpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("assets endpoints = %#v, want 1 auto-populated enrolled endpoint", eps)
	}
	got := eps[0]
	if got.Kind != assetcatalog.KindSteeredDevice || got.Source != assetcatalog.SourceEnrolled || got.Platform != "macos" || !got.Steered {
		t.Fatalf("enrolled endpoint = %#v, want steered macos enrolled", got)
	}
	if got.Identity != "dev_asset_seed_001" || got.Alias != "alice-mac.local" {
		t.Fatalf("enrolled endpoint identity/alias = %q/%q, want device id/hostname", got.Identity, got.Alias)
	}

	// A dynamic group by platform resolves the enrolled device as a member.
	var group assetcatalog.Group
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/assets/groups", `{"alias":"macs","dynamic":{"platform":"macos"}}`); rec.Code != http.StatusOK {
		t.Fatalf("create group status = %d, body=%s", rec.Code, rec.Body.String())
	} else if err := json.Unmarshal(rec.Body.Bytes(), &group); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	var members []string
	if rec := doAdmin(t, handler, http.MethodGet, "/admin/assets/groups/"+group.ID+"/members", ""); rec.Code != http.StatusOK {
		t.Fatalf("group members status = %d, body=%s", rec.Code, rec.Body.String())
	} else if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil {
		t.Fatalf("decode members: %v", err)
	}
	if len(members) != 1 || members[0] != got.ID {
		t.Fatalf("dynamic group members = %#v, want the enrolled mac endpoint id %q", members, got.ID)
	}
}

func doAdmin(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("content-type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ★★ SETTING data_residency IS NOW AN ERROR (2026-08-19, operator decision after measuring).
//
// The field was accepted, normalised, persisted in its own Postgres column and counted in the deletion
// footprint, and nothing consulted it. What actually places an organization is home_region / allowed_regions.
// A field that changes nothing is worse than a field that does not exist, and worse still when its NAME is a
// compliance promise: a reader who sees "data_residency: jp" concludes something is being enforced.
//
// Same treatment POST /admin/admins/invite gives a body tenant_id.
func TestSettingDataResidencyIsRefused(t *testing.T) {
	rec := httptest.NewRecorder()
	if !adminTenantRefuseResidency(rec, []byte(`{"tenant_id":"tenant_x","data_residency":"jp"}`)) {
		t.Fatal("a write naming data_residency was accepted, so the product still takes a value it does not act on")
	}
	if body := rec.Body.String(); !strings.Contains(body, "home_region") {
		t.Fatalf("the refusal does not say what DOES decide placement: %q", body)
	}

	// Absent and empty are not attempts to set it. A client echoing a record back — which is how a full-model
	// upsert works on this surface — must not be refused for a field it never touched.
	for _, body := range []string{
		`{"tenant_id":"tenant_x"}`,
		`{"tenant_id":"tenant_x","data_residency":""}`,
		`{"tenant_id":"tenant_x","data_residency":"   "}`,
	} {
		if adminTenantRefuseResidency(httptest.NewRecorder(), []byte(body)) {
			t.Fatalf("refused a body that does not set data_residency: %s", body)
		}
	}

	// ★ THE CONTROL THAT MATTERS MOST: an EXISTING value must still store. Every persistence path runs through
	// normalisation, including the config-bundle apply that upserts whatever the control plane holds — so
	// refusing there instead of at the route would turn one old value into a distribution that stops applying.
	existing := adminTenantModel{TenantID: "tenant_x", DisplayName: "X", Status: "active", DataResidency: "jp"}
	if _, err := normalizeAdminTenantModel(existing, "tenant_x", time.Now()); err != nil {
		t.Fatalf("a record that already carries data_residency can no longer be stored, so the bundle apply "+
			"would stop on it: %v", err)
	}
}

package main

import (
	"strings"
	"testing"
	"time"
)

// A deployment can be perfectly configured and about to stop working. The assessment asked whether each piece
// was CONFIGURED and never whether it was about to expire, so "ready for real traffic" could be true with a
// certificate lapsing the following week. Certificates give no warning: they work exactly as well as they do
// today until the moment they do not, and then everything depending on them fails at once.
func TestReadinessTreatsImminentExpiryAsBlocking(t *testing.T) {
	base := pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		IntermediateActive: true, EnrollConfigured: true, EnrollAdminTokens: true,
		RenewalEndpoint: true, RecoveryListener: true,
		SoonestExpiryHave: true, SoonestExpiryWhat: "the certificate held by mac-dev-1",
	}

	for _, tc := range []struct {
		name       string
		in         time.Duration
		wantStatus string
		wantBlocks bool
	}{
		{name: "already expired blocks", in: -time.Hour, wantStatus: "missing", wantBlocks: true},
		{name: "days away blocks", in: 6 * 24 * time.Hour, wantStatus: "missing", wantBlocks: true},
		{name: "weeks away needs attention", in: 30 * 24 * time.Hour, wantStatus: "attention"},
		{name: "far away is fine", in: 300 * 24 * time.Hour, wantStatus: "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.SoonestExpiryIn = tc.in
			report := assessPKIReadiness(in)

			var item *pkiReadinessItem
			for i := range report.Items {
				if report.Items[i].ID == "expiry" {
					item = &report.Items[i]
				}
			}
			if item == nil {
				t.Fatalf("no expiry item in the report")
			}
			if item.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", item.Status, tc.wantStatus)
			}
			// Everything else here is configured, so the deployment's safety turns on this item alone.
			if tc.wantBlocks && report.ProductionSafe {
				t.Fatalf("a fully configured deployment was called ready with %v until expiry", tc.in)
			}
			if !tc.wantBlocks && !report.ProductionSafe {
				t.Fatalf("expiry %v should not block a fully configured deployment", tc.in)
			}
			// Naming the thing is the difference between a warning and an instruction.
			if item.Status != "ok" && !strings.Contains(item.Detail+item.Remediation, "mac-dev-1") {
				t.Fatalf("the item does not say WHAT expires: %+v", item)
			}
		})
	}
}

// With nothing measurable, the item is absent rather than reported as fine. A deployment that cannot see any
// expiry is not one where nothing expires.
func TestReadinessOmitsExpiryWhenNothingIsKnown(t *testing.T) {
	report := assessPKIReadiness(pkiReadinessInput{EnrollConfigured: true})
	for _, item := range report.Items {
		if item.ID == "expiry" {
			t.Fatalf("expiry was reported without anything to measure: %+v", item)
		}
	}
}

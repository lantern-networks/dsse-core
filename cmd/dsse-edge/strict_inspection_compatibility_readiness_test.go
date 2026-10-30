package main

import (
	"strings"
	"testing"
)

// A completed port fold and working key custody do not make strict clients accept
// inspection certificates. Keep that failure visible without prescribing disabled checks.
func TestStrictInspectionCompatibilityRemainsVisible(t *testing.T) {
	base := pkiReadinessInput{
		KeyCustody: "pkcs11", KeyCustodyChecked: true, KeyCustodyHealthy: true,
		EnrollConfigured: true, EnrollIdPBacked: true, RenewalEndpoint: true,
	}
	without := assessPKIReadiness(base)
	for _, item := range without.Items {
		if item.ID == "interception_leaf_revocation" {
			t.Fatal("inspection compatibility warning before an intermediate is active")
		}
	}
	base.IntermediateActive = true
	with := assessPKIReadiness(base)
	item := pkiReadinessItemByID(t, with, "interception_leaf_revocation")
	if item.Status != "attention" || with.Attention == 0 {
		t.Fatalf("compatibility warning lost in the summary: before=%+v after=%+v", without, with)
	}
	if item.Blocking {
		t.Fatal("compatibility attention was conflated with unsafe key custody")
	}
	if !strings.Contains(item.Consequence, "CRYPT_E_NO_REVOCATION_CHECK") ||
		!strings.Contains(item.Consequence, "RevocationStatusUnknown") {
		t.Fatalf("known strict-client failures are absent: %s", item.Consequence)
	}
	for _, obsolete := range []string{"wait for the agent plane", "Nothing here is waiting to be built", "Allow the exception", "--ssl-no-revoke"} {
		if strings.Contains(item.Remediation, obsolete) {
			t.Fatalf("obsolete or weakened-check guidance: %s", item.Remediation)
		}
	}
	if !strings.Contains(item.Remediation, "Keep client revocation checking enabled") {
		t.Fatalf("remediation does not preserve the strict acceptance condition: %s", item.Remediation)
	}
}

func pkiReadinessItemByID(t *testing.T, report pkiReadinessReport, id string) pkiReadinessItem {
	t.Helper()
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("no readiness item %q — this test is measuring nothing", id)
	return pkiReadinessItem{}
}

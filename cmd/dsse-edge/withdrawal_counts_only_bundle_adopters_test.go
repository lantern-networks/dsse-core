package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ A CLIENT THE WITHDRAWAL CANNOT REACH WAS HOLDING IT BACK (2026-08-19).
//
// Ending an overlap — the Edge stopping the announcement of an authority devices are moving off — is gated on
// every enrolled identity having taken the distribution that carries the replacement. A connector never takes
// one: it pins the Edge CA handed to it at enrolment and reads no trust bundle, so it can neither confirm the
// move nor be harmed by what a bundle stops announcing. Counting it made roadmap D's last step unreachable,
// and it would have stayed unreachable for as long as the connector ran.
//
// Both directions: a service identity must not be counted, and an endpoint must — the narrowing's failure mode
// is a withdrawal that should have been refused, so the endpoint half is the half that matters.
func TestOnlyIdentitiesThatAdoptBundlesAreCountedForAWithdrawal(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, d := range []struct{ id, kind string }{
		{"mac-dev-1", ""}, // empty Kind means endpoint, as everywhere else
		{"win-dev-1", enrolledinventory.KindEndpoint},   //
		{"conn_lab_001", enrolledinventory.KindService}, // a connector: pins its CA at enrolment, reads no bundle
	} {
		if _, err := ledger.Enroll(d.id, "tenant_reference_lab", "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", d.id, err)
		}
		if d.kind != "" {
			if _, ok, err := ledger.SetKind(d.id, d.kind, stamp); err != nil || !ok {
				t.Fatalf("declare %s as %q: ok=%v err=%v", d.id, d.kind, ok, err)
			}
		}
	}

	known := enabledEnrolledIdentities(serverConfig{EnrolledLedger: ledger, TenantIDForTrust: "tenant_reference_lab"})
	has := func(id string) bool {
		for _, k := range known {
			if k == id {
				return true
			}
		}
		return false
	}
	if has("conn_lab_001") {
		t.Fatal("a service identity is counted as a device that must adopt the distribution — the withdrawal " +
			"can then never complete, on a client it does not affect")
	}
	if !has("mac-dev-1") || !has("win-dev-1") {
		t.Fatalf("a managed device was dropped from the denominator: %v — a withdrawal could complete while a "+
			"device that needs the new authority has not taken it", known)
	}
}

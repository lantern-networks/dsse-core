package enrolledinventory

import (
	"strings"
	"testing"
)

// merge_unknown_local_test.go — what happens to a device that enrolled HERE and that the control plane has
// never heard of.
//
// ★ WHY THIS IS PINNED RATHER THAN FIXED (2026-08-14, establishing decision 4's prerequisite). POST /enroll
// writes to this ledger and tells the control plane nothing. MergeAuthoritative rebuilds the ledger from the
// CP's list — it preserves the enrolment MARKER for identities the CP also names, which is the twenty-first
// review's fix, but an identity the CP does not name at all is simply not in the new map.
//
// So the earlier finding is half closed. "An unrelated control-plane change makes an enrolled device
// enrollable again" is fixed. "An unrelated control-plane change ERASES a device the CP never knew about" is
// not, and it is the half that matters for the OSS transition: Operator Quota counts this ledger, so a
// silently short ledger both under-reports the count (admitting devices past the operator's own limit) and
// leaves a real device holding a valid certificate that transport will refuse.
//
// The union is NOT the obvious fix, which is why this pins the behaviour instead of changing it. If local
// entries always survived, an administrator could never remove a device: absence from the CP's list would mean
// "keep" for both "I deleted this" and "I never knew this" — the same conflation that deleted 47 operator
// assets in this codebase once already. The real answer is for enrolment to reach the control plane, which is
// a design change, not a merge tweak.

func TestAnEnrolmentTheControlPlaneNeverSawIsDropped(t *testing.T) {
	l := NewLedger()
	// A device enrols here. This is exactly what POST /enroll does, and it writes nowhere else.
	if _, err := l.EnrollDeviceForTenant("laptop-42", "tenant_a", "", "enrolled via POST /enroll", "2026-08-14T00:00:00Z"); err != nil {
		t.Fatalf("local enrolment: %v", err)
	}
	if _, ok := l.EntryFor("laptop-42"); !ok {
		t.Fatal("the device should be in the ledger immediately after enrolling")
	}

	// Any control-plane bundle then arrives carrying a NON-EMPTY inventory that does not mention it — which is
	// every bundle, because nothing ever told the control plane this device exists. Non-empty matters: the
	// lockout guard in config_bundle_sync only declines to apply when the CP sends ZERO entries.
	if err := l.MergeAuthoritative([]Entry{
		{Identity: "seeded-1", TenantID: "tenant_a", Enabled: true},
	}, "2026-08-14T00:05:00Z"); err != nil {
		t.Fatalf("merge: %v", err)
	}

	if _, ok := l.EntryFor("laptop-42"); ok {
		t.Fatal("BEHAVIOUR CHANGED: the locally-enrolled device now survives a control-plane merge.\n" +
			"That may well be the intended fix — but it means absence from the CP's list no longer removes\n" +
			"anything, so check that an administrator can still delete a device, and update the transition\n" +
			"plan, which records this drop as the prerequisite for Operator Quota.")
	}
}

// ★ THE DROP MUST AT LEAST BE AUDIBLE. It cannot be silent: the operator's two visible consequences — a device
// that stops being admitted, and a quota count that is short — both point away from the config bundle, and
// nothing in the logs connected them to it.
func TestTheDropNamesWhatItDropped(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("laptop-42", "tenant_a", "", "enrolled via POST /enroll", "2026-08-14T00:00:00Z"); err != nil {
		t.Fatalf("local enrolment: %v", err)
	}
	if _, err := l.EnrollDeviceForTenant("laptop-43", "tenant_a", "", "enrolled via POST /enroll", "2026-08-14T00:01:00Z"); err != nil {
		t.Fatalf("local enrolment: %v", err)
	}
	dropped := l.MergeAuthoritativeDropped([]Entry{{Identity: "seeded-1", TenantID: "tenant_a", Enabled: true}},
		"2026-08-14T00:05:00Z")
	got := strings.Join(dropped, ",")
	if !strings.Contains(got, "laptop-42") || !strings.Contains(got, "laptop-43") {
		t.Fatalf("both locally-enrolled identities must be reported as dropped, got %q", got)
	}
	// An entry the CP never knew about and that NO device ever enrolled against is a different case: it was
	// pre-added or seeded locally, carries no certificate, and losing it costs nobody their access. Reporting
	// those too would bury the ones that matter.
	l2 := NewLedger()
	l2.Enroll("preadded-1", "tenant_a", "note", "2026-08-14T00:00:00Z")
	if d := l2.MergeAuthoritativeDropped([]Entry{{Identity: "seeded-1", Enabled: true}}, "2026-08-14T00:05:00Z"); len(d) != 0 {
		t.Fatalf("an identity no device ever enrolled against must not be reported as a lost enrolment, got %v", d)
	}
}

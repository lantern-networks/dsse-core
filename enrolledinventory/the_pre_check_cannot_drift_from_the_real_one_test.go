package enrolledinventory

import (
	"errors"
	"testing"
)

// WouldRefuseEnrolment exists so a caller can ask before it spends a one-time approval it cannot get back.
// Its danger is the ordinary danger of a second copy of a decision: the two drift, and the cheap one starts
// saying yes to what the real one refuses — which would put the spend back on the wrong side of the refusal
// without anything looking different.
//
// So every case is asked BOTH ways and the answers must match.
func TestThePreCheckAgreesWithTheWriteItGuards(t *testing.T) {
	const now = "2026-08-29T00:00:00Z"
	cases := []struct {
		name  string
		setUp func(l *Ledger)
		id    string
		mref  string
	}{
		{"never seen", func(l *Ledger) {}, "fresh-1", ""},
		{"pre-approved but never enrolled", func(l *Ledger) {
			if _, err := l.EnrollGroupForTenant("waiting-1", "", "tenant_a", "", "", now, true); err != nil {
				t.Fatalf("set up: %v", err)
			}
		}, "waiting-1", ""},
		{"already enrolled, no machine reference", func(l *Ledger) {
			if _, _, err := l.EnrollDeviceForTenantWithMachine("done-1", "tenant_a", "", "", now, ""); err != nil {
				t.Fatalf("set up: %v", err)
			}
		}, "done-1", ""},
		{"already enrolled, same machine", func(l *Ledger) {
			if _, _, err := l.EnrollDeviceForTenantWithMachine("done-2", "tenant_a", "", "", now, "mref-2"); err != nil {
				t.Fatalf("set up: %v", err)
			}
		}, "done-2", "mref-2"},
		{"already enrolled, a different machine with the same name", func(l *Ledger) {
			if _, _, err := l.EnrollDeviceForTenantWithMachine("done-3", "tenant_a", "", "", now, "mref-3"); err != nil {
				t.Fatalf("set up: %v", err)
			}
		}, "done-3", "mref-other"},
		{"removed by an administrator", func(l *Ledger) {
			if _, _, err := l.EnrollDeviceForTenantWithMachine("gone-1", "tenant_a", "", "", now, ""); err != nil {
				t.Fatalf("set up: %v", err)
			}
			if !l.Remove("gone-1", now) {
				t.Fatal("set up: remove")
			}
		}, "gone-1", ""},
		{"the machine is enrolled under another name", func(l *Ledger) {
			if _, _, err := l.EnrollDeviceForTenantWithMachine("old-name", "tenant_a", "", "", now, "mref-9"); err != nil {
				t.Fatalf("set up: %v", err)
			}
		}, "new-name", "mref-9"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := NewLedger()
			c.setUp(l)
			asked := l.WouldRefuseEnrolment(c.id, "tenant_a", c.mref)
			_, _, real := l.EnrollDeviceForTenantWithMachine(c.id, "tenant_a", "", "", now, c.mref)
			switch {
			case asked == nil && real == nil:
			case asked == nil && real != nil:
				t.Fatalf("the pre-check said yes and the write refused with %v — the approval would be spent "+
					"on the way to that refusal, which is the defect this function exists to end", real)
			case asked != nil && real == nil:
				t.Fatalf("the pre-check refused with %v and the write allowed it — enrolment turned away for "+
					"nothing", asked)
			case !errors.Is(real, asked):
				t.Fatalf("both refused but not with the same reason: pre-check %v, write %v", asked, real)
			}
		})
	}
}

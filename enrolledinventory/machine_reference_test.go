package enrolledinventory

import (
	"errors"
	"testing"
)

// ★★★ A SECOND ENROLMENT OF ONE NAME HAS THREE CAUSES, AND THE DEPLOYMENT HAD ONE SENTENCE FOR ALL OF THEM.
// Since a device enrols under the name its own operating system gives it, two machines called "laptop" are
// ordinary — and the one-time token is spent by the time anybody reads the refusal, so guessing wrong costs a
// trip through an administrator.

const (
	machineA = "11111111-1111-1111-1111-111111111111"
	machineB = "22222222-2222-2222-2222-222222222222"
)

func enrolled(t *testing.T, l *Ledger, id, machine string) {
	t.Helper()
	if _, _, err := l.EnrollDeviceForTenantWithMachine(id, "tenant_a", "", "", "2026-08-25T00:00:00Z", machine); err != nil {
		t.Fatalf("first enrolment of %q: %v", id, err)
	}
}

// The same machine coming back is a renewal. Telling it to rename itself would be wrong.
func TestTheSameMachineIsToldToRenew(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	_, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T01:00:00Z", machineA)
	if !errors.Is(err, ErrSameMachineAlreadyEnrolled) {
		t.Fatalf("want the same machine told to renew, got %v", err)
	}
}

// A namesake cannot renew — it holds no certificate to prove — so it has to be told the other thing.
func TestADifferentMachineWithTheSameNameIsToldToRename(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	_, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T01:00:00Z", machineB)
	if !errors.Is(err, ErrDifferentMachineSameName) {
		t.Fatalf("want the namesake told to rename, got %v", err)
	}
}

// ★ THE RENAMED MACHINE IS THE ONE THAT WOULD HAVE GONE UNNOTICED. It arrives under a name nothing knows, so
// every other check passes and it becomes a SECOND identity — two certificates, two rows in every view, one
// machine counted twice for ever.
func TestARenamedMachineDoesNotBecomeASecondDevice(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	_, conflict, err := l.EnrollDeviceForTenantWithMachine("laptop-renamed", "tenant_a", "", "", "2026-08-25T01:00:00Z", machineA)
	if !errors.Is(err, ErrMachineEnrolledUnderAnotherName) {
		t.Fatalf("want the renamed machine refused, got %v", err)
	}
	if conflict.EnrolledAs != "laptop" {
		t.Fatalf("the refusal did not name where the machine is enrolled: %+v", conflict)
	}
	if len(l.List()) != 1 {
		t.Fatalf("one machine produced %d identities", len(l.List()))
	}
}

// ★ AND THE OPERATOR CAN ALWAYS GET A MACHINE BACK. A rebuilt machine reports a new reference and a renamed
// one holds its old name; both are released by the same explicit act that lifts a removal.
func TestPermittingReenrolmentReleasesTheMachineBinding(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	if _, _, err := l.AllowReenrolment("laptop", "tenant_a", "2026-08-25T02:00:00Z"); err != nil {
		t.Fatalf("allow re-enrolment: %v", err)
	}
	// The rebuilt machine, under the same name.
	if _, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T03:00:00Z", machineB); err != nil {
		t.Fatalf("a rebuilt machine could not come back: %v", err)
	}
	// And the name it used to hold is free for the machine that was renamed.
	l2 := NewLedger()
	enrolled(t, l2, "laptop", machineA)
	if _, _, err := l2.AllowReenrolment("laptop", "tenant_a", "2026-08-25T02:00:00Z"); err != nil {
		t.Fatalf("allow re-enrolment: %v", err)
	}
	if _, _, err := l2.EnrollDeviceForTenantWithMachine("laptop-renamed", "tenant_a", "", "", "2026-08-25T03:00:00Z", machineA); err != nil {
		t.Fatalf("a renamed machine could not enrol after its old name was released: %v", err)
	}
}

// ★★ SILENCE ON EITHER SIDE MEANS THE DEPLOYMENT STILL CANNOT TELL, AND MUST NOT PRETEND IT CAN. An agent too
// old to report anything, or an identity enrolled before this existed, is exactly the ambiguity the combined
// sentence was written for.
func TestWithoutAMachineReferenceTheOldAnswerIsGiven(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", "")
	_, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T01:00:00Z", machineA)
	if !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("want the ambiguous answer when the stored side is silent, got %v", err)
	}
	l2 := NewLedger()
	enrolled(t, l2, "laptop", machineA)
	_, _, err = l2.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T01:00:00Z", "")
	if !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("want the ambiguous answer when the incoming side is silent, got %v", err)
	}
}

// ★ AND AN OLD AGENT MUST NOT ERASE WHAT A NEW ONE ESTABLISHED. A silent report that cleared the stored
// reference would put the deployment back to not being able to tell, quietly, on the first old agent through.
func TestASilentAgentDoesNotEraseTheStoredReference(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	if _, _, err := l.AllowReenrolment("laptop", "tenant_a", "2026-08-25T02:00:00Z"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if _, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T03:00:00Z", ""); err != nil {
		t.Fatalf("silent re-enrolment: %v", err)
	}
	// Nothing was recorded, so the deployment says so rather than claiming a machine it was never told about.
	if got := l.List()[0].MachineRef; got != "" {
		t.Fatalf("a silent agent left a machine reference %q", got)
	}
	// Now a reporting agent re-establishes it, and the distinction is back.
	if _, _, err := l.AllowReenrolment("laptop", "tenant_a", "2026-08-25T04:00:00Z"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if _, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T05:00:00Z", machineA); err != nil {
		t.Fatalf("re-enrolment: %v", err)
	}
	_, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T06:00:00Z", machineB)
	if !errors.Is(err, ErrDifferentMachineSameName) {
		t.Fatalf("the distinction did not come back: %v", err)
	}
}

// ★★★ A FIELD THAT IS REPORTED AND NOT CARRIED IS A FIELD THAT VANISHES. Every Edge's ledger is REPLACED from
// the control plane's copy at the next config bundle. A bundle that says nothing about the machine — the poll
// after an enrolment, or a deployment upgraded mid-flight — would erase the one thing that tells a machine
// from its namesake, silently, and the deployment would go back to the ambiguous refusal with nothing anywhere
// saying it had.
func TestABundleThatSaysNothingDoesNotEraseTheMachineItWasToldAbout(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)

	// What a control plane that has not yet heard about this machine sends.
	l.MergeAuthoritative([]Entry{{Identity: "laptop", Enabled: true, TenantID: "tenant_a"}}, "2026-08-25T02:00:00Z")

	if got := l.List()[0].MachineRef; got != machineA {
		t.Fatalf("the bundle erased the machine reference (%q) — the deployment can no longer tell this "+
			"machine from another of the same name", got)
	}
	// And the distinction still works after the merge, which is the thing that actually matters.
	if _, _, err := l.EnrollDeviceForTenantWithMachine("laptop", "tenant_a", "", "", "2026-08-25T03:00:00Z", machineB); !errors.Is(err, ErrDifferentMachineSameName) {
		t.Fatalf("after the bundle the namesake was not recognised: %v", err)
	}
}

// The guard: once the AUTHORITY holds a value it is the authority's, exactly like every other field here — the
// preservation above must not become "an Edge's copy always wins".
func TestTheAuthoritysMachineReferenceWins(t *testing.T) {
	l := NewLedger()
	enrolled(t, l, "laptop", machineA)
	l.MergeAuthoritative([]Entry{{Identity: "laptop", Enabled: true, TenantID: "tenant_a", MachineRef: machineB}},
		"2026-08-25T02:00:00Z")
	if got := l.List()[0].MachineRef; got != machineB {
		t.Fatalf("the control plane said %q and this node kept %q", machineB, got)
	}
}

// The authority records what an issuing node reports — and only when it does not already know, so a later
// report cannot quietly move a name to a different machine.
func TestTheAuthorityRecordsAReportedMachineButDoesNotLetItMoveOne(t *testing.T) {
	l := NewLedger()
	// An identity an operator pre-added: no machine behind it yet.
	if _, err := l.EnrollGroupForTenant("laptop", "", "tenant_a", "", "", "2026-08-25T00:00:00Z", true); err != nil {
		t.Fatalf("pre-add: %v", err)
	}
	if err := l.RecordReportedMachine("laptop", machineA, "2026-08-25T01:00:00Z"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if got := l.List()[0].MachineRef; got != machineA {
		t.Fatalf("the reported machine was not recorded: %q", got)
	}
	// A second report naming a different machine must not move the name.
	if err := l.RecordReportedMachine("laptop", machineB, "2026-08-25T02:00:00Z"); err != nil {
		t.Fatalf("second report: %v", err)
	}
	if got := l.List()[0].MachineRef; got != machineA {
		t.Fatalf("a later report moved the name to %q", got)
	}
}

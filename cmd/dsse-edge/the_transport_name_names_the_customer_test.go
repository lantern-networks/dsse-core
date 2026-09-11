package main

import (
	"strings"
	"testing"
	"time"
)

// ★★★ AN ORGANIZATION'S TRANSPORT NAME IS ITS CUSTOMER'S NAME, IN PLAINTEXT (2026-08-22, measured).
//
// organizationTransportServerName derives the name from the id, and an organization created before ids were
// issued carries the customer's own word: tenant_northwind is served as "northwind.dsse.invalid". SNI is
// plaintext and this deployment strips ECH, so every observer between a device and the Edge is told which
// company that laptop belongs to. New organizations do not have this — their ids are unguessable, so the
// derived names are — which leaves exactly the ones that predate it, and they had no way to change.
func TestAnOrganizationCanBeRenamedWithoutLockingOutADevice(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	a := newTenantTransportAuthority(nil, nil, func() time.Time { return now })
	if _, err := a.EnsureCA("tenant_northwind", "northwind.dsse.invalid"); err != nil {
		t.Fatalf("create: %v", err)
	}

	before, err := a.IssueFor("tenant_northwind", "edge-1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(before.CertPEM, "") || before.ServerName != "northwind.dsse.invalid" {
		t.Fatalf("the organization is not served under its own name: %q", before.ServerName)
	}

	row, err := a.RenameServerName("tenant_northwind", "k7q2x9.dsse.invalid")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if row.ServerName != "k7q2x9.dsse.invalid" || row.PreviousServerName != "northwind.dsse.invalid" {
		t.Fatalf("the rename did not keep the previous name: %+v", row)
	}

	// ★ THE CERTIFICATE MUST CARRY BOTH, or every device still sending the old name fails the handshake the
	// moment the fleet picks this up — including the one switched off during the rename.
	names := transportLeafNames(row)
	for _, want := range []string{
		"k7q2x9.dsse.invalid", "recovery.k7q2x9.dsse.invalid", "enrol.k7q2x9.dsse.invalid",
		"northwind.dsse.invalid", "recovery.northwind.dsse.invalid", "enrol.northwind.dsse.invalid",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the certificate does not carry %q during the rename: %v", want, names)
		}
	}
	// The folded paths follow the name, both of them — the enrolment fold has paid twice for a name nothing answers to.
	if len(names) != 6 {
		t.Fatalf("expected both name families and nothing else, got %v", names)
	}

	// One at a time.
	if _, err := a.RenameServerName("tenant_northwind", "other.dsse.invalid"); err == nil {
		t.Fatal("a second rename was allowed while one was in flight")
	}
	// Renaming to the name already in force is refused rather than silently starting an empty overlap.
	if _, err := a.RenameServerName("tenant_northwind", "k7q2x9.dsse.invalid"); err == nil {
		t.Fatal("renaming to the current name was accepted")
	}

	retired, err := a.RetirePreviousServerName("tenant_northwind")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	after := transportLeafNames(retired)
	if len(after) != 3 {
		t.Fatalf("after the retirement the old names are still carried: %v", after)
	}
	for _, n := range after {
		if strings.Contains(n, "northwind") {
			t.Fatalf("the customer's name survives in %q — which is the whole thing this removes", n)
		}
	}
	// ★ THE CONTROL: the organization is still served, under its new name. A rename that ends in no names at
	// all would pass every check above.
	issued, err := a.IssueFor("tenant_northwind", "edge-1", time.Hour)
	if err != nil || issued.ServerName != "k7q2x9.dsse.invalid" {
		t.Fatalf("the organization is not served after the rename: %q %v", issued.ServerName, err)
	}
	if _, err := a.RetirePreviousServerName("tenant_northwind"); err == nil {
		t.Fatal("retiring with no rename in flight was accepted")
	}
}

package main

import (
	"encoding/json"
	"testing"
	"time"
)

// ★ A RENAME THAT CANNOT BE ABANDONED HAS ONLY ONE EXIT, AND IT IS THE DESTRUCTIVE ONE (2026-08-22).
// Retiring the previous name fails the handshake for every device that has not adopted the new one, so
// without a way back an operator who started a rename in error had to either leave it in flight for ever or
// break their fleet. This is the transport tier's WithdrawIncoming.
func TestAbandonRenamePutsTheOrganizationBackOnTheNameDevicesKnow(t *testing.T) {
	var written []byte
	a := newTenantTransportAuthority(nil, func(b []byte) error { written = b; return nil }, nil)
	if _, err := a.EnsureCA("tenant_x", "x.dsse.invalid"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if _, err := a.AbandonRename("tenant_x"); err == nil {
		t.Fatal("abandoning when no rename is in flight must be refused, not silently succeed")
	}
	if _, err := a.RenameServerName("tenant_x", "y.dsse.invalid"); err != nil {
		t.Fatalf("RenameServerName: %v", err)
	}
	row, err := a.AbandonRename("tenant_x")
	if err != nil {
		t.Fatalf("AbandonRename: %v", err)
	}
	if row.ServerName != "x.dsse.invalid" {
		t.Fatalf("abandoning must land on the name the organization was moved off, got %q", row.ServerName)
	}
	// ★★★ AND IT MUST STILL CARRY THE ABANDONED NAME. A device that already adopted it fetches its next trust
	// bundle OVER THE TUNNEL — so dropping the name here strands exactly the devices that did what they were
	// told. Measured: it took this repository's own Mac off the network, recoverable only from the control
	// plane. Abandoning is a rename in the other direction, and RetirePreviousServerName is still the only act
	// that drops a name.
	if row.PreviousServerName != "y.dsse.invalid" {
		t.Fatalf("the abandoned name must become the PREVIOUS name and keep being served, got previous=%q",
			row.PreviousServerName)
	}
	names := transportLeafNames(row)
	for _, want := range []string{"x.dsse.invalid", "y.dsse.invalid", "enrol.x.dsse.invalid", "enrol.y.dsse.invalid"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the certificate must still name %q while devices move back; it names %v", want, names)
		}
	}
	// ★ It must survive a restart, or the rename resumes in the direction it was abandoned from.
	if len(written) == 0 {
		t.Fatal("nothing was persisted — a restart would not see the abandonment at all")
	}
	var rows []storedTenantTransportCA
	if err := json.Unmarshal(written, &rows); err != nil {
		t.Fatalf("persisted store is not readable: %v", err)
	}
	if len(rows) != 1 || rows[0].ServerName != "x.dsse.invalid" || rows[0].PreviousServerName != "y.dsse.invalid" {
		t.Fatalf("the persisted row does not describe the turned-around rename: %+v", rows)
	}
}

// ★★★ A RENAME DURING A ROTATION REACHED ONLY ONE OF THE TWO AUTHORITIES (2026-08-22, measured on
// tenant_northwind: the control plane read server_name=st3zohor…/renaming=false while the certificate on the
// wire named northwind.dsse.invalid and nothing else).
//
// RotateCA copies the name into the incoming authority when it stages it, so a rename afterwards changed only
// the outer row. Which name a device meets then depends on which authority the node happens to be serving —
// internal state no operator can see. A rename and a rotation are two independent movements; that is why
// they are two acts.
func TestARenameReachesBothAuthoritiesDuringARotation(t *testing.T) {
	a := newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := a.EnsureCA("tenant_x", "old.dsse.invalid"); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if _, err := a.RotateCA("tenant_x"); err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if _, err := a.RenameServerName("tenant_x", "new.dsse.invalid"); err != nil {
		t.Fatalf("RenameServerName: %v", err)
	}
	mats, err := a.IssueAllFor("tenant_x", "edge-a", time.Hour)
	if err != nil {
		t.Fatalf("IssueAllFor: %v", err)
	}
	if len(mats) != 2 {
		t.Fatalf("a rotation in flight must yield BOTH authorities' material, got %d", len(mats))
	}
	for i, m := range mats {
		if m.ServerName != "new.dsse.invalid" {
			t.Errorf("authority %d carries %q; a device meeting it would be served a name the organization "+
				"has been renamed away from", i, m.ServerName)
		}
		if m.PreviousServerName != "old.dsse.invalid" {
			t.Errorf("authority %d does not carry the previous name %q, so devices that have not adopted "+
				"cannot reach it", i, m.PreviousServerName)
		}
	}
}

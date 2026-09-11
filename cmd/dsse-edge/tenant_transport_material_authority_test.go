package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// ★★★ AN EDGE THAT APPEARS UNDER LOAD MUST BE ABLE TO SERVE AN ORGANIZATION IT WAS NEVER PREPARED FOR, AND IT
// MUST NOT BE HANDED ANYTHING THAT OUTLIVES IT (decided 2026-08-20, after measuring the scale-out path).
//
// The properties asserted here are the ones that make handing key material to a disposable machine acceptable
// at all: the material expires, the authority does not, the name travels with the certificate, and an
// organization the control plane holds no authority for gets nothing rather than something generic.
func TestTheControlPlaneIssuesShortLivedTransportMaterial(t *testing.T) {
	now := time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)
	saved := [][]byte{}
	a := newTenantTransportAuthority(nil, func(b []byte) error { saved = append(saved, b); return nil },
		func() time.Time { return now })

	if _, err := a.EnsureCA("tenant_reference_lab", ""); err == nil {
		t.Fatal("an authority was created without the name its agents will send — the certificate and the name " +
			"devices are told would then be free to drift apart, which is the defect that started this")
	}
	ca, err := a.EnsureCA("tenant_reference_lab", "Lab.DSSE.Invalid")
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	if ca.ServerName != "lab.dsse.invalid" {
		t.Fatalf("the name was not normalised the way a ClientHello arrives: %q", ca.ServerName)
	}
	if len(saved) != 1 {
		t.Fatal("the authority was not persisted — it would be regenerated on the next restart and every " +
			"device would be asked to adopt a new anchor")
	}

	// ★ THE SAME AUTHORITY ON EVERY CALL. A fresh CA per request is a fresh anchor per request.
	again, err := a.EnsureCA("tenant_reference_lab", "lab.dsse.invalid")
	if err != nil || again.CACertPEM != ca.CACertPEM {
		t.Fatalf("the authority was regenerated: %v", err)
	}

	mat, err := a.IssueFor("tenant_reference_lab", "edge-a2", 12*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	block, _ := pem.Decode([]byte(mat.CertPEM))
	if block == nil {
		t.Fatal("no certificate was returned")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	// ★ THREE NAMES, ONE PER PATH A DEVICE REACHES BY NAME (2026-08-21). Its own, the one it recovers through
	// when its certificate has expired, and the one it ENROLS through when it holds nothing at all — the enrolment fold's
	// fold to a single port. A fold that offers a name the certificate does not carry is the defect this
	// deployment has already paid for once, so the count is asserted rather than the first entry alone.
	if len(leaf.DNSNames) != 3 || leaf.DNSNames[0] != "lab.dsse.invalid" {
		t.Fatalf("the certificate does not carry the name devices are told to send: %v", leaf.DNSNames)
	}
	if leaf.DNSNames[2] != "enrol.lab.dsse.invalid" {
		t.Fatalf("the certificate does not carry the enrolment name, so a device holding nothing cannot reach "+
			"this Edge on the transport port: %v", leaf.DNSNames)
	}
	// ★ AND THE NAME ITS DEVICES RECOVER THROUGH (2026-08-20). The deployment-wide recovery name is answered by
	// the deployment-wide certificate, which an organization on its own authority no longer trusts — measured on
	// the lab the night roadmap D first completed: a device holding one anchor verified its transport name and
	// REFUSED recovery.dsse.invalid, with the dedicated recovery port already retired. Carrying the recovery
	// name on the same certificate its transport already uses is what makes the last resort reachable without
	// trusting anything new.
	if leaf.DNSNames[1] != "recovery.lab.dsse.invalid" {
		t.Fatalf("the certificate does not carry this organization's recovery name: %v", leaf.DNSNames)
	}
	if !leaf.NotAfter.After(now) || leaf.NotAfter.After(now.Add(13*time.Hour)) {
		t.Fatalf("material handed to a disposable node does not expire soon enough: %s", leaf.NotAfter)
	}
	// It must verify against the anchor devices are given, or the device refuses this Edge.
	anchors := x509.NewCertPool()
	if !anchors.AppendCertsFromPEM([]byte(mat.AnchorPEM)) {
		t.Fatal("the anchor handed alongside is not a certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: anchors, DNSName: "lab.dsse.invalid",
		CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("a device holding the anchor could not verify the certificate this Edge would present: %v", err)
	}

	// ★ ZERO LIFETIME IS NOT "FOREVER", IT IS A REFUSAL.
	if _, err := a.IssueFor("tenant_reference_lab", "edge-a2", 0); err == nil {
		t.Fatal("material with no expiry was issued to a node that may vanish")
	}

	// An organization with no authority here gets nothing — never the shared certificate by default.
	if _, err := a.IssueFor("tenant_unknown", "edge-a2", time.Hour); err == nil {
		t.Fatal("an Edge was handed material for an organization this control plane holds no authority for")
	} else if !strings.Contains(err.Error(), "tenant_unknown") {
		t.Fatalf("the refusal does not name the organization: %v", err)
	}

	// Restart: the authority survives, and the same anchor comes back.
	restarted := newTenantTransportAuthority(saved[len(saved)-1], func([]byte) error { return nil },
		func() time.Time { return now.Add(48 * time.Hour) })
	back, err := restarted.EnsureCA("tenant_reference_lab", "lab.dsse.invalid")
	if err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if back.CACertPEM != ca.CACertPEM {
		t.Fatal("a restart produced a different anchor — every device would have to adopt again, and the old " +
			"one would be un-issuable, which this lab has already done once by hand")
	}
	if orgs := restarted.Organizations(); len(orgs) != 1 || orgs[0] != "tenant_reference_lab" {
		t.Fatalf("the restored authority does not name its organizations: %v", orgs)
	}
}

// ★★★ A PER-PROCESS COPY OF SHARED STATE TESTIFIED TO AN ABSENCE, AND TWO EDGES EXITED (2026-08-28, measured
// on the two-region lab).
//
// An organization was given its own transport authority through the Console. The write went to the control
// plane that leads. Every OTHER control plane had loaded this map once, at start-up, and was never told — so
// when an Edge asked one of them for material it was answered, as a fact, that the organization has no
// authority. The fleet had already announced that organization's name, the Edge's own guard did the right
// thing with the wrong input, and two nodes refused to join and stayed down.
//
// So an absence is now read from the shared store, and a store that cannot be read is a different answer from
// a store that says no.
func TestAnAbsenceIsReadFromTheSharedStoreAndNotFromThisProcess(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC) }

	// The node that leads: it creates the authority and its own map has it.
	shared := []byte(nil)
	leader := newTenantTransportAuthorityWithReload(nil, func(b []byte) error { shared = b; return nil }, nil, now)
	if _, err := leader.EnsureCA("tenant_kaede", "kaede.dsse.lab"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(shared) == 0 {
		t.Fatal("the authority was not written to the shared store, so nothing below is measuring anything")
	}

	// Another control plane, started BEFORE that write. This is the one an Edge reached.
	reloads := 0
	other := newTenantTransportAuthorityWithReload(nil, func([]byte) error { return nil },
		func() ([]byte, error) { reloads++; return shared, nil }, now)
	mat, err := other.IssueFor("tenant_kaede", "edge-a", time.Hour)
	if err != nil {
		t.Fatalf("a control plane that did not receive the write answered that the organization has none, "+
			"which is what took two Edges down: %v", err)
	}
	if strings.TrimSpace(mat.ServerName) != "kaede.dsse.lab" {
		t.Fatalf("material was issued under %q", mat.ServerName)
	}
	if reloads != 1 {
		t.Fatalf("the shared store was read %d time(s); an absence must go through it exactly once", reloads)
	}

	// Existing rows also refresh: a different CP may have rotated or retired this authority.
	if _, err := other.IssueFor("tenant_kaede", "edge-a", time.Hour); err != nil {
		t.Fatal(err)
	}
	if reloads != 2 {
		t.Fatalf("the existing authority did not refresh from the shared store (%d reads)", reloads)
	}

	// ★★ A STORE THAT CANNOT BE READ IS NOT AN ABSENCE. This is the answer an Edge is allowed to wait on.
	deaf := newTenantTransportAuthorityWithReload(nil, func([]byte) error { return nil },
		func() ([]byte, error) { return nil, errString("connection refused") }, now)
	_, err = deaf.IssueFor("tenant_kaede", "edge-a", time.Hour)
	if err == nil {
		t.Fatal("a node that could not read the store answered as if it had")
	}
	if !authorityCouldNotBeAsked(err) {
		t.Fatalf("the refusal cannot be told apart from a real absence: %v", err)
	}
	if !transportAuthorityRefusalIsNotEvidence(err.Error()) {
		t.Fatalf("an Edge reading this over the wire could not tell it apart: %v", err)
	}

	// And a real absence stays a real absence — it must never be retried into a different answer.
	_, err = other.IssueFor("tenant_nobody", "edge-a", time.Hour)
	if err == nil || authorityCouldNotBeAsked(err) {
		t.Fatalf("an organization that genuinely has no authority was not refused as a fact: %v", err)
	}
}

// ★ THE SAME SHAPE IN THE OTHER TWO AUTHORITIES, so the family is closed rather than one instance of it.
//
// A control plane that did not receive the write refuses, as a fact:
//
//	device-identity   every enrolment its customer's administrator approved is answered "invalid or missing
//	                  eligibility token" on the device
//	interception      that organization's traffic is not inspected on the Edges this node serves
//
// Neither exits a process, which is exactly why they would have gone on being paid for quietly.
func TestTheOtherTwoAuthoritiesReadAnAbsenceFromTheSharedStoreToo(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC) }

	deviceShared := []byte(nil)
	deviceLeader := newTenantDeviceAuthorityWithReload(nil, func(b []byte) error { deviceShared = b; return nil }, nil, now)
	if _, err := deviceLeader.EnsureCA("tenant_kaede", "Kaede Logistics"); err != nil {
		t.Fatalf("device ensure: %v", err)
	}
	deviceOther := newTenantDeviceAuthorityWithReload(nil, func([]byte) error { return nil },
		func() ([]byte, error) { return deviceShared, nil }, now)
	if _, err := deviceOther.IssueFor("tenant_kaede", time.Hour); err != nil {
		t.Errorf("a control plane that did not receive the write refused this organization's device-identity "+
			"authority, so every enrolment it approves is refused on the device: %v", err)
	}
	deaf := newTenantDeviceAuthorityWithReload(nil, func([]byte) error { return nil },
		func() ([]byte, error) { return nil, errString("connection refused") }, now)
	if _, err := deaf.IssueFor("tenant_kaede", time.Hour); err == nil || !authorityCouldNotBeAsked(err) {
		t.Errorf("a node that could not read the store answered as if it had: %v", err)
	}
	if _, err := deviceOther.IssueFor("tenant_nobody", time.Hour); err == nil || authorityCouldNotBeAsked(err) {
		t.Errorf("a real absence stopped being a fact: %v", err)
	}
}

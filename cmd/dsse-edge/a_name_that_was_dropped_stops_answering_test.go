package main

import (
	"crypto/tls"
	"testing"
)

// ★★★ A NAME THIS ORGANIZATION NO LONGER HAS MUST STOP ANSWERING (2026-08-22, measured on the lab).
//
// put() only ever ADDED SNI keys. A name once served was served until the process restarted, so BOTH ends of a
// transport rename were silently ineffective on a running Edge:
//
//	abandon-rename        the abandoned name kept answering, so a device that had adopted it was never
//	                      pushed back onto the one the fleet is actually on
//	retire-previous-name  THE DESTRUCTIVE ACT DID NOTHING. The operator read a 200, the readiness screen
//	                      showed the rename finished, and every device still on the old name kept connecting
//	                      — until the next Edge restart dropped all of them at once, hours or days later,
//	                      with nothing linking the outage to the act that caused it.
//
// Measured: after abandoning the lab's rename, both Edges re-minted the three-name certificate AND still
// completed a handshake for SNI q7m2xk4n.dsse.invalid from the six-name leaf left in the map.
//
// The rule: put() is AUTHORITATIVE for one organization's names. Names it does not list, and that belong to
// this organization, are dropped in the same step.
func TestANameThisOrganizationNoLongerHasStopsAnswering(t *testing.T) {
	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })

	during := &tls.Certificate{}
	transportTenantCertificates.put("tenant_lab",
		[]string{"new.invalid", "enrol.new.invalid", "old.invalid", "enrol.old.invalid"}, during, "anchor")
	// Another organization's name, to prove the pruning is scoped and does not sweep the fleet.
	transportTenantCertificates.put("tenant_other", []string{"other.invalid"}, &tls.Certificate{}, "anchor-b")

	if _, _, ok := transportTenantCertificates.For("old.invalid"); !ok {
		t.Fatal("the old name must answer DURING the rename — otherwise this test proves nothing about after")
	}

	// The rename ends: this organization now has only the new family.
	transportTenantCertificates.put("tenant_lab", []string{"new.invalid", "enrol.new.invalid"}, &tls.Certificate{}, "anchor")

	for _, gone := range []string{"old.invalid", "enrol.old.invalid"} {
		if _, _, ok := transportTenantCertificates.For(gone); ok {
			t.Errorf("%q still answers after the organization stopped having it — a retirement that takes "+
				"effect only at the next restart is worse than one that fails loudly", gone)
		}
	}
	for _, kept := range []string{"new.invalid", "enrol.new.invalid"} {
		if _, _, ok := transportTenantCertificates.For(kept); !ok {
			t.Errorf("%q stopped answering, and it is the name the organization is on", kept)
		}
	}
	if _, _, ok := transportTenantCertificates.For("other.invalid"); !ok {
		t.Error("another organization's name was swept away — pruning is scoped to the organization named")
	}
}

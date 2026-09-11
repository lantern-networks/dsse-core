package main

import (
	"strings"
	"testing"
)

// ★★★ THE ANNOUNCEMENT MUST NOT DEPEND ON GO'S MAP ORDER (2026-08-20, measured on a four-Edge lab).
//
// An organization answers to its own name and to its recovery alias, and both are in this index because both
// are in its certificate. The builder kept whichever name the range handed it first, so each recompute
// announced a different one, every node read its peer's write as a change, and the serial climbed once a
// minute forever.
//
// Devices adopt by serial and the withdrawal gate asks whether every device has confirmed the CURRENT
// distribution, so a serial that never stops moving means no device is ever current and NO TRUST ANCHOR CAN
// BE WITHDRAWN. Fourteen attempts over ten minutes were refused "unconfirmed: mac-dev-1, win-dev-1" with both
// devices healthy.
//
// Repeated because one pass of a two-entry map agrees with itself half the time; this is the shape that has
// to fail loudly when the determinism goes away.
func TestTheAnnouncedServerNameDoesNotDependOnMapOrder(t *testing.T) {
	certs := &transportTenantCerts{tenantOf: map[string]string{
		"lab.dsse.invalid":                "tenant_reference_lab",
		"recovery.lab.dsse.invalid":       "tenant_reference_lab",
		"northwind.dsse.invalid":          "tenant_northwind",
		"recovery.northwind.dsse.invalid": "tenant_northwind",
		// ★ The second folded name, added 2026-08-21. Same reason as the first: it is in the certificate, so
		// it is in this index, and an announcement that picks one out of the map flaps forever.
		"enrol.lab.dsse.invalid":       "tenant_reference_lab",
		"enrol.northwind.dsse.invalid": "tenant_northwind",
	}}
	first := strings.Join(certs.ServerNameAnnouncements(), ",")
	for i := 0; i < 200; i++ {
		if got := strings.Join(certs.ServerNameAnnouncements(), ","); got != first {
			t.Fatalf("pass %d announced %q, the first pass announced %q — the fleet would read this as a change "+
				"and advance the serial with nothing having changed", i, got, first)
		}
	}
	if first != "tenant_northwind@northwind.dsse.invalid,tenant_reference_lab@lab.dsse.invalid" {
		t.Fatalf("the announcement names the recovery alias instead of the organization's own name: %q", first)
	}
}

// An organization that only has a recovery name keeps its promise rather than vanishing from the
// announcement: a node that stops naming an organization is a shrink, which is what the fleet guard exists
// to catch, and it must not be caused by the filter above.
func TestAnOrganizationWithOnlyARecoveryNameIsStillAnnounced(t *testing.T) {
	certs := &transportTenantCerts{tenantOf: map[string]string{
		"recovery.only.dsse.invalid": "tenant_only_recovery",
	}}
	if got := strings.Join(certs.ServerNameAnnouncements(), ","); got != "tenant_only_recovery@recovery.only.dsse.invalid" {
		t.Fatalf("an organization was dropped from the announcement entirely: %q", got)
	}
}

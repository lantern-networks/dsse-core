package main

import (
	"crypto/tls"
	"strings"
	"testing"
)

// ★★★ RETRACT, LET THE SERIAL CARRY IT, THEN STOP (2026-08-21, written after doing it in one step took the
// reference deployment down).
//
// An organization was deleted and purged. Dropping its certificate on every Edge — while the fleet's shared
// announcement went on promising its name — made every node fail the fleet-promise guard on start-up:
//
//	REFUSING TO JOIN THIS FLEET: … was promised the name … and this node has no certificate for it
//
// region-b exited, region-a crash-looped, and nothing recovered until the announcement was retracted by hand.
// The node killed itself for failing a promise it was one line away from withdrawing.
func TestARetirementLeavesTheAnnouncementBeforeItStopsServing(t *testing.T) {
	const tenant = "tenant_going_away"
	const name = "goingaway.dsse.invalid"

	restore := transportTenantCertificates
	transportTenantCertificates = newTransportTenantCerts()
	t.Cleanup(func() { transportTenantCertificates = restore })
	transportTenantCertificates.put(tenant, []string{name}, &tls.Certificate{}, "anchor")

	if _, _, ok := transportTenantCertificates.For(name); !ok {
		t.Fatal("the control failed: the name is not served to begin with")
	}

	// Phase one. The organization leaves the announcement and IS STILL SERVED.
	if !transportTenantCertificates.BeginRetiring(tenant) {
		t.Fatal("a served organization could not be marked for retirement")
	}
	if !transportTenantCertificates.IsRetiring(tenant) {
		t.Fatal("the retirement was not recorded")
	}
	if _, _, ok := transportTenantCertificates.For(name); !ok {
		t.Fatal("★ the name stopped being served the moment it was marked. A promise is kept until it has " +
			"been withdrawn — dropping first is what made every Edge fail the fleet-promise guard.")
	}

	// ★ AND IT IS OUT OF WHAT THIS NODE WOULD ANNOUNCE. That is the retraction; the serial carries it.
	for tenantInAnnouncement := range transportTenantCertificates.anchorsByTenant() {
		if tenantInAnnouncement == tenant && !transportTenantCertificates.IsRetiring(tenantInAnnouncement) {
			t.Fatal("a retiring organization is still announced")
		}
	}

	// Phase two, only once the promise is gone.
	if dropped := transportTenantCertificates.StopServing(tenant); dropped != 1 {
		t.Fatalf("stopping served %d name(s), want 1", dropped)
	}
	if _, _, ok := transportTenantCertificates.For(name); ok {
		t.Fatal("the name is still served after the retirement finished")
	}
	if transportTenantCertificates.IsRetiring(tenant) {
		t.Fatal("the retirement flag outlived the certificate — a later organization reusing the id would " +
			"start out already retiring")
	}

	// ★ AND AN ORGANIZATION THIS NODE DOES NOT SERVE CANNOT BE PUT INTO RETIREMENT, or a fetch that came back
	// empty would mark the whole fleet.
	if transportTenantCertificates.BeginRetiring("tenant_never_here") {
		t.Fatal("an organization this node does not serve was marked for retirement")
	}
	_ = strings.TrimSpace("")
}

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
)

func licenceNow() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

func testLicence(seats int) vendorlicense.Payload {
	n := licenceNow()
	return vendorlicense.Payload{
		SchemaVersion:    vendorlicense.Schema,
		MSSPID:           "mssp_partner_a",
		Serial:           1,
		Grants:           []vendorlicense.Grant{{Seats: seats, EndsAt: n.AddDate(0, 13, 0).Format(time.RFC3339)}},
		IssuedAt:         n.Format(time.RFC3339),
		ExpiresAt:        n.AddDate(0, 12, 0).Format(time.RFC3339),
		EnrolmentStopsAt: n.AddDate(0, 13, 0).Format(time.RFC3339),
		ServiceEndsAt:    n.AddDate(0, 16, 0).Format(time.RFC3339),
	}
}

// ★ THESE TESTS ARE ABOUT THE ENFORCING MODE, and they say so rather than inheriting it (2026-08-14). The
// quota stopped being a gate by default that day; a suite that kept passing without naming the mode would be
// asserting behaviour the shipped default no longer has. See TestAQuotaIsAnAlertByDefault for the other side.
const (
	quotaEnforcing = true
	quotaAdvisory  = false
)

func licensingAt(t *testing.T, at time.Time, seats int, requireLicence bool) (*enrolmentLicensing, *enrolledinventory.Ledger, *seatallocation.Store) {
	t.Helper()
	ledger := enrolledinventory.NewLedger()
	allocs := seatallocation.NewStore()
	e := newEnrolmentLicensing(allocs, ledger, requireLicence, quotaEnforcing)
	e.now = func() time.Time { return at }
	if seats > 0 {
		e.Apply(testLicence(seats))
	}
	return e, ledger, allocs
}

func enrol(t *testing.T, l *enrolledinventory.Ledger, tenant string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.EnrollGroup("dev-"+tenant+"-"+string(rune('a'+i)), tenant, "", "", "t0"); err != nil {
			t.Fatalf("seed enrol: %v", err)
		}
	}
}

// A deployment with no licensing at all is left alone. The reference lab and any single-tenant install run this
// way, and defaulting them to zero seats would stop enrolment everywhere the moment this code shipped.
func TestAnUnlicensedDeploymentIsNotGated(t *testing.T) {
	e, ledger, _ := licensingAt(t, licenceNow(), 0, false)
	enrol(t, ledger, "tenant_a", 5)
	if why, refused := e.RefuseEnrolment("tenant_a"); refused {
		t.Fatalf("an unlicensed deployment must not be gated: %q", why)
	}
}

// But an Edge TOLD to enforce licensing and given nothing to enforce must not fall open — otherwise the whole
// mechanism is optional in practice, and a misconfiguration looks like a working install.
func TestLicensingRequiredButAbsentRefuses(t *testing.T) {
	e, _, _ := licensingAt(t, licenceNow(), 0, true)
	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("licensing required with no licence present must refuse")
	}
}

func TestSeatsAreCountedAgainstThePoolWhenThereAreNoAllocations(t *testing.T) {
	e, ledger, _ := licensingAt(t, licenceNow(), 3, true)
	enrol(t, ledger, "tenant_a", 2)
	if why, refused := e.RefuseEnrolment("tenant_a"); refused {
		t.Fatalf("room for one more: %q", why)
	}
	enrol(t, ledger, "tenant_a", 3) // now 3 in total (a..c overlap) — fill the pool
	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("a full pool must refuse")
	}
}

// Under an MSSP the pool is divided, and a tenant is measured against ITS OWN share — not against what is left
// in the pool, which is what lets one customer quietly consume another's.
func TestATenantIsMeasuredAgainstItsOwnAllocation(t *testing.T) {
	e, ledger, allocs := licensingAt(t, licenceNow(), 1000, true)
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 2, "adm_alice", "", "t0")
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_b", 500, "adm_alice", "", "t0")

	enrol(t, ledger, "tenant_a", 2)
	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("tenant_a is full at its own allocation even though the pool has 998 free")
	}
	if why, refused := e.RefuseEnrolment("tenant_b"); refused {
		t.Fatalf("tenant_b has room and must not be affected by tenant_a: %q", why)
	}
}

// ★ The invariant. Every licensing shortfall refuses GROWTH and touches nothing that already runs.
func TestNoLicensingShortfallEverStopsAWorkingDevice(t *testing.T) {
	n := licenceNow()
	// Past the enrolment stop, with the fleet over its allocation, and the pool exhausted — every shortfall at
	// once. Enrolment is refused; the licence still says traffic may flow.
	e, ledger, allocs := licensingAt(t, n.AddDate(0, 14, 0), 1, true)
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 1, "adm_alice", "", "t0")
	enrol(t, ledger, "tenant_a", 5)

	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("growth must be refused")
	}
	licence, _ := e.Current()
	if !licence.MaySteerTraffic(n.AddDate(0, 14, 0)) {
		t.Fatalf("no shortfall may stop traffic — only the licence's declared service end does that")
	}
	if !ledger.IsAdmitted("dev-tenant_a-a") {
		t.Fatalf("a device already enrolled must stay admitted whatever the licensing says")
	}
}

// Disabling a device returns its seat. An operator who retires machines expects to be able to enrol replacements.
func TestDisablingADeviceFreesItsSeat(t *testing.T) {
	e, ledger, allocs := licensingAt(t, licenceNow(), 1000, true)
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 2, "adm_alice", "", "t0")
	enrol(t, ledger, "tenant_a", 2)
	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("full at 2 of 2")
	}
	ledger.SetEnabled("dev-tenant_a-a", false, "t1")
	if why, refused := e.RefuseEnrolment("tenant_a"); refused {
		t.Fatalf("retiring a device must free its seat: %q", why)
	}
}

// A seat block lapsing shrinks the pool. That refuses growth like any other shortfall — it is not a service event.
func TestALapsedSeatBlockOnlyRefusesGrowth(t *testing.T) {
	n := licenceNow()
	ledger := enrolledinventory.NewLedger()
	e := newEnrolmentLicensing(seatallocation.NewStore(), ledger, true, quotaEnforcing)
	p := testLicence(0)
	p.Grants = []vendorlicense.Grant{
		{Seats: 10, EndsAt: n.AddDate(0, 12, 0).Format(time.RFC3339)},
		{Seats: 5, StartsAt: n.AddDate(0, 6, 0).Format(time.RFC3339), EndsAt: n.AddDate(0, 9, 0).Format(time.RFC3339)},
	}
	e.Apply(p)
	enrol(t, ledger, "tenant_a", 12)

	e.now = func() time.Time { return n.AddDate(0, 7, 0) } // 15 seats: the addition is live
	if why, refused := e.RefuseEnrolment("tenant_a"); refused {
		t.Fatalf("12 of 15 in use, must have room: %q", why)
	}
	e.now = func() time.Time { return n.AddDate(0, 10, 0) } // the addition lapsed: 10 seats, 12 in use
	if _, refused := e.RefuseEnrolment("tenant_a"); !refused {
		t.Fatalf("over the shrunken pool must refuse growth")
	}
	licence, _ := e.Current()
	if !licence.MaySteerTraffic(n.AddDate(0, 10, 0)) {
		t.Fatalf("a lapsed seat block is not a service event")
	}
}

// Optional capabilities are seat-scoped and separate from capacity.
func TestOptionalCapabilitiesAreReportedSeparately(t *testing.T) {
	n := licenceNow()
	e, _, _ := licensingAt(t, n, 0, true)
	p := testLicence(0)
	p.Grants = []vendorlicense.Grant{
		{Seats: 100, EndsAt: n.AddDate(0, 13, 0).Format(time.RFC3339)},
		{Seats: 20, Feature: "dspm", EndsAt: n.AddDate(0, 6, 0).Format(time.RFC3339)},
	}
	e.Apply(p)
	if seats, ok := e.LicensedFeature("dspm"); !ok || seats != 20 {
		t.Fatalf("dspm: %d seats, licensed=%v", seats, ok)
	}
	if _, ok := e.LicensedFeature("ai-quarantine"); ok {
		t.Fatalf("a capability nobody bought is not licensed")
	}
	e.now = func() time.Time { return n.AddDate(0, 7, 0) }
	if _, ok := e.LicensedFeature("dspm"); ok {
		t.Fatalf("a lapsed capability is not licensed")
	}
}

// End to end through the REAL endpoint: with no seat left, a valid token is refused and — the part worth
// checking — the token is NOT spent, so the admin is not left re-issuing for a device there was no room for.
func TestEnrolIsRefusedWhenNoSeatIsLeftAndTheTokenSurvives(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	allocs := seatallocation.NewStore()
	licensing := newEnrolmentLicensing(allocs, ledger, true, quotaEnforcing)
	licensing.now = licenceNow
	licensing.Apply(testLicence(1000))
	allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_test", 1, "adm_alice", "", "t0")

	mux, tokens, _ := newTokenEnrolTestMuxWith(t, ledger, licensing)
	now := time.Now().UTC()
	_, first, _ := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(time.Hour), now)
	if code, resp := enrolPost(t, mux, "laptop-01", first); code != http.StatusOK {
		t.Fatalf("the first device fits: code=%d err=%q", code, resp.Error)
	}

	tok, second, _ := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(time.Hour), now)
	code, resp := enrolPost(t, mux, "laptop-02", second)
	if code != http.StatusForbidden {
		t.Fatalf("with no seat left enrolment must be refused, got %d", code)
	}
	// The caller learns nothing about capacity: a public endpoint must not report how close a tenant is to its
	// limit.
	if strings.Contains(strings.ToLower(resp.Error), "seat") {
		t.Fatalf("the refusal leaks capacity to an unauthenticated caller: %q", resp.Error)
	}
	if _, err := tokens.Verify(second, "tenant_test", now); err != nil {
		t.Fatalf("a token must survive an enrolment it was not the cause of: %v", err)
	}
	_ = tok
	// And the device that got in is untouched.
	if !ledger.IsAdmitted("laptop-01") {
		t.Fatalf("the enrolled device must be unaffected")
	}
}

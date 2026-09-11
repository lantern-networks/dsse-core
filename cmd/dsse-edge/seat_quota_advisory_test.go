package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/seatallocation"
)

// seat_quota_advisory_test.go — the shipped default: a tenant quota is a number to watch, not a gate.
//
// ★ WHY THE DEFAULT NEEDS ITS OWN TESTS (2026-08-14, operator decision for the OSS release). Every existing
// licensing test names quotaEnforcing, because they were written when the quota refused. If nothing asserted
// the other mode, the suite would go on describing a behaviour the product no longer ships — and the way this
// codebase has repeatedly lost a safe-side default is by having tests only for the arm somebody was thinking
// about at the time.
//
// What is deliberately NOT tested here as a refusal: the licence's own enrolment-stop date. That arm is
// untouched and belongs to decision 4's B-3, which decides the vendor licence type's future separately.

func TestAQuotaIsAnAlertByDefaultAndTheDeviceStillEnrols(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	allocs := seatallocation.NewStore()
	e := newEnrolmentLicensing(allocs, ledger, true, quotaAdvisory)
	e.now = licenceNow
	e.Apply(testLicence(1000))
	if _, err := allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 2, "adm_alice", "", "t0"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	enrol(t, ledger, "tenant_a", 5) // five devices against a quota of two

	why, refused := e.RefuseEnrolment("tenant_a")
	if refused {
		t.Fatalf("the default must ADMIT past the quota and alert instead; it refused with %q", why)
	}

	// And the operator can read the alert back, with both numbers — a warning that lives only in a log is a
	// warning only for whoever was tailing it.
	over := e.OverQuotaTenants()
	if len(over) != 1 {
		t.Fatalf("the over-quota tenant must be readable from the summary, got %v", over)
	}
	if over[0]["tenant_id"] != "tenant_a" || over[0]["devices"].(int) != 5 || over[0]["quota"].(int) != 2 {
		t.Fatalf("the alert must name the tenant and both numbers, got %v", over[0])
	}
}

// ★ THE CASE THAT USED TO BREAK A FLEET SILENTLY. Allocating seats to ONE tenant flipped every other tenant
// from "shares the pool" to "no seats allocated; refused" — an unrelated administrative act stopping enrolment
// for customers nobody had touched, with nothing said. A tenant nobody has spoken about is not over a quota.
func TestATenantWithNoQuotaIsNotRefusedBecauseAnotherTenantGotOne(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	allocs := seatallocation.NewStore()
	e := newEnrolmentLicensing(allocs, ledger, true, quotaEnforcing) // even ENFORCING
	e.now = licenceNow
	e.Apply(testLicence(1000))
	if _, err := allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_a", 2, "adm_alice", "", "t0"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	enrol(t, ledger, "tenant_b", 3)

	if why, refused := e.RefuseEnrolment("tenant_b"); refused {
		t.Fatalf("tenant_b was never given a quota and must not be refused because tenant_a was: %q", why)
	}
}

// An operator who means zero says zero, and that IS a quota — it alerts by default and refuses when enforcing.
// This is what the previous behaviour could not express: silence and zero were the same value.
func TestAnExplicitZeroIsAQuotaLikeAnyOther(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enforce bool
		want    bool
	}{
		{"advisory", quotaAdvisory, false}, {"enforcing", quotaEnforcing, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := enrolledinventory.NewLedger()
			allocs := seatallocation.NewStore()
			e := newEnrolmentLicensing(allocs, ledger, true, tc.enforce)
			e.now = licenceNow
			e.Apply(testLicence(1000))
			if _, err := allocs.Allocate(seatallocation.Policy{PoolSeats: 1000}, "tenant_z", 0, "adm_alice", "", "t0"); err != nil {
				t.Fatalf("allocate zero: %v", err)
			}
			enrol(t, ledger, "tenant_z", 1)
			_, refused := e.RefuseEnrolment("tenant_z")
			if refused != tc.want {
				t.Fatalf("explicit zero, %s: refused=%v want %v", tc.name, refused, tc.want)
			}
		})
	}
}

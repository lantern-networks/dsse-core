package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
)

// EnrolmentLicensing answers the one licensing question the enrolment endpoint asks. An interface so the
// endpoint does not have to know whether a deployment is licensed at all — an unlicensed Edge passes nil and the
// gate never runs.
type EnrolmentLicensing interface {
	// RefuseEnrolment reports whether a tenant may NOT enrol another device, and why — written for an operator's
	// log. The endpoint gives the caller a generic message instead, so a public endpoint cannot be used to probe
	// how close a tenant is to its limit.
	RefuseEnrolment(tenantID string) (string, bool)
}

// enrolmentLicensing joins the three things that decide whether one more device fits: what the vendor licensed,
// how the MSSP divided it, and how many seats are actually occupied.
//
// It answers only about GROWTH. Nothing it reports can stop a device that already works — a licence running past
// its enrolment-stop, an allocation trimmed below current use, a pool that shrank when a seat block lapsed, all
// refuse new enrolments and leave the running fleet alone. The only thing in this product that stops traffic is
// the licence's own declared service end, which is not this gate's business.
type enrolmentLicensing struct {
	mu sync.RWMutex
	// licence is the verified payload currently in force. nil means no licence has been accepted, which for a
	// deployment that HAS licensing configured is a refusal — an Edge told to enforce licensing and given
	// nothing to enforce must not fall open.
	licence *vendorlicense.Payload
	// requireLicence separates "no licensing in this deployment" from "licensing configured but no valid licence
	// present". The first is a single-tenant install and is left alone; the second is a misconfiguration or an
	// expired install, and defaulting it to unlimited would make the whole mechanism optional in practice.
	requireLicence bool

	// enforceSeatQuota turns the tenant quota back into an admission gate. FALSE by default and set only by an
	// operator: the OSS release ships quotas as a number to watch, not a number that refuses.
	//
	// ★ IT IS THE SEAM, AND IT IS DELIBERATELY THE ONLY ONE. A future vendor-imposed cap has somewhere to live —
	// this switch, and the refusal it re-enables — instead of the enforcement being scattered back through the
	// enrolment path. Anything that sets it without an operator saying so is the "safe-side default silently
	// flipped" accident this product keeps having, so ops/checks/no_licence_traffic_gate.sh asserts it stays
	// operator-driven.
	enforceSeatQuota bool

	// overQuotaSeen remembers which tenants have already raised the alert, so a crossing is announced once
	// rather than on every enrolment past it. A line printed per attempt is a line nobody reads.
	overQuotaSeen sync.Map

	allocations *seatallocation.Store
	ledger      *enrolledinventory.Ledger
	now         func() time.Time
}

func newEnrolmentLicensing(allocations *seatallocation.Store, ledger *enrolledinventory.Ledger, requireLicence, enforceSeatQuota bool) *enrolmentLicensing {
	return &enrolmentLicensing{
		allocations:      allocations,
		ledger:           ledger,
		requireLicence:   requireLicence,
		enforceSeatQuota: enforceSeatQuota,
		now:              time.Now,
	}
}

// Apply records a verified licence as the one in force. Verification — signature, serial, addressee — happens
// before this; nothing unverified reaches here.
func (e *enrolmentLicensing) Apply(p vendorlicense.Payload) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.licence = &p
}

// Enforced reports whether this deployment gates enrolment on a licence at all. A single-tenant install or the
// reference lab has no vendor keys configured and is not gated — and a console that says "no devices can enrol
// until you apply a licence" to one of those is simply wrong, which is worse than saying nothing.
func (e *enrolmentLicensing) Enforced() bool { return e != nil && e.requireLicence }

// Current returns the licence in force, if any.
func (e *enrolmentLicensing) Current() (vendorlicense.Payload, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.licence == nil {
		return vendorlicense.Payload{}, false
	}
	return *e.licence, true
}

func (e *enrolmentLicensing) RefuseEnrolment(tenantID string) (string, bool) {
	if e == nil {
		return "", false
	}
	now := e.now().UTC()
	licence, have := e.Current()

	if !have {
		if !e.requireLicence {
			return "", false // unlicensed deployment: not this gate's concern
		}
		return "no valid licence is installed; enrolment is held until one is applied", true
	}
	if !licence.MayEnrolNewDevices(now) {
		// Past the licence's enrolment stop. Devices already enrolled are untouched, and traffic keeps flowing
		// until the separately declared service end.
		return fmt.Sprintf("the licence stopped admitting new devices on %s; existing devices are unaffected",
			licence.EnrolmentStopsAt), true
	}

	// ★★ SEATS ARE AN ALERT, NOT A REFUSAL, UNLESS AN OPERATOR SAYS OTHERWISE (2026-08-14, operator decision
	// for the OSS release). The quota a tenant is given is now a number the operator manages and watches; going
	// past it raises an over-quota alert and lets the device enrol. Only enforceSeatQuota turns it back into a
	// gate, and nothing sets that on its own — it is the seam a future vendor-imposed cap plugs into, kept
	// reachable rather than kept armed.
	//
	// ★ WHAT THIS REPLACED WAS NOT A WORKING CEILING. Measured the same day: with NO allocations at all, `used`
	// counts one TENANT's devices and `pool` is the whole licence, so every tenant could independently reach the
	// pool and nothing refused — the comment here said "a single-tenant deployment ... measures the whole fleet
	// against the whole pool", and that premise was doing all the work with nothing enforcing it. Then the
	// moment ONE tenant was allocated seats, every other tenant flipped to `allocated <= 0` and was refused. So
	// the behaviour being changed was two extremes with no middle: no ceiling, or a silent fleet-wide stop
	// caused by an unrelated allocation. An alert with a number an operator chose is the middle.
	used := e.ledger.CountAdmitted(tenantID)
	over, quota := e.overQuota(tenantID, licence, used, now)
	if !over {
		return "", false
	}
	reason := fmt.Sprintf("this tenant has %d device(s) against a quota of %d", used, quota)
	if !e.enforceSeatQuota {
		// Reported once per crossing rather than per attempt: a line on every enrolment past the quota is a line
		// nobody reads, which is the same as not raising it.
		e.noteOverQuota(tenantID, used, quota)
		return "", false
	}
	return reason + "; existing devices are unaffected", true
}

// overQuota answers whether this tenant is past the number it has been given, and what that number is.
//
// A tenant with NO quota set is not over one. That is the deliberate consequence of the decision above: an
// unallocated tenant used to be refused outright the moment any other tenant was allocated, and an operator who
// wants a tenant held at zero says so by setting zero, which is a quota like any other and alerts like one.
func (e *enrolmentLicensing) overQuota(tenantID string, licence vendorlicense.Payload, used int, now time.Time) (bool, int) {
	if e.allocations == nil || len(e.allocations.List()) == 0 {
		// No per-tenant quotas anywhere: the licensed pool is the only number there is.
		pool := licence.SeatsAt(now)
		return used >= pool, pool
	}
	if !e.allocations.Has(tenantID) {
		return false, 0
	}
	q := e.allocations.SeatsFor(tenantID)
	return used >= q, q
}

// LicensedFeature reports whether a tenant may use an optional capability right now — DSPM, AI quarantine, and
// whatever follows. Seat-scoped: a capability bought for part of a fleet is licensed for that many seats, and a
// tenant using more of them than it bought is over its entitlement rather than unlicensed.
//
// Deliberately separate from RefuseEnrolment. Enrolment capacity and optional capabilities are different
// quantities, and a block that carries a feature never adds capacity.
func (e *enrolmentLicensing) LicensedFeature(feature string) (seats int, licensed bool) {
	licence, have := e.Current()
	if !have {
		return 0, !e.requireLicence // unlicensed deployment: everything available, as it is today
	}
	n := licence.SeatsForFeatureAt(strings.TrimSpace(feature), e.now().UTC())
	return n, n > 0
}

// applyLicenceFile verifies a licence and puts it in force. Returns the payload so a caller can log what it
// accepted — seats and dates are not secret, and an operator needs them in the record.
func applyLicenceFile(e *enrolmentLicensing, env vendorlicense.Envelope, accepted []*ecdsa.PublicKey,
	expectedMSSPID string, lastAcceptedSerial int64) (vendorlicense.Payload, error) {
	p, err := vendorlicense.Verify(env, accepted, expectedMSSPID, lastAcceptedSerial)
	if err != nil {
		return vendorlicense.Payload{}, err
	}
	e.Apply(p)
	return p, nil
}

// noteOverQuota raises the operator alert for a tenant that has passed the number it was given, once.
//
// It is a LOG line and a state an operator can read back, not a refusal — see RefuseEnrolment for why. The
// wording says what to do about it, because "over quota" alone leaves a reader deciding whether anything broke:
// nothing did, and that is the point worth stating.
func (e *enrolmentLicensing) noteOverQuota(tenantID string, used, quota int) {
	if e == nil {
		return
	}
	key := strings.ToLower(strings.TrimSpace(tenantID))
	if _, already := e.overQuotaSeen.LoadOrStore(key, used); already {
		return
	}
	log.Printf("★ seat_quota_exceeded tenant=%q devices=%d quota=%d — the device WAS admitted: this quota is a "+
		"number to watch, not a gate. Raise the quota if the growth is intended, or investigate if it is not",
		tenantID, used, quota)
}

// OverQuotaTenants is what an operator reads back: every tenant currently past the quota it was given, with the
// two numbers. Exported so the admin summary can show it — an alert only in a log is an alert only for whoever
// happened to be tailing it.
func (e *enrolmentLicensing) OverQuotaTenants() []map[string]any {
	if e == nil || e.allocations == nil {
		return nil
	}
	licence, have := e.Current()
	now := e.now().UTC()
	out := []map[string]any{}
	for _, a := range e.allocations.List() {
		used := e.ledger.CountAdmitted(a.TenantID)
		var over bool
		var quota int
		if have {
			over, quota = e.overQuota(a.TenantID, licence, used, now)
		} else {
			quota = a.Seats
			over = a.Seats > 0 && used >= a.Seats
		}
		if over {
			out = append(out, map[string]any{"tenant_id": a.TenantID, "devices": used, "quota": quota})
		}
	}
	return out
}

// QuotaNote is what to say about a tenant that is NOT blocked: past its quota, or never given one.
//
// Separate from RefuseEnrolment because the answers are different in kind. That one decides admission; this one
// is the operator's view, and after the quota stopped refusing it is the only place the two conditions still
// surface. Empty when there is nothing to say.
func (e *enrolmentLicensing) QuotaNote(tenantID string, used int) string {
	if e == nil || e.allocations == nil || len(e.allocations.List()) == 0 {
		return ""
	}
	if !e.allocations.Has(tenantID) {
		return "no quota set for this tenant; enrolment is not limited by one"
	}
	if q := e.allocations.SeatsFor(tenantID); used >= q {
		return fmt.Sprintf("past its quota of %d (using %d); the quota alerts and does not refuse", q, used)
	}
	return ""
}

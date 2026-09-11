package enrolledinventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// enrol_ownership_test.go — who may write an identity that already exists, decided where the write happens.
//
// ★ THE CHECK USED TO LIVE IN THE CALLER (2026-08-12, eighteenth review). The admin route read the entry,
// decided, and then wrote — two acquisitions of this ledger's mutex with a window in between. Every test of
// that check was sequential, so nothing could see the window; a TOCTOU is invisible to a caller that never
// overlaps with another.

const now = "2026-08-12T00:00:00Z"

func TestATenantCannotEnrolOverAnotherTenantsDevice(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("b-1", "tenant_b", "", now); err != nil {
		t.Fatal(err)
	}
	l.SetEnabled("b-1", false, now)

	_, err := l.EnrollGroupForTenant("b-1", "tenant_a", "tenant_a", "", "taken", now, false)

	if !errors.Is(err, ErrIdentityOwnedByAnotherTenant) {
		t.Fatalf("tenant_a enrolled tenant_b's device (err=%v)", err)
	}
	e, _ := l.EntryFor("b-1")
	if !strings.EqualFold(e.TenantID, "tenant_b") || e.Enabled {
		t.Fatalf("the device moved or was re-enabled: tenant=%q enabled=%v", e.TenantID, e.Enabled)
	}
}

// An operator may adopt a device that belongs to nobody — that is the action the Console tells them to take.
func TestAnOperatorMayAdoptAnUnassignedDeviceAndATenantMayNot(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("legacy-1", "", "", now); err != nil {
		t.Fatal(err)
	}

	if _, err := l.EnrollGroupForTenant("legacy-1", "tenant_a", "tenant_a", "", "", now, false); !errors.Is(err, ErrIdentityUnassigned) {
		t.Fatalf("a tenant admin claimed an unassigned device (err=%v)", err)
	}
	if _, err := l.EnrollGroupForTenant("legacy-1", "tenant_a", "tenant_a", "", "", now, true); err != nil {
		t.Fatalf("an operator could not adopt an unassigned device: %v", err)
	}
	if e, _ := l.EntryFor("legacy-1"); !strings.EqualFold(e.TenantID, "tenant_a") {
		t.Fatalf("the adoption did not assign the device: %q", e.TenantID)
	}
}

// ★ AND AN OPERATOR STILL MAY NOT MOVE ONE BETWEEN TENANTS THIS WAY. Adoption is not a general reassignment
// power; a cross-tenant move is a decision and must not be reachable as a side effect of enrolling.
func TestNotEvenAnOperatorMovesADeviceBetweenTenantsByEnrolling(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("b-1", "tenant_b", "", now); err != nil {
		t.Fatal(err)
	}

	if _, err := l.EnrollGroupForTenant("b-1", "tenant_a", "tenant_a", "", "", now, true); !errors.Is(err, ErrIdentityOwnedByAnotherTenant) {
		t.Fatalf("an operator moved a device between tenants by enrolling it (err=%v)", err)
	}
}

// ★ THE RACE ITSELF. Two tenants POST the same UNREGISTERED identity at once. Exactly one may end up owning
// it — with the check in the caller, both saw "does not exist" and the later write took the device.
func TestTwoTenantsRacingForOneNewIdentityDoNotBothWin(t *testing.T) {
	// Enough goroutines and attempts that the window between "does it exist" and "write it" is actually
	// entered. With the decision inside the lock there is no window at all and this is simply repetitive; with
	// the decision in the caller — the shape being guarded against — it trips within a few attempts.
	const attempts, racers = 4000, 16
	for attempt := 0; attempt < attempts; attempt++ {
		l := NewLedger()
		var wg sync.WaitGroup
		results := make([]error, racers)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			tenant := "tenant_a"
			if i%2 == 1 {
				tenant = "tenant_b"
			}
			wg.Add(1)
			go func(i int, tenant string) {
				defer wg.Done()
				<-start
				_, results[i] = l.EnrollGroupForTenant("contested-1", tenant, tenant, "", "", now, false)
			}(i, tenant)
		}
		close(start)
		wg.Wait()

		e, _ := l.EntryFor("contested-1")
		owner := strings.TrimSpace(e.TenantID)
		for i, err := range results {
			tenant := "tenant_a"
			if i%2 == 1 {
				tenant = "tenant_b"
			}
			// Every caller that was told it succeeded must be the one that owns the device. Two tenants both
			// being told yes is the defect: whichever landed second owns a machine the other believes is
			// theirs, and neither was told anything was wrong.
			if err == nil && !strings.EqualFold(tenant, owner) {
				t.Fatalf("attempt %d: %s was told it enrolled contested-1, which is owned by %q. Both tenants "+
					"saw 'does not exist' before either wrote, so the check answered a question that was no "+
					"longer true by the time the write happened.", attempt, tenant, owner)
			}
		}
		if owner == "" {
			t.Fatalf("attempt %d: the contested device ended up owned by nobody", attempt)
		}
	}
}

// ★ THE PUBLIC DOOR INTO THE SAME ROOM (2026-08-12, nineteenth review). The admin route was made atomic and
// the device-facing one still called a method that checked only the disabled flag and then assigned TenantID
// unconditionally — so a caller holding a valid enrolment credential for one tenant could name another
// tenant's device id, move the ledger entry, and be issued a certificate for it.
func TestADeviceCredentialCannotEnrolOverAnotherTenantsDevice(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("a-1", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}

	_, err := l.EnrollDeviceForTenant("a-1", "tenant_b", "", "enrolled via POST /enroll", now)

	if !errors.Is(err, ErrIdentityOwnedByAnotherTenant) {
		t.Fatalf("a tenant_b credential enrolled tenant_a's device (err=%v)", err)
	}
	if e, _ := l.EntryFor("a-1"); !strings.EqualFold(e.TenantID, "tenant_a") {
		t.Fatalf("the device moved to %q", e.TenantID)
	}
}

// The device path still refuses a DISABLED identity — that check predates this one and must survive it.
func TestADeviceCredentialCannotReEnableADisabledIdentity(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("a-1", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}
	l.SetEnabled("a-1", false, now)

	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityDisabled) {
		t.Fatalf("a disabled identity re-enrolled itself (err=%v)", err)
	}
	if e, _ := l.EntryFor("a-1"); e.Enabled {
		t.Fatal("admission was restored by the device the operator had blocked")
	}
}

// And a device enrolling for the first time against a seeded entry with no tenant still works — the evidence
// here is a one-time credential an administrator issued for that tenant, not a person naming a string.
func TestADeviceCredentialAssignsASeededUnassignedEntry(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("new-1", "", "", now); err != nil {
		t.Fatal(err)
	}

	if _, err := l.EnrollDeviceForTenant("new-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("a first enrolment against a seeded entry was refused: %v", err)
	}
	if e, _ := l.EntryFor("new-1"); !strings.EqualFold(e.TenantID, "tenant_a") {
		t.Fatalf("the enrolment did not assign the tenant: %q", e.TenantID)
	}
}

// ★ AND THE TWO DOORS RACE EACH OTHER. An admin POST and a device enrolment for DIFFERENT tenants, on the same
// unregistered identity, at the same moment: exactly one may end up owning it.
func TestTheAdminAndDeviceDoorsDoNotBothWinTheSameIdentity(t *testing.T) {
	const attempts, rounds = 2000, 4
	for attempt := 0; attempt < attempts; attempt++ {
		l := NewLedger()
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, rounds*2)
		for i := 0; i < rounds; i++ {
			wg.Add(2)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i*2] = l.EnrollGroupForTenant("contested-2", "tenant_a", "tenant_a", "", "", now, false)
			}(i)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i*2+1] = l.EnrollDeviceForTenant("contested-2", "tenant_b", "", "", now)
			}(i)
		}
		close(start)
		wg.Wait()

		e, _ := l.EntryFor("contested-2")
		owner := strings.TrimSpace(e.TenantID)
		for i, err := range errs {
			claimed := "tenant_a"
			if i%2 == 1 {
				claimed = "tenant_b"
			}
			if err == nil && !strings.EqualFold(claimed, owner) {
				t.Fatalf("attempt %d: a caller claiming %s succeeded on a device now owned by %q — the admin "+
					"route and the device route decided independently and both wrote", attempt, claimed, owner)
			}
		}
	}
}

// ★ THE CROSS-TENANT REFUSAL LEFT THE SAME-TENANT ONE OPEN (2026-08-12, twentieth review). An enrolment token
// is one-time but is not bound to a device id — nothing in the token names one, and the Console cannot know
// the id before the machine is set up — so any holder of a valid credential for a tenant could name an
// EXISTING device in that tenant and be issued a fresh certificate under its name.
func TestADeviceCannotEnrolAnIdentityThatHasAlreadyEnrolled(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "first", now); err != nil {
		t.Fatal(err)
	}

	_, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "second", now)

	if !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("a second device enrolled an identity that already had a certificate (err=%v) — same tenant, "+
			"so the cross-tenant check never fires, and the impersonator gets a certificate in that machine's name", err)
	}
}

// An identity an OPERATOR pre-added — the entry exists, no device has ever enrolled it — is still the normal
// first enrolment. Refusing that would mean a pre-approved device could never come online.
func TestADevicePreAddedByAnOperatorCanStillEnrolOnce(t *testing.T) {
	l := NewLedger()
	if _, err := l.Enroll("a-2", "tenant_a", "pre-added by an operator", now); err != nil {
		t.Fatal(err)
	}

	if _, err := l.EnrollDeviceForTenant("a-2", "tenant_a", "", "", now); err != nil {
		t.Fatalf("a pre-approved device could not enrol: %v", err)
	}
	// And exactly once.
	if _, err := l.EnrollDeviceForTenant("a-2", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("it enrolled twice (err=%v)", err)
	}
}

// The marker has to survive a reload, or a restart of the Edge reopens the window for every device.
func TestTheDeviceEnrolmentMarkerIsPartOfTheEntry(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-3", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}
	e, ok := l.EntryFor("a-3")
	if !ok || strings.TrimSpace(e.DeviceEnrolledAt) == "" {
		t.Fatalf("the entry does not record that a device enrolled it: %+v", e)
	}
}

// ★ THE CONFIG BUNDLE ERASED THE MARKER, WHICH RE-OPENED EVERY ENROLLED DEVICE (2026-08-12, twenty-first
// review). Enrolment happens at the Edge, so the control plane's copy of an entry carries no marker — and the
// bundle REPLACES this ledger. Any unrelated CP change therefore made every enrolled identity enrollable
// again by whoever holds a credential for its tenant. In the reference topology one Edge has both a config
// source and a device CA signer, so this is the supported configuration.
func TestAControlPlaneUpdateDoesNotReOpenAnEnrolledDevice(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	// What the CP holds: the same identity, admitted, with no idea that a device has enrolled it.
	_ = l.MergeAuthoritative([]Entry{{Identity: "a-1", Enabled: true, TenantID: "tenant_a"}}, now)

	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("after a control-plane update the device could enrol again (err=%v) — one config change on an "+
			"unrelated setting re-opens the whole fleet", err)
	}
}

// And the administrator's decision still propagates FROM the control plane: a re-arm granted there must reach
// an Edge that thinks the device is enrolled, or the permission is unusable in the topology it is for.
func TestAReArmGrantedOnTheControlPlaneReachesTheEdge(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	// The CP's copy after an admin permitted a re-enrolment there: same entry, grant 1.
	_ = l.MergeAuthoritative([]Entry{{Identity: "a-1", Enabled: true, TenantID: "tenant_a", ReenrolmentNonce: 1}}, now)

	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("a re-enrolment granted on the control plane did not reach the device: %v", err)
	}
	// And it is spent: the same grant does not permit a second one.
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("one grant permitted two enrolments (err=%v)", err)
	}
}

// ★ RE-ARM IS NOT A SIDE EFFECT OF EDITING A DEVICE. An admin fixing a note or assigning a group must not
// silently re-open enrolment for it.
func TestReAddingADeviceDoesNotPermitReEnrolment(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	if _, err := l.EnrollGroupForTenant("a-1", "tenant_a", "tenant_a", "laptops", "moved desk", now, false); err != nil {
		t.Fatalf("an admin could not edit their own device: %v", err)
	}

	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("editing the device re-opened enrolment for it (err=%v)", err)
	}
	if _, _, err := l.AllowReenrolment("a-1", "tenant_a", now); err != nil {
		t.Fatalf("the explicit permission failed: %v", err)
	}
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("after the explicit permission the device still could not enrol: %v", err)
	}
}

// stubClaimer is a shared claim: one map, the way one database row behaves for every issuer that asks.
type stubClaimer struct {
	mu          sync.Mutex
	grants      map[string]int
	held        map[string]bool
	fail        error
	failRelease error
}

func newStubClaimer() *stubClaimer {
	return &stubClaimer{grants: map[string]int{}, held: map[string]bool{}}
}

func (s *stubClaimer) ClaimIdentity(_ context.Context, tenantID, identity string, grant int) (bool, error) {
	if s.fail != nil {
		return false, s.fail
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tenantID + "\x00" + identity
	if s.held[k] && grant <= s.grants[k] {
		return false, nil
	}
	s.held[k], s.grants[k] = true, grant
	return true, nil
}

// ★ TWO ISSUERS, EACH WITH ITS OWN LEDGER, MUST NOT BOTH ISSUE (2026-08-13, twenty-fourth review). Separate
// node-local files were the previous "fix" and they are the worst version: neither node can see the other's
// enrolment, so both answer "never enrolled" for the same name.
func TestTwoIssuersSharingAClaimCannotBothEnrolOneIdentity(t *testing.T) {
	claim := newStubClaimer()
	a, b := NewLedger(), NewLedger()
	a.SetIdentityClaimer(claim)
	b.SetIdentityClaimer(claim)

	if _, err := a.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("the first issuer could not enrol: %v", err)
	}
	_, err := b.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now)

	if !errors.Is(err, ErrIdentityClaimedElsewhere) {
		t.Fatalf("a second issuer with its own ledger issued for the same device name (err=%v) — its ledger has "+
			"no marker because the enrolment happened on the other node, which is exactly what per-node files "+
			"guarantee", err)
	}
}

// The operator's re-arm still reaches the second issuer, or the claim would strand a re-imaged machine.
func TestAReArmLetsAnyIssuerEnrolThatIdentityOnce(t *testing.T) {
	claim := newStubClaimer()
	a, b := NewLedger(), NewLedger()
	a.SetIdentityClaimer(claim)
	b.SetIdentityClaimer(claim)
	// Both nodes hold the control plane's entry, which is how a second Edge knows the identity at all.
	cp := []Entry{{Identity: "win-dev-1", Enabled: true, TenantID: "tenant_a"}}
	_ = a.MergeAuthoritative(cp, now)
	_ = b.MergeAuthoritative(cp, now)
	if _, err := a.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	// The administrator permits it again — on node b, which is where the operator happened to be.
	if _, _, err := b.AllowReenrolment("win-dev-1", "tenant_a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("after the operator's permission the device could not enrol: %v", err)
	}
	// And that one grant is spent for BOTH nodes. Node a refuses from its OWN marker here rather than from the
	// shared claim — either is a refusal, and asserting which layer spoke would pin the order of two checks
	// rather than the property, which is that one permission produces one certificate.
	if _, err := a.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err == nil {
		t.Fatal("one grant let two issuers each enrol: two certificates exist for one device name")
	}
}

// A claim that cannot be taken is not a yes: an unknown answer must refuse rather than issue.
func TestAClaimStoreThatErrorsRefusesTheEnrolment(t *testing.T) {
	claim := newStubClaimer()
	claim.fail = errors.New("database unreachable")
	l := NewLedger()
	l.SetIdentityClaimer(claim)

	if _, err := l.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err == nil {
		t.Fatal("an enrolment was issued while the shared claim could not be taken — an unknown answer is not a yes")
	}
}

func (s *stubClaimer) ReleaseIdentity(_ context.Context, tenantID, identity string, grant int) error {
	if s.failRelease != nil {
		return s.failRelease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tenantID + "\x00" + identity
	if s.grants[k] == grant {
		delete(s.held, k)
	}
	return nil
}

func (s *stubClaimer) BackfillClaims(_ context.Context, claims []IdentityClaim) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range claims {
		k := c.TenantID + "\x00" + c.Identity
		if !s.held[k] {
			s.held[k], s.grants[k] = true, c.Grant
			n++
		}
	}
	return n, nil
}

// ★ A CLAIM TAKEN FOR AN ENROLMENT THAT THEN FAILED LOCALLY MUST GO BACK (2026-08-13, twenty-fifth review).
// Otherwise the device gets no certificate AND cannot retry — its one-time token is spent and the identity is
// claimed — so a disk error turns into "an administrator must re-arm this machine". Fail-closed either way;
// this is the difference between safe and stuck.
func TestAClaimIsReleasedWhenTheLocalRecordCannotBeWritten(t *testing.T) {
	claim := newStubClaimer()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLedger()
	l.SetStatePath(filepath.Join(blocker, "inventory.json")) // every save fails
	l.SetIdentityClaimer(claim)

	if _, err := l.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err == nil {
		t.Fatal("an enrolment succeeded although its record could not be written")
	}

	// A healthy node must still be able to enrol that device.
	healthy := NewLedger()
	healthy.SetIdentityClaimer(claim)
	if _, err := healthy.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("the identity stayed claimed after a failed enrolment (%v) — the device's one-time token is "+
			"spent and only an administrator can free it", err)
	}
}

// ★ THE EXISTING FLEET MUST BE CLAIMED BEFORE A SECOND ISSUER APPEARS. A new claim table is empty, and a new
// issuer has no local marker either, so every identity enrolled before the upgrade is available to it.
func TestBackfillClaimsWhatThisNodeHasAlreadyEnrolled(t *testing.T) {
	claim := newStubClaimer()
	a := NewLedger()
	a.SetIdentityClaimer(claim)
	// Enrolled BEFORE the shared claim existed: recorded locally, unknown to the claim store.
	a.SetIdentityClaimer(nil)
	if _, err := a.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}
	// An operator pre-added this one and no device has ever enrolled it: it must stay available.
	if _, err := a.Enroll("win-dev-2", "tenant_a", "pre-added", now); err != nil {
		t.Fatal(err)
	}
	a.SetIdentityClaimer(claim)

	n, err := a.BackfillIdentityClaims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("backfilled %d claims; exactly the one already-enrolled identity should be claimed", n)
	}

	b := NewLedger()
	b.SetIdentityClaimer(claim)
	if _, err := b.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityClaimedElsewhere) {
		t.Fatalf("a second issuer enrolled an identity that was already in use before the upgrade (err=%v)", err)
	}
	if _, err := b.EnrollDeviceForTenant("win-dev-2", "tenant_a", "", "", now); err != nil {
		t.Fatalf("the backfill claimed a device that had never enrolled: %v", err)
	}
}

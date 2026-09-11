package enrolledinventory

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// enrol_marker_durability_test.go — the marker has to be on DISK before the certificate is handed over, and a
// store written before the marker existed must not read as "nobody has enrolled".

// ★ THE MARKER WAS A SECOND WRITE AFTER THE ENTRY (2026-08-12, twenty-first review), and persistLocked only
// logged — so a failure or a crash between the two left a device holding a certificate and a store saying
// that identity had never enrolled. The endpoint answered 200 either way.
func TestTheEnrolmentMarkerIsOnDiskBeforeTheCallerIsToldItSucceeded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	l := NewLedger()
	l.SetStatePath(path)
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	// Read what a restart would read — not what this process remembers.
	reloaded := NewLedger()
	reloaded.SetStatePath(path)

	e, ok := reloaded.EntryFor("a-1")
	if !ok || strings.TrimSpace(e.DeviceEnrolledAt) == "" {
		t.Fatalf("the store does not record that a device enrolled: %+v", e)
	}
	if _, err := reloaded.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("after a restart the identity could enrol again (err=%v)", err)
	}
}

// A store that cannot be written must not produce a certificate. The caller clears the journal's pending
// state on success, so "succeeded but not recorded" is the one outcome that cannot be recovered from.
func TestAnEnrolmentThatCannotBeRecordedIsRefused(t *testing.T) {
	dir := t.TempDir()
	// The state path's parent is a FILE, so every save fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLedger()
	l.SetStatePath(filepath.Join(blocker, "inventory.json"))

	_, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now)

	if err == nil {
		t.Fatal("an enrolment that could not be recorded returned success: the device is handed a certificate " +
			"and the next restart says that identity has never enrolled, so it can be enrolled again")
	}
	if _, ok := l.EntryFor("a-1"); ok {
		t.Fatal("the failed enrolment was left in memory, so this process disagrees with its own store")
	}
}

// ★ A v1 STORE'S SILENCE IS NOT "NEVER ENROLLED". Every entry written before the marker existed would
// otherwise be enrollable once by anyone holding a credential for its tenant — the whole existing fleet.
func TestEntriesFromAV1StoreAreTreatedAsAlreadyEnrolled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	v1 := map[string]any{
		"schema_version": "enrolled_inventory_state.v1",
		"entries": map[string]any{
			"mac-dev-1": map[string]any{"identity": "mac-dev-1", "enabled": true, "tenant_id": "tenant_a"},
		},
	}
	raw, _ := json.Marshal(v1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	l := NewLedger()
	l.SetStatePath(path)

	if _, err := l.EnrollDeviceForTenant("mac-dev-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("an identity from a pre-marker store could be enrolled (err=%v) — that is one free "+
			"impersonation for every device already in the fleet", err)
	}
	// And an operator can still let a genuine re-image through.
	if _, _, err := l.AllowReenrolment("mac-dev-1", "tenant_a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EnrollDeviceForTenant("mac-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("after the operator's permission the device could not enrol: %v", err)
	}
}

// ★ THE STATIC ADMISSION LIST IS THE OTHER WAY IN (2026-08-12, twenty-first review, second pass). The v2
// migration covers entries that arrive from the durable STORE. Seeding happens at boot, before the store is
// attached, and where no store is configured — or on a first boot with an empty one — those entries survive
// with no marker. Each is then one same-tenant impersonation, which is the category the migration exists to
// close, arriving by a route it did not cover.
func TestAStaticallySeededIdentityCannotBeEnrolledByAnyoneWhoKnowsItsName(t *testing.T) {
	l := NewLedger()
	l.SeedFromStatic(map[string]struct{}{"mac-dev-1": {}, "win-dev-1": {}}, now)

	if _, err := l.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("a statically seeded identity could be enrolled (err=%v) — on a deployment with no durable "+
			"store, every name in the admission list is one free certificate to whoever holds a token", err)
	}
	// And the operator's exception still works.
	if _, _, err := l.AllowReenrolment("win-dev-1", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EnrollDeviceForTenant("win-dev-1", "tenant_a", "", "", now); err != nil {
		t.Fatalf("after the operator's permission the seeded device could not enrol: %v", err)
	}
}

// A re-seed must not disturb an entry that already exists — including one a device has enrolled.
func TestReSeedingDoesNotTouchAnEnrolledEntry(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}
	e, _ := l.EntryFor("a-1")
	wasEnrolledAt := e.DeviceEnrolledAt

	l.SeedFromStatic(map[string]struct{}{"a-1": {}}, "2026-09-01T00:00:00Z")

	after, _ := l.EntryFor("a-1")
	if after.DeviceEnrolledAt != wasEnrolledAt {
		t.Fatalf("a re-seed rewrote the enrolment marker: %q -> %q", wasEnrolledAt, after.DeviceEnrolledAt)
	}
	if !strings.EqualFold(after.TenantID, "tenant_a") {
		t.Fatalf("a re-seed dropped the tenant: %q", after.TenantID)
	}
}

// ★ A PERMISSION THAT COULD NOT BE RECORDED WAS STILL GRANTED IN MEMORY (2026-08-12, twenty-second review).
// The rollback restored the entry it had just written rather than the one before it, so a re-arm whose
// durable write failed answered 500 and cleared the marker anyway — and the very next enrolment from anyone
// holding a credential for that tenant succeeded.
func TestAReArmThatCouldNotBePersistedDoesNotTakeEffect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	l := NewLedger()
	l.SetStatePath(path)
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err != nil {
		t.Fatal(err)
	}

	// Make every later save fail: replace the state file's directory with a file.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := l.AllowReenrolment("a-1", "tenant_a", now); err == nil {
		t.Fatal("a re-arm that could not be recorded reported success")
	}

	// Put the store back, so the enrolment below can fail for exactly ONE reason: the permission that was
	// never granted. Otherwise a persist error would mask the state this test is about.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The point: this process must still refuse the enrolment the failed permission would have allowed.
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
		t.Fatalf("after a FAILED re-arm the identity could enrol again (err=%v) — the API said 500 and the "+
			"permission took effect anyway, so whoever holds a credential for this tenant gets a certificate "+
			"in that machine's name", err)
	}
}

// ★ THE MERGE READ LOCAL STATE, RELEASED THE LOCK, AND WROTE BACK WHAT IT HAD DECIDED (2026-08-12,
// twenty-second review). An enrolment completing in that gap was overwritten by the stale decision, so a
// config bundle that had nothing to do with the device re-opened it.
func TestAnEnrolmentDuringAConfigMergeIsNotOverwritten(t *testing.T) {
	// The window between a snapshot and a swap is a few instructions wide, and a merge that runs ONCE beside
	// an enrolment almost never lands in it. So the mergers run CONTINUOUSLY while the enrolment happens, the
	// way a config-source poll does against a fleet that is enrolling: that is what enters the window
	// reliably against a deliberately reintroduced two-phase version. The enrolment TOCTOU taught the same
	// lesson — a concurrency test that has never been run against the bug asserts nothing.
	const attempts, mergers = 400, 4
	cp := []Entry{{Identity: "a-1", Enabled: true, TenantID: "tenant_a"}}
	for attempt := 0; attempt < attempts; attempt++ {
		l := NewLedger()
		_ = l.MergeAuthoritative(cp, now) // the identity is admitted; no device has enrolled it yet

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < mergers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = l.MergeAuthoritative(cp, now)
					}
				}
			}()
		}
		runtime.Gosched()
		_, enrolErr := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now)
		close(stop)
		wg.Wait()

		if enrolErr != nil {
			continue // the enrolment lost outright; there is nothing to preserve
		}
		// It succeeded, so a certificate was issued: the identity must be spent, whatever the merges did.
		if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); !errors.Is(err, ErrIdentityAlreadyEnrolled) {
			e, _ := l.EntryFor("a-1")
			t.Fatalf("attempt %d: a device enrolled and a concurrent config merge erased the record (%+v). "+
				"A certificate exists for that name and the next caller can obtain another one.", attempt, e)
		}
	}
}

// ★ AN UNREADABLE LEDGER MUST NOT READ AS AN EMPTY ONE (2026-08-13, twenty-sixth review). loadLocked logged a
// read or parse failure and carried on — for a node about to ISSUE certificates that means "every identity in
// the fleet is unenrolled", after which it claims them all and hands out certificates in their names. The
// caller has to be able to refuse, so the failure is returned.
func TestAnUnreadableLedgerIsReportedRatherThanTreatedAsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	l := NewLedger()
	err := l.SetPersisterChecked(blobstore.FilePersister{Path: path})

	if err == nil {
		t.Fatal("an unparseable enrolled inventory loaded silently: an issuing node would treat the whole fleet " +
			"as never enrolled and start issuing in their names")
	}
}

// And a store that is simply absent is NOT a failure — that is a new deployment, which is the ordinary case.
func TestAnAbsentLedgerIsNotAFailure(t *testing.T) {
	l := NewLedger()
	if err := l.SetPersisterChecked(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "new.json")}); err != nil {
		t.Fatalf("a deployment with no ledger yet refused to start: %v", err)
	}
}

// ★ DISABLE IS THE MANUAL REVOCATION PATH (2026-08-13, twenty-seventh review). It took a best-effort write, so
// an operator revoking a compromised device got success whether or not it was recorded — and the next restart
// made the durable store authoritative, readmitting the machine with an audit trail saying it had been revoked.
func TestDisablingADeviceFailsWhenItCannotBeRecorded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	l := NewLedger()
	l.SetStatePath(path)
	if _, err := l.Enroll("stolen-1", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}

	// Every later save fails.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := l.SetEnabledChecked("stolen-1", false, now)

	if err == nil {
		t.Fatal("disabling a device reported success although the change could not be recorded: the operator " +
			"believes the machine is revoked and the next restart readmits it")
	}
	if errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("a write failure was reported as 'not in the inventory' (%v) — that sends the operator looking "+
			"for the wrong problem", err)
	}
	// And memory agrees with the disk: the device is still enabled here too.
	if e, _ := l.EntryFor("stolen-1"); !e.Enabled {
		t.Fatal("this process believes the device is disabled while the store does not — one restart apart")
	}
}

// ★ A STORE THIS PROCESS NEVER READ MUST NOT BE OVERWRITTEN BY IT (2026-08-13, twenty-seventh review). A
// non-issuing Edge continues on a failed load, and the persister is already attached — so the next admin
// change or bundle merge saved a seed-only ledger over a file whose enrolment markers were merely unreadable
// a moment ago. The SingleWriter guard cannot help: it arms on a successful load.
func TestAFailedLoadLatchesWritesOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLedger()
	if err := l.SetPersisterChecked(blobstore.FilePersister{Path: path}); err == nil {
		t.Fatal("an unparseable store loaded silently")
	}

	// A later change must not be persisted over the file this process could not read.
	if _, err := l.EnrollDeviceForTenant("a-1", "tenant_a", "", "", now); err == nil {
		t.Fatal("a write went through to a store this process never read — the markers in it would be gone")
	}
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(raw) != "{not json" {
		t.Fatalf("the unreadable store was overwritten anyway: %s", raw)
	}
}

// ★ REMOVING A DEVICE IS A REVOCATION (2026-08-13, twenty-eighth review). Remove persisted through the
// best-effort seam, so an operator removing a compromised machine got success in memory and in the API while
// the durable store still held it — and the next restart put it back.
func TestRemovingADeviceFailsWhenItCannotBeRecorded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	l := NewLedger()
	l.SetStatePath(path)
	if _, err := l.Enroll("compromised-1", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if l.Remove("compromised-1", "2026-08-24T00:00:00Z") {
		t.Fatal("removing a device reported success although it could not be recorded: the operator believes " +
			"the machine is gone and the next restart brings it back")
	}
	if _, ok := l.EntryFor("compromised-1"); !ok {
		t.Fatal("the device was dropped from memory anyway, so this process disagrees with its own store")
	}
}

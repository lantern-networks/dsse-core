package steerexclusion

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sharedRows is one durable store that two control planes read, as the deployment's database is.
type sharedRows struct {
	mu   sync.Mutex
	rows map[string]Policy
}

func (s *sharedRows) LoadAll(context.Context) ([]*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*Policy{}
	for _, p := range s.rows {
		c := clonePolicy(p)
		// What comes back from a database: no monotonic reading, another location.
		c.CreatedAt = c.CreatedAt.Round(0).In(time.FixedZone("db", 9*3600))
		c.UpdatedAt = c.UpdatedAt.Round(0).In(time.FixedZone("db", 9*3600))
		out = append(out, &c)
	}
	return out, nil
}

func (s *sharedRows) Upsert(_ context.Context, p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[p.ID] = clonePolicy(*p)
	return nil
}

func (s *sharedRows) Delete(_ context.Context, id, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}

// TestAChangeMadeThroughAnotherControlPlaneMovesThisOnesVersion: the config bundle carries the set now, and an
// Edge applies a bundle only when its version is newer. A policy written through control plane A has to move
// control plane B's version once B re-reads the database, or the Edges pulling from B never take it.
func TestAChangeMadeThroughAnotherControlPlaneMovesThisOnesVersion(t *testing.T) {
	db := &sharedRows{rows: map[string]Policy{}}
	a, err := NewStoreWithPersistence(db)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStoreWithPersistence(db)
	if err != nil {
		t.Fatal(err)
	}
	before := b.ConfigGeneration()

	saved, err := a.Upsert(Policy{TenantID: "org-1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{`\git\usr\bin\ssh.exe`}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.ConfigGeneration() == 0 {
		t.Fatal("the control plane that took the write did not move its version")
	}
	b.mu.Lock()
	b.refreshedAt = time.Time{} // past the refresh window
	b.mu.Unlock()
	afterWrite := b.ConfigGeneration()
	if afterWrite <= before {
		t.Fatalf("control plane B re-read the database holding a new policy and its version stayed %d", afterWrite)
	}
	all, err := b.SnapshotAllChecked()
	if err != nil || len(all) != 1 || all[0].ID != saved.ID {
		t.Fatalf("B's snapshot = %+v, %v; want the policy written through A", all, err)
	}

	// Re-reading the same rows — times now from the database, in another zone — is not a change.
	b.mu.Lock()
	b.refreshedAt = time.Time{}
	b.mu.Unlock()
	if again := b.ConfigGeneration(); again != afterWrite {
		t.Fatalf("re-reading unchanged rows moved the version %d -> %d; every Edge would re-pull for nothing", afterWrite, again)
	}

	if _, err := a.DeleteChecked(saved.ID, "org-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.refreshedAt = time.Time{}
	b.mu.Unlock()
	if afterDelete := b.ConfigGeneration(); afterDelete <= afterWrite {
		t.Fatalf("a deletion through A left B's version at %d; the deletion would never reach an Edge", afterDelete)
	}
}

// TestADeviceScopedPolicyFindsTheDeviceTheWayTheScreenDoes: the Console says whether a device-scoped policy
// applies by comparing identities case-blind, because its lists spell the same machine differently. Resolving
// exactly would make the screen say "applies" about a device this never gave it to.
func TestADeviceScopedPolicyFindsTheDeviceTheWayTheScreenDoes(t *testing.T) {
	s := NewStore()
	if _, err := s.Upsert(Policy{TenantID: "org-1", ScopeType: "device", ScopeID: "DESKTOP-ACC3", ExcludedAppSigningIDs: []string{`\git\usr\bin\ssh.exe`}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := s.ResolveForDevice("org-1", "desktop-acc3", ""); len(got) != 1 {
		t.Fatalf("resolved %v for the same machine spelled in lower case", got)
	}
	if got := s.ResolveForDevice("org-1", "desktop-acc4", ""); len(got) != 0 {
		t.Fatalf("resolved %v for another machine", got)
	}
	if got := s.ResolveForDevice("org-2", "desktop-acc3", ""); len(got) != 0 {
		t.Fatalf("resolved %v across organizations", got)
	}
}

// TestADeviceExclusionIsNotGivenToAnotherEnrolledDevice — review C3-R2: "desktop-s" and "desktop-ſ" are two
// enrolled devices, and EqualFold called them one.
func TestADeviceExclusionIsNotGivenToAnotherEnrolledDevice(t *testing.T) {
	s := NewStore()
	if _, err := s.Upsert(Policy{TenantID: "org-1", ScopeType: "device", ScopeID: "desktop-s", ExcludedAppSigningIDs: []string{"a.exe"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := s.ResolveForDevice("org-1", "desktop-ſ", ""); len(got) != 0 {
		t.Fatalf("the exclusion for desktop-s was given to desktop-ſ: %v", got)
	}
	if got := s.ResolveForDevice("org-1", " DESKTOP-S ", ""); len(got) != 1 {
		t.Fatalf("the same enrolled device spelled in capitals was refused: %v", got)
	}
}

// TestTheDeviceRelationIsEnrolments keeps sameEnrolledIdentity equal to enrolment's normalization, which this
// package does not import.
func TestTheDeviceRelationIsEnrolments(t *testing.T) {
	normalize := func(id string) string { return strings.ToLower(strings.TrimSpace(id)) } // enrolledinventory.NormalizeIdentity
	for _, pair := range [][2]string{{"A", "a"}, {"desktop-s", "desktop-ſ"}, {"K", "K"}, {" x ", "X"}, {"ß", "SS"}} {
		if got, want := sameEnrolledIdentity(pair[0], pair[1]), normalize(pair[0]) == normalize(pair[1]); got != want {
			t.Errorf("%q vs %q: %t, enrolment says %t", pair[0], pair[1], got, want)
		}
	}
	src, err := os.ReadFile(filepath.Join("..", "enrolledinventory", "ledger.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "func NormalizeIdentity(id string) string { return strings.ToLower(strings.TrimSpace(id)) }") {
		t.Fatal("enrolment's NormalizeIdentity changed; change sameEnrolledIdentity with it")
	}
}

// readOnlyRows loads what it holds and refuses every write: a cache that can be read and, for the moment, not
// written.
type readOnlyRows struct{ sharedRows }

func (r *readOnlyRows) Upsert(context.Context, *Policy) error { return errors.New("disk full") }
func (r *readOnlyRows) Delete(context.Context, string, string) error {
	return errors.New("disk full")
}

// TestARemovalThatCouldNotBeSavedIsReportedAndNotUndone — review C3-R3: the removal was reported as applied,
// the save failed in silence, and five seconds later the stale cache was read back over it.
func TestARemovalThatCouldNotBeSavedIsReportedAndNotUndone(t *testing.T) {
	now := time.Now().UTC()
	cache := &readOnlyRows{sharedRows{rows: map[string]Policy{
		"sx_old": {ID: "sx_old", TenantID: "org-1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"ssh.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now},
	}}}
	s, err := NewStoreWithPersistence(cache)
	if err != nil {
		t.Fatal(err)
	}
	s.SetReceiver()
	err = s.ReplaceTenantsChecked(map[string][]Policy{"org-1": {}})
	if !errors.Is(err, ErrPersistence) {
		t.Fatalf("a removal whose durable copy failed was reported as %v; it must be an error so it is offered again", err)
	}
	if got := s.ResolveForDevice("org-1", "any", ""); len(got) != 0 {
		t.Fatalf("the removal the control plane sent is not in force: %v", got)
	}
	s.mu.Lock()
	s.refreshedAt = time.Time{}
	s.mu.Unlock()
	if got := s.ResolveForDevice("org-1", "any", ""); len(got) != 0 {
		t.Fatalf("the stale cache was read back over the removal: %v", got)
	}
}

// TestNothingChangesWhenOneOrganizationIsRefused — everything is checked before anything is replaced: a conflict
// in the second organization used to be found after the first had been replaced.
func TestNothingChangesWhenOneOrganizationIsRefused(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	keep := Policy{ID: "sx_c", TenantID: "org-c", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"c.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now}
	a := Policy{ID: "sx_a", TenantID: "org-a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"a.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := s.ReplaceTenantsChecked(map[string][]Policy{"org-c": {keep}, "org-a": {a}}); err != nil {
		t.Fatal(err)
	}
	stolen := keep
	stolen.TenantID = "org-b" // org-b claims org-c's policy ID, and org-c is not being replaced
	err := s.ReplaceTenantsChecked(map[string][]Policy{"org-a": {}, "org-b": {stolen}})
	if !errors.Is(err, ErrTenantConflict) {
		t.Fatalf("err=%v, want the conflict", err)
	}
	if got := s.ResolveForDevice("org-a", "x", ""); len(got) != 1 {
		t.Fatalf("org-a was replaced although the call was refused: %v", got)
	}
}

// flakyRows fails the first Delete and then works, as a cache whose disk was briefly full.
type flakyRows struct {
	sharedRows
	deletes, failFirst int
}

func (f *flakyRows) Delete(ctx context.Context, id, tenant string) error {
	f.deletes++
	if f.deletes <= f.failFirst {
		return errors.New("disk full")
	}
	return f.sharedRows.Delete(ctx, id, tenant)
}

// TestARemovalWhoseSaveFailedIsRetriedUntilItIsDurable — review C3-RR1: the retry took its removals from memory,
// which had already dropped the row, so it removed nothing, reported success, and the next start loaded the
// removed exclusion back from the cache.
func TestARemovalWhoseSaveFailedIsRetriedUntilItIsDurable(t *testing.T) {
	now := time.Now().UTC()
	cache := &flakyRows{failFirst: 1, sharedRows: sharedRows{rows: map[string]Policy{
		"sx_old": {ID: "sx_old", TenantID: "org-1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"ssh.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now},
	}}}
	s, err := NewStoreWithPersistence(cache)
	if err != nil {
		t.Fatal(err)
	}
	s.SetReceiver()
	if err := s.ReplaceTenantsChecked(map[string][]Policy{"org-1": {}}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("first attempt: %v, want the failed save reported", err)
	}
	// The same bundle, offered again.
	if err := s.ReplaceTenantsChecked(map[string][]Policy{"org-1": {}}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if cache.deletes != 2 {
		t.Fatalf("the durable copy was asked to remove the row %d time(s); the retry must ask again", cache.deletes)
	}
	// The next start reads the cache.
	restarted, err := NewStoreWithPersistence(cache)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.ResolveForDevice("org-1", "any", ""); len(got) != 0 {
		t.Fatalf("after a restart the removed exclusion is back: %v", got)
	}
}

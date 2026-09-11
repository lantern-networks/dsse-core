//go:build windows

// Tests for the STICKY verified-app store behind signature-form steer exclusions on the WFP backend.
//
// The defect these are written against (measured 2026-08-06): the pushed exact-APP_ID set was rebuilt from
// CURRENTLY RUNNING processes on every tick, so a verified image's path disappeared from the kernel table the
// moment its process exited. `signed:winget.exe` was distributed, verified, and reported as effective while
// enforcing nothing, because winget lives ~5s and the scan runs every 30s — and even a lucky catch was undone
// on the next tick. Membership is a property of the IMAGE, not of a live process.
package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func mkApp(nt string, seen time.Time) verifiedApp {
	return verifiedApp{win32: `C:\x\` + nt, nt: `\device\harddiskvolume3\x\` + nt, lastSeen: seen}
}

// A verified image must stay enforced after its process is gone. This is the whole bug: the old
// implementation had no store at all, so "not running right now" and "not excluded" were the same state.
func TestVerifiedAppStoreKeepsEntriesAfterTheProcessExits(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	s.add(mkApp("winget.exe", base))

	// Simulate many later sweeps in which winget is NOT running: nothing re-adds it, nothing may drop it.
	for i := 0; i < 5; i++ {
		scanRunningIntoStore(newAppBypass(nil), nil, s, base.Add(time.Duration(i)*time.Minute))
	}
	got := s.list()
	if len(got) != 1 {
		t.Fatalf("list() = %v, want the entry retained while its process is not running", got)
	}
}

// touch must refresh recency and report a hit, so a repeat sighting skips the (millisecond) Authenticode work.
func TestVerifiedAppStoreTouchReportsMembershipAndRefreshesRecency(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	a := mkApp("winget.exe", base)
	s.add(a)

	if !s.touch(a.nt, base.Add(time.Hour)) {
		t.Fatal("touch() on a stored entry = false, want true")
	}
	if s.touch(`\device\harddiskvolume3\x\absent.exe`, base) {
		t.Fatal("touch() on an unknown entry = true, want false")
	}
	// Case-insensitivity matters: the kernel compares ALE_APP_ID case-insensitively, so the store must too or
	// the same image would be stored twice and burn two of the sixteen slots.
	if !s.touch(strings.ToUpper(a.nt), base) {
		t.Fatal("touch() is case-sensitive; ALE_APP_ID comparison is not")
	}
}

// The kernel table is a fixed wfpMaxExactApps entries. Overflow must drop the LEAST recently seen, never the
// most recently used — otherwise an app in active use loses its bypass to one that ran once an hour ago.
func TestVerifiedAppStoreEvictsLeastRecentlySeenAtTheKernelCap(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	total := wfpMaxExactApps + 5
	for i := 0; i < total; i++ {
		// Older entries first, so the last wfpMaxExactApps added are the most recent.
		s.add(mkApp(string(rune('a'+i))+".exe", base.Add(time.Duration(i)*time.Minute)))
	}
	got := s.list()
	if len(got) != wfpMaxExactApps {
		t.Fatalf("list() returned %d entries, want the kernel cap %d", len(got), wfpMaxExactApps)
	}
	// The oldest five must be the ones gone.
	for i := 0; i < 5; i++ {
		stale := mkApp(string(rune('a'+i))+".exe", base).nt
		for _, g := range got {
			if strings.EqualFold(g, stale) {
				t.Fatalf("list() kept %s; the least recently seen entries must be evicted first", stale)
			}
		}
	}
}

// keep() is how a swapped binary loses its bypass at the re-verify boundary. It must drop exactly what the
// predicate rejects and retain the rest — a re-verify that cleared everything would reintroduce the
// evaporation bug on a five-minute cycle instead of a thirty-second one.
func TestVerifiedAppStoreKeepDropsOnlyRejectedEntries(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	keep := mkApp("good.exe", base)
	drop := mkApp("swapped.exe", base)
	s.add(keep)
	s.add(drop)

	s.keep(func(a verifiedApp) bool { return a.nt != drop.nt })

	got := s.list()
	if len(got) != 1 || !strings.EqualFold(got[0], keep.nt) {
		t.Fatalf("list() = %v, want only %s retained", got, keep.nt)
	}
}

// Adding an UNRELATED rule must not disturb entries that still satisfy the rules which did not change.
// Regression: the first implementation reset the whole store on any rule-set change, and the live test caught
// it immediately — a just-learned entry was pushed to the kernel and wiped 60 milliseconds later when an
// unrelated probe rule arrived in the same sync. Re-verification, not reset, is what a rule change calls for.
func TestVerifiedAppStoreSurvivesAnUnrelatedRuleChange(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	kept := mkApp("learned.exe", base)
	s.add(kept)

	// What the sweep now does on a rule change: keep whatever the NEW rule set still accepts. Here the entry
	// still matches, so it must survive; the old code discarded it purely because the rule LIST differed.
	s.keep(func(a verifiedApp) bool { return true })

	got := s.list()
	if len(got) != 1 || !strings.EqualFold(got[0], kept.nt) {
		t.Fatalf("list() = %v, want %s retained across an unrelated rule change", got, kept.nt)
	}

	// And the other direction: a rule genuinely removed must drop what no longer verifies.
	s.keep(func(a verifiedApp) bool { return false })
	if got := s.list(); len(got) != 0 {
		t.Fatalf("list() = %v, want empty once nothing verifies", got)
	}
}

// An entry added WHILE keep() is running must survive. keep() verifies outside the store lock (pred does
// Authenticode and can take seconds with a cold CRL), and the process-creation hold and learn-on-steer both
// add() from other goroutines during that window. The first implementation replaced the map with the
// survivors set, so a binary decided at process creation mid-sweep lost its entry moments after it reached
// the kernel — the same wipe as the rule-change reset, through a different door. Caught in review, not by
// TestVerifiedAppStoreKeepDropsOnlyRejectedEntries, which only covers the filtering.
func TestVerifiedAppStoreKeepDoesNotDiscardAConcurrentAdd(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	existing := mkApp("existing.exe", base)
	s.add(existing)

	// Added from another goroutine while pred is still deciding about the entries keep() snapshotted.
	arrived := mkApp("decided-at-creation.exe", base.Add(time.Second))
	var once sync.Once
	s.keep(func(a verifiedApp) bool {
		once.Do(func() {
			done := make(chan struct{})
			go func() { s.add(arrived); close(done) }()
			<-done
		})
		return true
	})

	got := s.list()
	found := false
	for _, g := range got {
		if strings.EqualFold(g, arrived.nt) {
			found = true
		}
	}
	if !found {
		t.Fatalf("list() = %v, want the entry added during keep() to survive (%s)", got, arrived.nt)
	}
	if len(got) != 2 {
		t.Fatalf("list() = %v, want both the pre-existing and the concurrently added entry", got)
	}
}

// list() must be stable for an unchanged set: the resolver compares it against the last pushed slice to decide
// whether to re-push the kernel policy, so unstable ordering would issue a pointless IOCTL on every tick.
func TestVerifiedAppStoreListIsStableForAnUnchangedSet(t *testing.T) {
	s := newVerifiedAppStore()
	base := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		s.add(mkApp(string(rune('a'+i))+".exe", base.Add(time.Duration(i)*time.Second)))
	}
	first := s.list()
	second := s.list()
	if !sameStrings(first, second) {
		t.Fatalf("list() is not stable: %v then %v", first, second)
	}
}

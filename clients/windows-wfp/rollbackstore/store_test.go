package rollbackstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFile is the source-package fixture: a file with some bytes in it.
func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestFileNameRejectsHostileVersions is the security-relevant test in this package. The version reaching
// FileName comes from a manifest or a registry value, so it is an input; if it can carry separators it can
// steer a stash write or a prune delete outside the store.
func TestFileNameRejectsHostileVersions(t *testing.T) {
	bad := []struct {
		name    string
		version string
	}{
		{"empty", ""},
		{"parent traversal posix", "../../etc/passwd"},
		{"parent traversal windows", `..\..\Windows\System32\x`},
		{"forward slash", "1.0/x"},
		{"backslash", `1.0\x`},
		{"absolute posix", "/etc/passwd"},
		{"drive absolute", `C:\x`},
		{"colon ads", "1.0:stream"},
		{"nul byte", "1.0\x00"},
		{"leading dot", ".hidden"},
		{"leading hyphen", "-flag"},
		{"space", "1.0 beta"},
		{"wildcard", "1.*"},
		{"too long", strings.Repeat("9", maxVersionLen+1)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := FileName(tc.version); err == nil {
				t.Fatalf("FileName(%q) = %q, want an error", tc.version, got)
			}
		})
	}
}

// TestFileNameAcceptsRealVersions guards the opposite failure: a validator so strict that the versions this
// product actually produces are refused would make every box unable to stash, which looks identical to
// "nobody implemented stashing".
func TestFileNameAcceptsRealVersions(t *testing.T) {
	good := []string{
		"0.1.0",
		"0.1.0+2e39256d.dirty", // the form this box reports today
		"1.2.3-rc1",
		"0.2.0_build7",
	}
	for _, v := range good {
		t.Run(v, func(t *testing.T) {
			name, err := FileName(v)
			if err != nil {
				t.Fatalf("FileName(%q) errored: %v", v, err)
			}
			if got := versionFromName(name, nameSuffix); got != v {
				t.Fatalf("round trip: versionFromName(%q) = %q, want %q", name, got, v)
			}
		})
	}
}

// TestStashThenLookup is the whole point of the package: what the installer put down, the updater can find.
func TestStashThenLookup(t *testing.T) {
	root := testStoreRoot(t)
	s := New(filepath.Join(root, "store"))
	src := writeFile(t, filepath.Join(root, "src", "agent.msi"), "MSI-BODY")

	stored, err := s.Stash(src, "0.1.0")
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	found, err := s.Lookup("0.1.0")
	if err != nil {
		t.Fatalf("Lookup after Stash: %v", err)
	}
	if found != stored {
		t.Fatalf("Lookup = %q, Stash = %q; they must agree", found, stored)
	}
	body, err := os.ReadFile(found)
	if err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if string(body) != "MSI-BODY" {
		t.Fatalf("stored body = %q, want %q", body, "MSI-BODY")
	}
	// No temp files may survive a successful stash — they would be indistinguishable from restore material to
	// anyone reading the directory, and they are not.
	ents, err := os.ReadDir(s.Root())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("store holds %d files (%v), want exactly 1", len(ents), names)
	}
}

// TestLookupMissingIsErrNoMaterial pins the sentinel. The caller (agentupdate) must be able to tell "this box
// has no rollback material, refuse the update and say why" apart from "the disk is broken".
func TestLookupMissingIsErrNoMaterial(t *testing.T) {
	s := New(filepath.Join(testStoreRoot(t), "store"))
	_, err := s.Lookup("9.9.9")
	if !errors.Is(err, ErrNoMaterial) {
		t.Fatalf("Lookup of absent version: err = %v, want ErrNoMaterial", err)
	}
}

// TestLookupTreatsEmptyFileAsAbsent is the torn-copy case. A name that promises a rollback with a body that
// cannot perform one is worse than nothing, because it converts a refusal into an unrecoverable update.
func TestLookupTreatsEmptyFileAsAbsent(t *testing.T) {
	s := New(testStoreRoot(t))
	p, err := s.Path("0.1.0")
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	writeFile(t, p, "")

	_, err = s.Lookup("0.1.0")
	if !errors.Is(err, ErrNoMaterial) {
		t.Fatalf("Lookup of empty file: err = %v, want ErrNoMaterial", err)
	}
	// And List must not offer it either.
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List returned %d entries for an empty file, want 0", len(got))
	}
}

// TestStashRefusesEmptySource stops the torn copy being created deliberately: storing a zero-byte source
// satisfies every later Lookup by name and fails only at the moment of an actual rollback.
func TestStashRefusesEmptySource(t *testing.T) {
	root := testStoreRoot(t)
	s := New(filepath.Join(root, "store"))
	src := writeFile(t, filepath.Join(root, "empty.msi"), "")

	if _, err := s.Stash(src, "0.1.0"); err == nil {
		t.Fatal("Stash of an empty source succeeded; it must refuse")
	}
	if _, err := s.Lookup("0.1.0"); !errors.Is(err, ErrNoMaterial) {
		t.Fatalf("after refused Stash, Lookup err = %v, want ErrNoMaterial", err)
	}
}

// TestStashIsIdempotentOnIdenticalBytes covers repair and re-run: re-stashing the same package must not
// rewrite it and must not fail.
func TestStashIsIdempotentOnIdenticalBytes(t *testing.T) {
	root := testStoreRoot(t)
	s := New(filepath.Join(root, "store"))
	src := writeFile(t, filepath.Join(root, "agent.msi"), "SAME-BYTES")

	first, err := s.Stash(src, "0.1.0")
	if err != nil {
		t.Fatalf("first Stash: %v", err)
	}
	before, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Backdate it, which is the case that matters: a package stored days ago being reinstalled by a ROLLBACK.
	// Without backdating, "before" and "after" can land in the same filesystem timestamp tick and the assertion
	// below would be testing the clock's granularity rather than the behaviour.
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(first, old, old); err != nil {
		t.Fatal(err)
	}
	if before, err = os.Stat(first); err != nil {
		t.Fatal(err)
	}
	same := writeFile(t, filepath.Join(root, "copy.msi"), "SAME-BYTES")
	second, err := s.Stash(same, "0.1.0")
	if err != nil {
		t.Fatalf("second Stash: %v", err)
	}
	if first != second {
		t.Fatalf("paths differ across idempotent stashes: %q vs %q", first, second)
	}
	after, err := os.Stat(second)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// ★ THE PROPERTY IS "NOT REWRITTEN", NOT "MTIME UNCHANGED" (2026-08-12). This used to compare mtimes,
	// which was a proxy — and the proxy became wrong when the identical-digest path started TOUCHING the file
	// on purpose (Prune keeps the newest by mtime, and a rollback reinstalls stored bytes, so without the touch
	// the version a device just went back to becomes the first one pruned). A rewrite goes temp-then-rename and
	// produces a new file, so file identity is the thing to assert.
	if !os.SameFile(before, after) {
		t.Fatal("identical bytes were rewritten; the cheap-repeat property is gone")
	}
	// And the touch itself: mtime must mean "when this package was last installed", or Prune throws away the
	// one package a rollback needs.
	if !after.ModTime().After(before.ModTime()) {
		t.Fatalf("re-stashing identical bytes did not refresh the mtime (%s -> %s): Prune reads this as \"last "+
			"installed\", so a rolled-back version would become the oldest entry and be pruned",
			before.ModTime(), after.ModTime())
	}
}

// TestDifferentBytesUnderOneVersionReplace is a correction to what this file used to assert, and the reason is
// a version string this product actually produces.
//
// The old test pinned "a different source under the same version must NOT replace what is stored: the version
// is the identity". That premise is false here: agentVersion() appends ".dirty" for a modified tree, so two
// different builds of one commit share a version string — the daily case on a development box. Keeping the
// first would mean a rollback installs bytes that were never the ones running, which is precisely what this
// store exists to prevent.
//
// Last install wins, because the last install is what is running.
func TestDifferentBytesUnderOneVersionReplace(t *testing.T) {
	root := testStoreRoot(t)
	s := New(filepath.Join(root, "store"))
	dirtyA := writeFile(t, filepath.Join(root, "a.msi"), "DIRTY-BUILD-A")
	dirtyB := writeFile(t, filepath.Join(root, "b.msi"), "DIRTY-BUILD-B")
	const version = "0.1.0+2e39256d.dirty"

	if _, err := s.Stash(dirtyA, version); err != nil {
		t.Fatalf("first Stash: %v", err)
	}
	stored, err := s.Stash(dirtyB, version)
	if err != nil {
		t.Fatalf("second Stash: %v", err)
	}
	body, err := os.ReadFile(stored)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "DIRTY-BUILD-B" {
		t.Fatalf("stored body = %q, want the most recently installed build; a rollback would restore bytes that were never running", body)
	}
	// And exactly one package for the version, not two.
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("store holds %d entries for one version, want 1", len(entries))
	}
}

// TestSameSizeDifferentBytesReplace guards the shortcut: sizes are compared first to avoid hashing tens of
// megabytes, so two builds that happen to be the same length must still be distinguished.
func TestSameSizeDifferentBytesReplace(t *testing.T) {
	root := testStoreRoot(t)
	s := New(filepath.Join(root, "store"))
	a := writeFile(t, filepath.Join(root, "a.msi"), "AAAAAAAA")
	b := writeFile(t, filepath.Join(root, "b.msi"), "BBBBBBBB")

	if _, err := s.Stash(a, "0.1.0"); err != nil {
		t.Fatalf("first Stash: %v", err)
	}
	stored, err := s.Stash(b, "0.1.0")
	if err != nil {
		t.Fatalf("second Stash: %v", err)
	}
	body, err := os.ReadFile(stored)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "BBBBBBBB" {
		t.Fatalf("stored body = %q; equal sizes were treated as equal contents", body)
	}
}

// TestStashRejectsHostileVersionBeforeTouchingDisk makes the validation load-bearing rather than decorative:
// nothing may be written anywhere when the version is refused.
func TestStashRejectsHostileVersionBeforeTouchingDisk(t *testing.T) {
	root := testStoreRoot(t)
	storeDir := filepath.Join(root, "store")
	s := New(storeDir)
	src := writeFile(t, filepath.Join(root, "agent.msi"), "MSI-BODY")

	if _, err := s.Stash(src, "../escaped"); err == nil {
		t.Fatal("Stash accepted a traversing version; it must refuse")
	}
	if _, err := os.Stat(filepath.Join(root, "escaped.msi")); err == nil {
		t.Fatal("a file was written outside the store root")
	}
	if _, err := os.Stat(storeDir); err == nil {
		t.Fatal("the store root was created despite the version being refused")
	}
}

// TestListIgnoresForeignFiles: a stray file in this directory is not restore material and must not be
// reported as any version.
func TestListIgnoresForeignFiles(t *testing.T) {
	s := New(testStoreRoot(t))
	writeFile(t, filepath.Join(s.Root(), "readme.txt"), "hello")
	writeFile(t, filepath.Join(s.Root(), "dsse-agent-0.1.0.msi.bak"), "x")
	writeFile(t, filepath.Join(s.Root(), "other-0.1.0.msi"), "x")
	writeFile(t, filepath.Join(s.Root(), "dsse-agent-0.1.0.msi"), "real")

	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Version != "0.1.0" {
		t.Fatalf("List = %+v, want exactly the 0.1.0 entry", got)
	}
}

// TestPruneProtectsTheRunningVersion is the case a plain last-modified rule gets wrong. On a box that has
// been stable for a long time the running version's package is the OLDEST, so age alone would delete the one
// package that is actually needed.
func TestPruneProtectsTheRunningVersion(t *testing.T) {
	s := New(testStoreRoot(t))
	// Written oldest-first, then stamped so the running version is unambiguously the oldest.
	versions := []string{"0.1.0", "0.2.0", "0.3.0", "0.4.0"}
	base := time.Now().Add(-96 * time.Hour)
	for i, v := range versions {
		p, err := s.Path(v)
		if err != nil {
			t.Fatalf("Path(%s): %v", v, err)
		}
		writeFile(t, p, "body-"+v)
		when := base.Add(time.Duration(i) * 24 * time.Hour)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	if err := s.Prune(2, "0.1.0"); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if _, err := s.Lookup("0.1.0"); err != nil {
		t.Fatalf("the protected running version was pruned: %v", err)
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		var names []string
		for _, e := range got {
			names = append(names, e.Version)
		}
		t.Fatalf("after Prune(2, \"0.1.0\") store holds %v, want 2 entries total", names)
	}
	// The survivors alongside the protected one must be the newest, not an arbitrary pair.
	if _, err := s.Lookup("0.4.0"); err != nil {
		t.Fatalf("newest version was pruned: %v", err)
	}
}

// TestPruneOnMissingRootIsNotAnError: a box that has never stashed anything is a normal state, and
// housekeeping must not fail an install over it.
func TestPruneOnMissingRootIsNotAnError(t *testing.T) {
	s := New(filepath.Join(testStoreRoot(t), "never-created"))
	if err := s.Prune(3); err != nil {
		t.Fatalf("Prune on a missing root: %v", err)
	}
}

// TestDefaultRootIsUnderProgramData pins the location decision. Beside the binaries would be wrong: that is
// what an upgrade rewrites and an uninstall removes, so the package would vanish exactly when needed.
func TestDefaultRootIsUnderProgramData(t *testing.T) {
	t.Setenv("ProgramData", filepath.Join("X:", "PD"))
	got := DefaultRoot()
	want := filepath.Join("X:", "PD", "DSSE", "rollback")
	if got != want {
		t.Fatalf("DefaultRoot = %q, want %q", got, want)
	}

	t.Setenv("ProgramData", "")
	if got := DefaultRoot(); got == "" {
		t.Fatal("DefaultRoot returned empty with ProgramData unset; callers must not have to handle that")
	}
}

// ★ TestTheMarkerDescribesTheBYTES, not the version, and this is the property the whole mechanism rests on.
//
// The check that admits a deliberate downgrade ships inside the package being installed, so "can this be rolled
// back to" is a fact about the stored bytes. Two builds of one commit share a version string (".dirty"), so a
// package that honours the mechanism can be replaced by one that does not, under the same name. If the marker
// outlived the bytes it described, the updater would launch a downgrade the incoming package refuses — the
// exact false-alarm the marker exists to prevent, produced by the marker.
func TestReplacingAStoredPackageClearsItsRollbackMarker(t *testing.T) {
	dir := testStoreRoot(t)
	s := New(dir)
	a := filepath.Join(dir, "a.msi")
	b := filepath.Join(dir, "b.msi")
	if err := os.WriteFile(a, []byte("build one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("build two, same version string"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stash(a, "1.0.0.dirty"); err != nil {
		t.Fatalf("stash a: %v", err)
	}
	if err := s.MarkAcceptsRollbackIntent("1.0.0.dirty"); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if ok, _ := s.AcceptsRollbackIntent("1.0.0.dirty"); !ok {
		t.Fatal("the marker was not read back after being written")
	}

	if _, err := s.Stash(b, "1.0.0.dirty"); err != nil { // different bytes, same version
		t.Fatalf("stash b: %v", err)
	}
	ok, err := s.AcceptsRollbackIntent("1.0.0.dirty")
	if err != nil {
		t.Fatalf("read marker after replace: %v", err)
	}
	if ok {
		t.Fatal("the marker survived the package it described — a rollback would now be launched against bytes " +
			"that never carried the mechanism")
	}
}

// Re-stashing IDENTICAL bytes is a no-op and must not throw away a true marker: a repair or a re-run of the
// installer is ordinary, and losing the marker would leave a box unable to roll back for no reason.
func TestRestashingTheSameBytesKeepsTheMarker(t *testing.T) {
	dir := testStoreRoot(t)
	s := New(dir)
	src := filepath.Join(dir, "same.msi")
	if err := os.WriteFile(src, []byte("identical"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stash(src, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAcceptsRollbackIntent("1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stash(src, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.AcceptsRollbackIntent("1.0.0"); err != nil || !ok {
		t.Fatalf("re-stashing identical bytes lost the marker (ok=%v err=%v)", ok, err)
	}
}

// A pruned package must not leave its marker behind: the next package stored for that version would inherit a
// claim written about a file that is gone.
func TestPruneRemovesTheMarkerWithThePackage(t *testing.T) {
	dir := testStoreRoot(t)
	s := New(dir)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		src := filepath.Join(dir, "src-"+v)
		if err := os.WriteFile(src, []byte("pkg "+v), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Stash(src, v); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkAcceptsRollbackIntent(v); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(src); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Prune(1, "2.0.0"); err != nil {
		t.Fatalf("prune: %v", err)
	}
	p, err := s.Path("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(IntentMarkerPath(p)); !os.IsNotExist(err) {
		t.Fatalf("the marker for the pruned version survived (%v) — it now describes a package that is gone", err)
	}
	if ok, err := s.AcceptsRollbackIntent("2.0.0"); err != nil || !ok {
		t.Fatalf("prune took the surviving version's marker too (ok=%v err=%v)", ok, err)
	}
}

// An unmarked package is a clean false, not an error: that is the ordinary state of every box that has not yet
// installed a build carrying the mechanism, and reporting it as a fault would send operators to look for one.
func TestAnUnmarkedPackageIsFalseNotAnError(t *testing.T) {
	dir := testStoreRoot(t)
	s := New(dir)
	src := filepath.Join(dir, "old.msi")
	if err := os.WriteFile(src, []byte("a package from before the mechanism"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stash(src, "0.9.0"); err != nil {
		t.Fatal(err)
	}
	ok, err := s.AcceptsRollbackIntent("0.9.0")
	if err != nil {
		t.Fatalf("an unmarked package reported an error: %v", err)
	}
	if ok {
		t.Fatal("a package nobody marked claimed to accept a declared rollback")
	}
}

// TestARolledBackVersionSurvivesTheNextTwoUpdates reproduces the state the lab MAC was found in, on this
// store's own rules.
//
// 0.2.4 → 0.2.5 → 0.2.6, then a ROLLBACK to 0.2.4, then 0.2.7. The rollback reinstalls stored bytes, so it
// lands on Stash's identical-digest path — and before the touch, 0.2.4 kept its original mtime, became the
// oldest entry, and was pruned by the next update. The device then reported that a rollback was possible and
// held no package for the version it named.
//
// Two independent defences, so both are exercised SEPARATELY: with only the version just installed protected,
// the touch is what saves 0.2.4; naming it in protect saves it regardless. A single case passing proves only
// that at least one of them works, which is how a defence quietly stops existing.
func TestARolledBackVersionSurvivesTheNextTwoUpdates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		protect []string
	}{
		{"the touch alone", []string{"0.2.7"}},
		{"and naming the rollback target", []string{"0.2.7", "0.2.4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testStoreRoot(t)
			s := New(filepath.Join(root, "store"))
			src := func(v string) string { return writeFile(t, filepath.Join(root, "pkg-"+v+".msi"), "body-"+v) }

			base := time.Now().Add(-96 * time.Hour)
			for i, v := range []string{"0.2.4", "0.2.5", "0.2.6"} {
				if _, err := s.Stash(src(v), v); err != nil {
					t.Fatalf("stash %s: %v", v, err)
				}
				p, _ := s.Path(v)
				when := base.Add(time.Duration(i) * time.Hour)
				if err := os.Chtimes(p, when, when); err != nil {
					t.Fatal(err)
				}
				if err := s.Prune(3, v); err != nil {
					t.Fatalf("prune after %s: %v", v, err)
				}
			}

			// The rollback: the same bytes for 0.2.4 are handed to Stash again.
			if _, err := s.Stash(src("0.2.4"), "0.2.4"); err != nil {
				t.Fatalf("rollback stash: %v", err)
			}
			if err := s.Prune(3, "0.2.4"); err != nil {
				t.Fatalf("prune after the rollback: %v", err)
			}

			// And then the next update.
			if _, err := s.Stash(src("0.2.7"), "0.2.7"); err != nil {
				t.Fatalf("stash 0.2.7: %v", err)
			}
			if err := s.Prune(3, tc.protect...); err != nil {
				t.Fatalf("prune after 0.2.7: %v", err)
			}

			if _, err := s.Lookup("0.2.4"); err != nil {
				got, _ := s.List()
				var have []string
				for _, e := range got {
					have = append(have, e.Version)
				}
				t.Fatalf("the version a rollback would install was pruned (%v): the store holds %v", err, have)
			}
		})
	}
}

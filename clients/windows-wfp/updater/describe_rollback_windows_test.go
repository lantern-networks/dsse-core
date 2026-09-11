//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// storeHolding builds a rollback store in a temp dir with a package stashed for each version.
func storeHolding(t *testing.T, versions ...string) *rollbackstore.Store {
	t.Helper()
	src := filepath.Join(t.TempDir(), "pkg.msi")
	if err := os.WriteFile(src, []byte("not a real msi, but not empty either"), 0o644); err != nil {
		t.Fatalf("write source package: %v", err)
	}
	s := rollbackstore.New(t.TempDir())
	for _, v := range versions {
		if _, err := s.Stash(src, v); err != nil {
			t.Fatalf("stash %s: %v", v, err)
		}
	}
	return s
}

// ★ --status must name what this box HOLDS, in every branch — especially the ones that refuse.
//
// Measured on win-dev-1 2026-08-11: a box holding 0.1.0 and 0.2.0, upgraded by an operator running msiexec
// instead of by the service, printed "nothing — this box has never recorded a version to come back from" and
// stopped. Each word true, the whole line read as "there is no restore material here", and
// `--rollback-to 0.1.0+37949d7d.dirty` would have worked. The journal answers what the device DID; only the
// store bounds what --rollback-to CAN do, and the flag's help already promised --status would list it.
//
// The macOS line prints the inventory in all four branches. This one had drifted — in the direction that reads
// as an empty store — so the assertion is on the property, not on one branch.
func TestStatusNamesTheHeldPackagesEvenWhenItRefuses(t *testing.T) {
	const a, b = "0.1.0+abc.dirty", "0.2.0+abc.dirty"
	u := &updater{store: storeHolding(t, a, b)}

	cases := []struct {
		name string
		j    *agentupdate.Journal
	}{
		// The measured case: an operator-driven upgrade leaves no from_version, so --rollback has no target
		// while the store is full.
		{"no recorded from_version", &agentupdate.Journal{}},
		// The last attempt was itself a rollback: from_version is the build already abandoned.
		{"last attempt was a rollback", &agentupdate.Journal{
			AttemptKind: agentupdate.KindRollback, TargetVersion: a, FromVersion: b}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := describeRollback(u, tc.j)
			for _, v := range []string{a, b} {
				if !strings.Contains(line, v) {
					t.Errorf("the status line does not name the held version %s — an operator reading it "+
						"concludes this box has no restore material, while --rollback-to %s would work:\n  %s",
						v, v, line)
				}
			}
			if !strings.Contains(line, "--rollback-to") {
				t.Errorf("the status line refuses without naming the flag that would succeed:\n  %s", line)
			}
		})
	}
}

// An unreadable store must not be reported in the words of an empty one: they are the same sentence to a
// reader and opposite facts to whoever has to repair it.
func TestStatusDistinguishesAnUnreadableStoreFromAnEmptyOne(t *testing.T) {
	empty := describeRollback(&updater{store: rollbackstore.New(t.TempDir())}, &agentupdate.Journal{})
	if !strings.Contains(empty, "none stored") {
		t.Errorf("an empty store is not described as empty:\n  %s", empty)
	}

	// A root Windows cannot even parse. Deliberately NOT "a file where the directory should be", which was the
	// first attempt: Windows answers that with ERROR_PATH_NOT_FOUND, os.IsNotExist is true, and List correctly
	// reports it as "holds nothing" — so it never reaches the branch under test.
	line := describeRollback(&updater{store: rollbackstore.New(filepath.Join(t.TempDir(), `roll|back`))},
		&agentupdate.Journal{})
	if strings.Contains(line, "none stored") || !strings.Contains(line, "could not be listed") {
		t.Errorf("a store that could not be read is reported as an empty one:\n  %s", line)
	}
}

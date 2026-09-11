package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ A REPAIR THAT REPORTS A FILE MUST HAVE WRITTEN IT (2026-08-31, measured on a live deployment).
//
// repairDerivedFiles reused the install-time writers, each of which returns early when the file already
// exists, so on a running deployment — where every one of them exists — it rewrote nothing and printed the
// names of all of them. A fix in the installer could not reach a deployment by any route, and the operator was
// told it had.
func TestARepairRewritesAnExistingGeneratedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy-edge.cfg")
	stale := []byte("# written by an older installer\n")
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}

	// An INSTALL leaves it alone. That guard is not the defect and must survive.
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("agents.example.test")); err != nil {
		t.Fatalf("install-time write: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(stale) {
		t.Fatal("an install overwrote a file that was already there — an operator's edits must survive a second run")
	}

	// A REPAIR rewrites it, keeps the previous content beside it, and says so.
	regeneratingDerivedFiles = true
	derivedFileOutcomes = nil
	defer func() { regeneratingDerivedFiles = false; derivedFileOutcomes = nil }()
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("agents.example.test")); err != nil {
		t.Fatalf("repair-time write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == string(stale) {
		t.Fatal("the repair left the stale file in place — an installer fix cannot reach a running deployment")
	}
	if !strings.Contains(string(got), "resolve-prefer ipv4") {
		t.Error("the repaired door does not carry the fix the current installer generates")
	}

	// The previous content is recoverable by name, and the outcome list says the file changed.
	entries, _ := os.ReadDir(dir)
	backup := ""
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "haproxy-edge.cfg.before-repair-") {
			backup = filepath.Join(dir, e.Name())
		}
	}
	if backup == "" {
		t.Fatal("the repair overwrote a file without keeping what was there")
	}
	if kept, _ := os.ReadFile(backup); string(kept) != string(stale) {
		t.Error("the kept copy is not what the file held before the repair")
	}
	if len(derivedFileOutcomes) == 0 || !derivedFileOutcomes[0].changed {
		t.Error("the repair rewrote the file and did not record it as changed, which is what the report prints")
	}
}

// ★★★ A REPAIR MUST WRITE THROUGH THE FILE, AND SAY HOW TO PUT THE BACKUP BACK (2026-08-31, measured while
// recovering a region's door by hand).
//
// These generated files are bind-mounted into their containers ONE FILE AT A TIME, so a container is attached
// to the file's INODE and not to its path. Two consequences, and both cost real time:
//
//   - The repair must overwrite the existing file, never write a new one and rename it into place. A rename
//     gives the path a fresh inode; the running container goes on reading the file that no longer has a name,
//     and restarting it does not help, because there is nothing new at the inode it holds.
//   - The operator is handed the previous content by NAME, and the obvious way to put a file back is `mv`.
//     That is the same trap from the other side: the host then shows the restored config and the container
//     serves the repaired one. Measured on gate-nagoya — the door read as restored for fifteen minutes while
//     it was still routing to a dead end, and every host-side check agreed with the wrong answer.
func TestARepairKeepsTheInodeAndSaysHowToPutTheBackupBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "haproxy-edge.cfg")
	if err := os.WriteFile(path, []byte("# older\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	regeneratingDerivedFiles = true
	derivedFileOutcomes = nil
	defer func() { regeneratingDerivedFiles = false; derivedFileOutcomes = nil }()
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("agents.example.test")); err != nil {
		t.Fatalf("repair-time write: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("the repair replaced the file instead of writing through it — a container bind-mounted to the " +
			"old inode would go on serving the unrepaired config, and a restart would not fix it")
	}

	// What the operator is actually told. Captured, not asserted about a comment: a check satisfied by the
	// prose beside the code is not a check.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	reportDerivedFiles()
	w.Close()
	os.Stdout = stdout
	out, _ := io.ReadAll(r)

	said := string(out)
	if !strings.Contains(said, "cat ") || !strings.Contains(said, "> "+path) {
		t.Errorf("the repair names a backup without saying how to put it back through the same file.\n"+
			"An operator who reaches for `mv` restores it on the host and not in the container.\ngot:\n%s", said)
	}
	if strings.Contains(said, "mv ") {
		t.Errorf("the repair told an operator to `mv` a bind-mounted file back:\n%s", said)
	}
}

package updateplatform

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestStagedPathRejectsHostileVersions is the reason StagedPath borrows rollbackstore.FileName instead of
// formatting a name itself. The version comes from a signed manifest, so it is an input, and this path is the
// argument to a privileged install — a version that can carry separators aims msiexec at a file of someone
// else's choosing.
func TestStagedPathRejectsHostileVersions(t *testing.T) {
	bad := []string{
		"",
		"../../Windows/System32/x",
		`..\..\evil`,
		"/etc/passwd",
		`C:\x`,
		"1.0 beta",
		".hidden",
	}
	for _, v := range bad {
		t.Run(v, func(t *testing.T) {
			if got, err := StagedPath(v); err == nil {
				t.Fatalf("StagedPath(%q) = %q, want an error", v, got)
			}
		})
	}
}

// TestStagedPathAcceptsRealVersions guards the opposite failure: refusing the versions this product actually
// builds would stall every update while looking like a network problem.
func TestStagedPathAcceptsRealVersions(t *testing.T) {
	for _, v := range []string{"0.1.0", "0.1.0+2e39256d.dirty", "1.2.3-rc1"} {
		t.Run(v, func(t *testing.T) {
			got, err := StagedPath(v)
			if err != nil {
				t.Fatalf("StagedPath(%q): %v", v, err)
			}
			if !strings.Contains(got, v) {
				t.Fatalf("StagedPath(%q) = %q, which does not name the version", v, got)
			}
			if dir := filepath.Dir(got); dir != StagedRoot() {
				t.Fatalf("StagedPath(%q) landed in %q, want %q", v, dir, StagedRoot())
			}
		})
	}
}

// TestStagedRootIsNotTheRollbackStore pins the separation. A verified artifact waiting to be installed and a
// package kept so the box can go back are different things with different lifetimes; sharing one directory
// would let a prune delete an update that was staged and waiting for its window.
func TestStagedRootIsNotTheRollbackStore(t *testing.T) {
	t.Setenv("ProgramData", filepath.Join("X:", "PD"))
	staged, err := StagedPath("0.1.0")
	if err != nil {
		t.Fatalf("StagedPath: %v", err)
	}
	if strings.Contains(staged, filepath.Join("DSSE", "rollback")) {
		t.Fatalf("staged path %q is inside the rollback store", staged)
	}
	if want := filepath.Join("X:", "PD", "DSSE", "staged"); StagedRoot() != want {
		t.Fatalf("StagedRoot = %q, want %q", StagedRoot(), want)
	}
}

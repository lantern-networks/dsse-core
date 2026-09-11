package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootIsUnderProgramData(t *testing.T) {
	t.Setenv("ProgramData", filepath.Join("X:", "PD"))
	if got, want := Root(), filepath.Join("X:", "PD", "DSSE"); got != want {
		t.Fatalf("Root = %q, want %q", got, want)
	}
	// Not the install directory: an upgrade rewrites that and an uninstall removes it, so a rollback package
	// kept there would vanish during the install that needs it.
	if strings.Contains(Root(), "Program Files") {
		t.Fatalf("Root = %q, which an upgrade rewrites", Root())
	}
}

func TestEnsureCreatesAndReportsCreated(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	st, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !st.Created {
		t.Fatal("Ensure did not report creating the directory")
	}
	if st.PreExisting {
		t.Fatal("a directory Ensure created was reported as pre-existing")
	}
	if fi, err := os.Stat(st.Path); err != nil || !fi.IsDir() {
		t.Fatalf("stat %s: %v", st.Path, err)
	}
	// The ordinary case says something short, or nothing worth burying the interesting case under.
	if d := st.Describe(); strings.Contains(d, "NOT changed") {
		t.Fatalf("a freshly created directory produced the pre-existing warning: %q", d)
	}
}

// TestEnsureDoesNotTightenAnExistingDirectory is the restraint, pinned as behaviour.
//
// An operator may have opened it deliberately; more to the point, an installer that rewrites ACLs it did not
// create is how the util:PermissionEx attempt rolled installs back on this product before. Setting the DACL at
// CREATION is safe because nothing has had a chance to depend on it yet.
func TestEnsureDoesNotTightenAnExistingDirectory(t *testing.T) {
	pd := t.TempDir()
	t.Setenv("ProgramData", pd)
	existing := filepath.Join(pd, "DSSE")
	if err := os.MkdirAll(existing, 0o777); err != nil {
		t.Fatalf("pre-create: %v", err)
	}

	st, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure on an existing directory: %v", err)
	}
	if !st.PreExisting {
		t.Fatal("an existing directory was not reported as pre-existing")
	}
	if st.Created || st.Hardened {
		t.Fatalf("Ensure changed an existing directory: created=%v hardened=%v", st.Created, st.Hardened)
	}
}

// TestPreExistingIsLoudBecauseNothingElseWillSayIt: this is the case where the protection may simply be
// absent, and no other component looks. A silent state here is a box where the staged installer package can be
// replaced before it runs as SYSTEM, with nothing anywhere reporting it.
func TestPreExistingIsLoudBecauseNothingElseWillSayIt(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramData", root)
	if err := os.MkdirAll(filepath.Join(root, "DSSE"), 0o777); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	st, err := Ensure()
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !st.PreExisting {
		t.Fatal("Ensure did not notice the directory was already there")
	}
	if st.Describe() == "" {
		t.Fatal("a pre-existing directory produced no message; nothing else in the system will mention it")
	}
}

// ★ The three answers Describe has to give, and the reason the first one exists.
//
// PreExisting is true on every call after the very first — including on a directory this product created and
// hardened a minute earlier — so a warning keyed on it alone fires on every healthy box, every tick, forever.
// Nobody reads that, which would leave the genuinely wide-open directory exactly as invisible as it was before
// this package existed. The protection flag is what separates the case worth saying from the case that is
// simply normal.
func TestDescribeIsSilentOnlyWhenTheDirectoryIsActuallyProtected(t *testing.T) {
	protected := State{Path: `C:\ProgramData\DSSE`, PreExisting: true, Protected: true, ProtectionKnown: true}
	if got := protected.Describe(); got != "" {
		t.Fatalf("a protected directory must be silent, got %q", got)
	}

	// The measured failure: created by a bare MkdirAll, so it inherits %ProgramData%, which grants Users write.
	open := State{Path: `C:\ProgramData\DSSE`, PreExisting: true, ProtectionKnown: true}
	d := open.Describe()
	if d == "" {
		t.Fatal("an unprotected directory was silent — this is the whole case the package exists for")
	}
	// It has to say what the CONSEQUENCE is, not just that it declined to act: "permissions were not changed"
	// alone is a sentence an operator skips.
	for _, want := range []string{"SYSTEM", "not changed"} {
		if !strings.Contains(d, want) {
			t.Errorf("the warning does not carry %q: %q", want, d)
		}
	}

	// Unreadable is its own answer. Reporting it as protected would be the reassuring lie; reporting it as
	// unprotected would cry wolf on a box nobody can check.
	unknown := State{Path: `C:\ProgramData\DSSE`, PreExisting: true}
	u := unknown.Describe()
	if u == "" || !strings.Contains(u, "could not be read") {
		t.Fatalf("an unreadable DACL must say so, got %q", u)
	}
	if u == d {
		t.Fatal("unknown and unprotected produced the same sentence; they need different responses")
	}
}

// TestEnsureIsIdempotent: every component calls this before writing, so it runs constantly.
func TestEnsureIsIdempotent(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	first, err := Ensure()
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if !first.Created {
		t.Fatal("first Ensure did not create")
	}
	second, err := Ensure()
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if second.Created {
		t.Fatal("second Ensure created the directory again")
	}
	if !second.PreExisting {
		t.Fatal("second Ensure did not report the directory as already there")
	}
}

// TestAFileWhereTheDirectoryShouldBeIsAnError: silently proceeding would send every later write to a path
// that cannot hold them, and the first symptom would be an update that never stages.
func TestAFileWhereTheDirectoryShouldBeIsAnError(t *testing.T) {
	pd := t.TempDir()
	t.Setenv("ProgramData", pd)
	if err := os.WriteFile(filepath.Join(pd, "DSSE"), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	if _, err := Ensure(); err == nil {
		t.Fatal("Ensure accepted a file where the data directory should be")
	}
}

package updateplatform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var intentNow = time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)

func TestAnIntentIsBoundToOneVersionAndOneShortWindow(t *testing.T) {
	in := NewIntent("0.2.0+20260811013215", "0.2.1+20260811035942", "/store/dsse-agent-0.2.0.pkg", intentNow)

	if in.Schema != IntentSchema {
		t.Fatalf("schema = %q, want %q — a preinstall that cannot recognise it refuses the rollback", in.Schema, IntentSchema)
	}
	if in.ToVersion != "0.2.0+20260811013215" {
		t.Fatalf("to_version = %q: the authorisation must name the exact version being installed, or it authorises "+
			"any downgrade", in.ToVersion)
	}
	if in.Expired(intentNow) {
		t.Fatal("an authorisation must be usable the moment it is written")
	}
	if !in.Expired(intentNow.Add(IntentTTL)) {
		t.Fatalf("an authorisation must not outlive %s: one left behind by a rollback that never completed would "+
			"approve a downgrade later", IntentTTL)
	}
	// ★ The deadline the shell compares is the INTEGER one. A guard that had to parse an RFC3339 string in a
	// shell would be reading a UTC timestamp in local time.
	if in.ExpiresAtUnix != intentNow.Add(IntentTTL).Unix() {
		t.Fatalf("expires_at_unix = %d, want %d", in.ExpiresAtUnix, intentNow.Add(IntentTTL).Unix())
	}
}

func TestWriteIntentIsRootOnlyAndReadableBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback", "rollback_intent.json")
	want := NewIntent("0.2.0+1", "0.2.1+2", "/store/p.pkg", intentNow)
	if err := WriteIntent(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The preinstall refuses anything looser than this, so writing it looser would be a rollback that refuses
	// itself. Both halves of that pairing are asserted — here, and in the packaging test that reads the script.
	//
	// ★ Skipped where the HOST cannot represent a Unix mode at all. On Windows every file stats as 0666
	// regardless of what was requested, so this assertion failed on a machine where nothing was wrong and
	// blocked every push from it — the same cost sentinels.go's header describes, and the mirror of the plutil
	// gate that blocked macOS work from Windows.
	//
	// The skip probes the CAPABILITY rather than testing runtime.GOOS: a host that grows mode support starts
	// running it, and one that loses it stops, without anyone editing a platform list. It is not circular —
	// the probe writes its own file with the standard library, while the subject is WriteIntent.
	if hostKeepsUnixModes(t) {
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %04o, want 0600: this file talks a root installer out of its downgrade guard", perm)
		}
	} else {
		t.Log("SKIPPED the 0600 assertion: this host does not preserve Unix file modes, so it cannot check the " +
			"one property that keeps this authorisation from being writable by anyone. macOS runs it.")
	}

	got, err := ReadIntent(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != want {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
}

func TestAnIntentWithTheWrongSchemaIsNotUsable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback_intent.json")
	raw, _ := json.Marshal(map[string]any{"schema": "something.else", "to_version": "0.2.0"})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIntent(path); err == nil {
		t.Fatal("a file of a different schema must not be read as an authorisation")
	}
}

// ★ Holding the package and being able to install it are different facts. The preinstall that honours an
// authorisation ships INSIDE the package being installed, so everything stored before this mechanism existed
// refuses the downgrade — and the updater must say that before launching anything, not after.
func TestAPackageThatPredatesTheAuthorisationIsRefusedBeforeAnythingRuns(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "dsse-agent-0.2.0+20260811013215.pkg")
	if err := os.WriteFile(pkg, []byte("not really a package"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := PackageAcceptsIntent(pkg)
	if err == nil {
		t.Fatal("a stored package with no marker must not be treated as installable")
	}
	if !strings.Contains(err.Error(), "first one built with") {
		t.Errorf("the refusal must explain the bootstrap rather than look like a fault, got %q", err)
	}

	// The marker the installer writes beside it.
	if err := os.WriteFile(AcceptsIntentMarker(pkg), []byte(IntentSchema+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := PackageAcceptsIntent(pkg); err != nil {
		t.Fatalf("a package that states it honours %s must be installable: %v", IntentSchema, err)
	}

	// A marker for a different schema is not a pass: a declared capability nobody compares is the shape this
	// whole mechanism exists to end.
	if err := os.WriteFile(AcceptsIntentMarker(pkg), []byte("dsse_rollback_intent.v2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := PackageAcceptsIntent(pkg); err == nil {
		t.Fatal("a marker naming a different schema must be refused, not waved through")
	}
}

// hostKeepsUnixModes reports whether this filesystem stores the permission bits a chmod-style mode asks for.
// Windows does not: every file stats 0666. Probed with a file of the test's own so the answer is about the
// host and not about the code under test.
func hostKeepsUnixModes(t *testing.T) bool {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mode-probe")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("mode probe: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("mode probe stat: %v", err)
	}
	return st.Mode().Perm() == 0o600
}

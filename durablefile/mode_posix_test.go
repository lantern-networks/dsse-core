//go:build !windows

package durablefile

import (
	"os"
	"path/filepath"
	"testing"
)

// The mode is set BEFORE the file becomes visible under its real name; otherwise there is a window in which a
// file naming signing authority is readable by anyone.
//
// This is the Unix half. Windows has no permission bits — it has one read-only attribute, and reports every
// writable file as 0666 no matter what was asked for — so the same guarantee is asserted there in the terms
// that platform actually has (mode_windows_test.go). Split rather than deleted: the property is real on the
// platform the Edge runs on, and pinning it to bits that cannot exist elsewhere was what broke.
func TestTheModeIsInForceTheMomentTheFileAppears(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret.json")
	if err := Write(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode is %v, so the file was visible with the wrong permissions", perm)
	}
	// And a wider mode is honoured too: CreateTemp makes 0600, so a caller asking for a file another uid must
	// read would silently get an unreadable one if the chmod were skipped.
	q := filepath.Join(filepath.Dir(p), "public.json")
	if err := Write(q, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(q)
	if perm := st.Mode().Perm(); perm != 0o644 {
		t.Fatalf("mode is %v, want 0644 — CreateTemp's 0600 survived", perm)
	}
}

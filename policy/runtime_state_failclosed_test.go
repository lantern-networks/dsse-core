package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The path this closes: a runtime-state store that EXISTS but cannot be used must not degrade into "every
// security toggle at its OFF default", because the store is then rewritten with those defaults and the real
// posture is gone with no record. Absent is different and must stay an ordinary first boot.
func TestRuntimeStateFailsClosedWhenTheStoreIsUnusable(t *testing.T) {
	t.Run("corrupt store refuses", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := NewStore(nil).SetRuntimeStatePath(p)
		if err == nil {
			t.Fatal("a corrupt runtime-state store was accepted — the Edge would boot with every security toggle OFF and persist that")
		}
		if !strings.Contains(err.Error(), "unparseable") {
			t.Fatalf("error must say what is wrong, got: %v", err)
		}
	})

	t.Run("unreadable store refuses", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(p, []byte("{}"), 0o000); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			t.Skip("running as root: permissions cannot make a file unreadable")
		}
		// Same reason, different platform: Windows has no POSIX permission bits, so the 0o000 above does not
		// make the file unreadable and there is nothing for the guard to refuse. (Geteuid returns -1 there, so
		// the root check above does not cover it.) The guard itself is real and holds on Linux, where it runs.
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission bits are not meaningful on Windows")
		}
		if err := NewStore(nil).SetRuntimeStatePath(p); err == nil {
			t.Fatal("an unreadable runtime-state store was accepted")
		}
	})

	t.Run("absent store is a normal first boot", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "does-not-exist.json")
		if err := NewStore(nil).SetRuntimeStatePath(p); err != nil {
			t.Fatalf("an absent store must not be an error (first boot): %v", err)
		}
	})
}

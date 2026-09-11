//go:build darwin

package updateplatform

import (
	"os"
	"path/filepath"
	"testing"
)

// ★ THE WIRING, not just the helper. The first version of this test built a store directly and passed while
// Platform.store() still constructed a Windows one — a negative test that could not fail for the reason it
// named, which is the third time that shape has appeared in this work.
//
// Build-tagged because it asserts a darwin-only construction. The DECISION it protects (which extension) lives
// in the tag-free file and is tested there too; this checks that the platform actually goes through it.
func TestThePlatformsStoreFindsWhatTheMacInstallerWrites(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DSSE_TEST_ROLLBACK_ROOT", root) // unused by production code; documents intent for the reader

	const version = "0.1.0+20260810020647"
	// Exactly what the built package's postinstall produced on 2026-08-10.
	const writtenByPostinstall = "dsse-agent-0.1.0+20260810020647.pkg"

	store := DefaultRollbackStore()
	if got := filepath.Ext(mustPath(t, store, version)); got != ".pkg" {
		t.Fatalf("the platform's store looks for %q files; the macOS installer writes .pkg", got)
	}
	if base := filepath.Base(mustPath(t, store, version)); base != writtenByPostinstall {
		t.Fatalf("the store looks for %q, the installer wrote %q", base, writtenByPostinstall)
	}

	// And through the Platform itself, which is the wiring the mutation broke.
	p := &Platform{}
	if base := filepath.Base(mustPath(t, p.store(), version)); base != writtenByPostinstall {
		t.Fatalf("Platform.store() looks for %q, the installer wrote %q", base, writtenByPostinstall)
	}
	_ = os.Remove(root)
}

func mustPath(t *testing.T, s interface{ Path(string) (string, error) }, version string) string {
	t.Helper()
	p, err := s.Path(version)
	if err != nil {
		t.Fatalf("Path(%q): %v", version, err)
	}
	return p
}

//go:build windows

package rollbackstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testStoreRoot is a fixture root that can actually satisfy the guarantee Stash enforces.
//
// ★ WHY NOT t.TempDir(). Stash verifies the store AND its whole
// ancestry — a parent whose children a non-administrator may delete is a parent that can hand the product a
// directory of someone else's making. On Windows t.TempDir() sits under %LOCALAPPDATA%\Temp, every level of
// which is owned by the user running the test, so it can never satisfy that by construction.
//
// The alternative was to exempt the product path when the root "looks like a test", which is how a regression
// in the one function that matters becomes untestable. So the FIXTURE is fixed instead: %WINDIR%\Temp is owned
// by SYSTEM and grants BUILTIN\Users only CreateFiles/AppendData — no delete, no delete-child — so a directory
// created there has an ancestry that passes, without touching %ProgramData%\DSSE or any real data.
func testStoreRoot(t *testing.T) string {
	t.Helper()
	base := filepath.Join(os.Getenv("SystemRoot"), "Temp")
	if base == "Temp" {
		t.Skip("SystemRoot is not set, so no administrator-owned temporary root is available")
	}
	dir, err := os.MkdirTemp(base, "dsse-rbs-")
	if err != nil {
		t.Skipf("create an administrator-owned fixture root under %s: %v", base, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// MkdirTemp creates it owned by the test process, and %WINDIR%Temp hands CREATOR OWNER full control down
	// to what it creates. Production makes this directory as SYSTEM with a protected DACL, so the fixture is
	// given the same shape: inheritance broken, SYSTEM and Administrators only, owned by Administrators.
	// Otherwise the fixture asserts who ran `go test` rather than the ACL.
	for _, args := range [][]string{
		{dir, "/inheritance:r"},
		{dir, "/grant", "*S-1-5-18:(OI)(CI)F"},
		{dir, "/grant", "*S-1-5-32-544:(OI)(CI)F"},
		{dir, "/setowner", "*S-1-5-32-544"},
	} {
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			t.Skipf("icacls %v: %v (%s)", args, err, strings.TrimSpace(string(out)))
		}
	}
	return dir
}

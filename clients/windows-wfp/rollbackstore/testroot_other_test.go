//go:build !windows

package rollbackstore

import "testing"

// testStoreRoot is an ordinary temporary directory everywhere else. The guarantee Stash enforces is a Windows
// DACL, and the portable build does not attempt to express it — see verifyStoreForWriting in protect_other.go.
func testStoreRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

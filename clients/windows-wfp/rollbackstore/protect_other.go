//go:build !windows

package rollbackstore

import (
	"fmt"
	"os"
)

// createProtected is the portable fallback: POSIX modes carry the intent, and the Windows-only DACL work in
// protect_windows.go is what actually closes the hole this exists for. 0o700 rather than 0o755 for the same
// reason the DACL grants nobody outside SYSTEM and Administrators — nothing in user mode needs an installer.
func createProtected(dir string) (preExisting bool, err error) {
	if fi, serr := os.Stat(dir); serr == nil {
		if !fi.IsDir() {
			return false, fmt.Errorf("rollbackstore: %s exists and is not a directory", dir)
		}
		return true, nil
	} else if !os.IsNotExist(serr) {
		return false, fmt.Errorf("rollbackstore: stat %s: %w", dir, serr)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("rollbackstore: create %s: %w", dir, err)
	}
	return false, nil
}

// verifyStore has no portable equivalent: the guarantee this checks is a Windows DACL, and there is no
// POSIX statement of "SYSTEM and Administrators only". Reporting that it cannot be shown rather than
// inventing a mode comparison keeps the caller honest — it marks the store unverified, which is true.
func verifyStore(dir string) error {
	return fmt.Errorf("%s: this platform cannot state who may write here", dir)
}

// VerifyStoreAndPackage has no portable equivalent, for the same reason verifyStore does not: the guarantee
// is a Windows DACL. Reporting that it cannot be established is the honest answer, and callers refuse on it.
func VerifyStoreAndPackage(dir, pkg string) error {
	return fmt.Errorf("%s: this platform cannot state who may write here", dir)
}

// verifyStoreForWriting PERMITS on this platform, and that is a documented gap rather than an opinion.
//
// The guarantee Stash enforces on Windows is a DACL: owner, protected flag, per-ACE rights, ancestry. POSIX
// has an analogous statement — root-owned and not group- or world-writable at every level — but it is not
// implemented here, and macOS uses this package for its .pkg store. Returning an error would therefore not
// harden that lane; it would stop it storing rollback material at all, which is the failure this package
// exists to prevent, arrived at from the other direction.
//
// So this returns nil and the gap is stated where the other lane will read it. Nothing on Windows depends on
// it: protect_windows.go is what closes the hole there.
func verifyStoreForWriting(string) error { return nil }

// Shared macOS storage keeps its existing POSIX behavior. These hooks do not claim Windows ACL validation.
func prepareStoreForWriting(string) error                { return nil }
func verifyStoredPackageForWriting(string, string) error { return nil }

// claimStoredPackage is a no-op off Windows: ownership there is the POSIX uid, which this package does not
// manage, and the guarantee it supports is the Windows DACL one.
func claimStoredPackage(string) error { return nil }

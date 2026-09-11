//go:build !windows

package datadir

// harden is a no-op off Windows.
//
// The DACL this package exists to set is a Windows concept, and every consumer of this directory —
// the steering agent, the updater, the rollback store — is Windows-only. This file exists so the DECISIONS in
// datadir.go (set on create, never silently tighten, report what was found) compile and test on any host,
// which is the same split every other portable/OS-specific pair in this tree uses.
//
// It returns nil rather than an error deliberately: an error would make Ensure fail on a developer's Linux
// box for a protection that has no meaning there, and Ensure's error means "this directory is not safe to
// write an installer package into", which would then be a lie.
func harden(string) error { return nil }

// daclIsProtected has no meaning off Windows, and says so by reporting the answer as unknown rather than as
// "protected". A false "protected" here would make the portable tests assert the reassuring case on a host
// where nothing was ever checked.
func daclIsProtected(string) (protected bool, known bool) { return false, false }

// MakePublicReadable is the portable no-op: POSIX modes already make these files world-readable, and the
// Windows-only inheritance problem this closes does not exist here.
func MakePublicReadable(string) error { return nil }

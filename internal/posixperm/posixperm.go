// Package posixperm answers one question a test cannot answer for itself: does the file mode this machine
// reports mean anything?
//
// ★★★ WHY IT EXISTS (2026-08-31, after the fifth Windows-only red in two days). This product asserts POSIX
// permissions in nine test files — a private key travels 0600, a connector's identity directory is 0700, a
// journal is not group-readable. Every one of those assertions is correct and worth keeping on the machines
// this software runs on, and NONE of them can hold on Windows: there are no POSIX mode bits there, so
// os.WriteFile(path, data, 0o600) produces a file Stat reports as 0666, and MkdirAll(dir, 0o700) a directory
// reported as 0777.
//
// The consequence is not a harmless red. One developer machine fails a check that passes on every CI runner,
// for a reason that has nothing to do with the code — and a box that is permanently red stops being able to
// report a real break. That has now happened five times in two days here, three of them this shape.
//
// ★ IT IS A SKIP, NOT A RELAXATION. The property is genuinely unverified on Windows, and saying so is the
// honest report. Delivering it there means an ACL, which is a different mechanism and a different assertion;
// when something on Windows needs that guarantee, it needs its own test, not this one weakened.
package posixperm

import "runtime"

// Meaningful reports whether the running OS implements the POSIX permission bits that os.FileMode.Perm()
// returns. False on Windows, where Perm() reports a constant unrelated to what was asked for.
func Meaningful() bool { return runtime.GOOS != "windows" }

// SkipReason is the sentence a test prints when it skips, so a reader of the log knows the property was not
// checked rather than assuming it passed.
const SkipReason = "POSIX permission bits do not exist on this OS: os.FileMode.Perm() reports a constant " +
	"here, so this assertion would test the operating system rather than this code. The guarantee is " +
	"unverified on this platform — delivering it here means an ACL, which needs its own test."

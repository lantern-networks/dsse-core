//go:build !windows

package main

import (
	"fmt"
	"os"
)

// ★★★ WHY THIS FILE EXISTS (2026-08-24). Every source file in this package is behind //go:build windows,
// which is correct — it drives the Windows Filtering Platform and there is nothing here that could run
// elsewhere. The consequence was that on any other host `go build ./...` failed with
//
//	runtime.main_main·f: function main is undeclared in the main package
//
// That is the first command a stranger runs after cloning, and it failed on macOS and Linux for four
// packages. It reads as a broken repository rather than as "these four are for Windows".
//
// ★ THE POINT IS THE MESSAGE, NOT THE BUILD. A build tag alone would make the error go away and leave
// somebody holding a binary that exits silently; this one says what it is and refuses with a non-zero
// status, so a script that runs it on the wrong platform stops rather than continuing as if it had worked.
//
// Nothing about the Windows build changes: this file is excluded there, and the real main() in
// main_windows.go is untouched.
//
// ★ CONFIRMED BYTE-IDENTICAL ON WINDOWS (2026-08-24, win-dev-1). The same commit built with and without this
// file, on a real Windows host with go1.26.4 windows/amd64, produced the SAME SHA256 for all four binaries —
// not "the same size" or "behaves the same", the same output.
//
// ★★ REPRODUCING IT NEEDS -buildvcs=false. Removing the file makes the tree dirty, and Go stamps
// vcs.modified=true into the binary, so without that flag the comparison shows a difference that has nothing
// to do with this change. Whoever checks this next would spend the time chasing a problem that is not there.
func main() {
	fmt.Fprintln(os.Stderr, "updater is a Windows component: it drives the Windows Filtering Platform and has no behaviour on "+
		"this platform. Build it with GOOS=windows.")
	os.Exit(1)
}

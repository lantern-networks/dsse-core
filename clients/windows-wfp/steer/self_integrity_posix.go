//go:build !windows

package main

import "os"

// probeDirectoryWritability — the POSIX answer: three permission bits, which is the whole question here.
//
// This is also the path the tests take, because this logic is developed on a Mac and the fixtures are stat
// results. The Windows half asks a different question entirely (see self_integrity_windows.go); it is not a
// port of this one, because the bits it would read are synthesised and mean nothing.
func probeDirectoryWritability(dir string, info os.FileInfo, report *selfIntegrityReport) error {
	mode := info.Mode().Perm()
	report.WorldWritable = mode&0o002 != 0
	report.GroupWritable = mode&0o020 != 0
	return nil
}

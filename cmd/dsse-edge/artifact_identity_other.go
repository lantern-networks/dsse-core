//go:build !darwin && !linux

package main

import (
	"os"
	"time"
)

// fileIdentity — everywhere else. Zero, which the caller reads as "this platform cannot pin the file", so the
// cache falls back to size+mtime rather than pretending it has an identity it does not.
func fileIdentity(os.FileInfo) (inode, device uint64, ctime time.Time) { return 0, 0, time.Time{} }

//go:build linux

package main

import (
	"os"
	"syscall"
	"time"
)

// fileIdentity — the linux spelling. See artifact_identity_darwin.go for why this is per-platform.
func fileIdentity(fi os.FileInfo) (inode, device uint64, ctime time.Time) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, time.Time{}
	}
	return uint64(st.Ino), uint64(st.Dev), time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
}

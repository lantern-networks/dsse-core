//go:build darwin

package main

import (
	"os"
	"syscall"
	"time"
)

// fileIdentity is the triple a replacement cannot forge: inode, device, and the inode's change time. Zero on a
// platform that does not expose it, in which case the cache falls back to size+mtime and says so at the call
// site.
//
// ★ SPLIT PER PLATFORM BECAUSE IT HAD TO BE (2026-08-12). The ctime field is spelled Ctimespec on darwin and
// Ctim on linux, and the Edge RUNS ON LINUX — the single-file version compiled on the machine it was written
// on and on no machine it is deployed to. The local push gate builds this module for the host only, so nothing
// said a word until a lab redeploy failed.
func fileIdentity(fi os.FileInfo) (inode, device uint64, ctime time.Time) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, time.Time{}
	}
	return uint64(st.Ino), uint64(st.Dev), time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec)
}

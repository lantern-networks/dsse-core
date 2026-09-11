//go:build linux

package engine

import (
	"syscall"
	"time"
)

// waitFDs blocks until the origin socket is readable (always), writable (when alsoWrite), or the wake pipe is
// readable (new client data) — up to d. Drains the wake pipe so it re-arms.
//
// This is the real implementation used in production. It relies on the Linux shape of syscall.FdSet
// (Bits [16]int64) and the two-value syscall.Select signature (n, err). The broker only ever runs in its
// Linux container; wait_other.go provides a portable stub so the package still type-checks elsewhere.
func waitFDs(sock, wake int, alsoWrite bool, d time.Duration) {
	if sock < 0 {
		return
	}
	var r, wr syscall.FdSet
	fdSet(&r, sock)
	maxfd := sock
	if wake >= 0 {
		fdSet(&r, wake)
		if wake > maxfd {
			maxfd = wake
		}
	}
	if alsoWrite {
		fdSet(&wr, sock)
	}
	tv := syscall.NsecToTimeval(int64(d))
	if n, _ := syscall.Select(maxfd+1, &r, &wr, nil, &tv); n <= 0 {
		return
	}
	if wake >= 0 && fdIsSet(&r, wake) {
		var drain [256]byte
		_, _ = syscall.Read(wake, drain[:]) // clear the wake pipe (non-blocking: select said readable)
	}
}

func fdSet(p *syscall.FdSet, fd int) { p.Bits[fd/64] |= 1 << (uint(fd) % 64) }

func fdIsSet(p *syscall.FdSet, fd int) bool { return p.Bits[fd/64]&(1<<(uint(fd)%64)) != 0 }

//go:build darwin || linux || freebsd

package deploymentcrl

import (
	"os"
	"syscall"
)

func lockIssuerLedger(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX) }
func unlockIssuerLedger(file *os.File)     { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }

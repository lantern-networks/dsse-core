//go:build windows

// pending_windows.go — persisting "the new driver is on disk but the kernel still has the old one".
//
// That state is the honest outcome when a loaded driver cannot be unloaded, and it must not be reported as
// success — reporting it as success is the defect this whole change exists to fix, one layer down. It also
// must not be reported only to a console that nobody is watching, since the install runs from an MSI custom
// action in session 0.
//
// It lives under the driver service's OWN Parameters key, so it is removed with the service and inherits the
// Services ACL (SYSTEM/Administrators write) rather than needing one of its own.
package main

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

var procGetTickCount64 = syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")

func tickCount64() uint64 {
	r, _, _ := procGetTickCount64.Call()
	return uint64(r)
}

func pendingKeyPath(serviceName string) string {
	return `SYSTEM\CurrentControlSet\Services\` + serviceName + `\Parameters`
}

// bootID identifies the current boot, so a pending note can be told apart from one left over from before a
// restart. Derived from the boot instant (now minus uptime) rather than a counter, because it has to survive
// this process exiting and be comparable across runs.
//
// Rounded to the minute: GetTickCount64 has coarse resolution and the arithmetic drifts by a few milliseconds
// between calls, which would otherwise make every run look like a different boot and clear notes that are
// still valid.
func bootID() int64 {
	uptime := time.Duration(tickCount64()) * time.Millisecond
	return time.Now().Add(-uptime).Unix() / 60
}

// recordPendingReboot notes that digest is on disk and NOT loaded. Best-effort: failing to write the note must
// not turn a reboot-required install into a failed one, and the printed line carries the same information.
func recordPendingReboot(serviceName, digest string) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, pendingKeyPath(serviceName), registry.SET_VALUE)
	if err != nil {
		fmt.Printf("driversvc: could not record the pending-reboot state for %s: %v (the message above is the only record)\n", serviceName, err)
		return
	}
	defer k.Close()
	_ = k.SetStringValue(pendingImageValueName, digest)
	_ = k.SetQWordValue(pendingBootValueName, uint64(bootID()))
}

// clearPendingReboot removes the note after an image has actually been loaded.
func clearPendingReboot(serviceName string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, pendingKeyPath(serviceName), registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(pendingImageValueName)
	_ = k.DeleteValue(pendingBootValueName)
}

// readPendingReboot returns the recorded note, if any.
func readPendingReboot(serviceName string) PendingReboot {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, pendingKeyPath(serviceName), registry.QUERY_VALUE)
	if err != nil {
		return PendingReboot{}
	}
	defer k.Close()
	digest, _, err := k.GetStringValue(pendingImageValueName)
	if err != nil {
		return PendingReboot{}
	}
	boot, _, _ := k.GetIntegerValue(pendingBootValueName)
	return PendingReboot{Digest: digest, SetAtBootID: int64(boot)}
}

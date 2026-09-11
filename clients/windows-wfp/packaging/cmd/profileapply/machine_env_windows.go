//go:build windows

package main

// machine_env_windows.go — set and unset machine-wide environment variables, the way Windows expects.
//
// Two things make this less trivial than writing a registry value, and both have bitten this project's
// equivalents before:
//
// ★ THE VALUE TYPE MATTERS. A path written as REG_SZ is taken literally; one written as REG_EXPAND_SZ has
// %VARIABLES% expanded when it is read. These paths contain none, so REG_SZ is correct and is what is used —
// but an existing value of the other type must be replaced rather than half-updated, which SetStringValue
// does by overwriting the type along with the data.
//
// ★ NOTHING SEES IT UNTIL SOMETHING BROADCASTS. The registry is the store of record, but a running process
// read its environment at startup and Explorer hands that copy to every process it launches. Without
// WM_SETTINGCHANGE, a new terminal opened from the taskbar still gets the old environment — so the change
// looks like it did not happen, and the next person concludes the variable does not work. The broadcast is
// what makes "start a new shell" the correct advice rather than "log out and back in".
//
// It still does not reach a process that is ALREADY running. Nothing can: that process holds a copy.

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const machineEnvKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// setMachineEnv sets a machine-wide environment variable, or deletes it when value is empty.
func setMachineEnv(name, value string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open the machine environment key (needs elevation): %w", err)
	}
	defer k.Close()

	if value == "" {
		if derr := k.DeleteValue(name); derr != nil && derr != registry.ErrNotExist {
			return derr
		}
	} else if serr := k.SetStringValue(name, value); serr != nil {
		return serr
	}
	broadcastEnvironmentChange()
	return nil
}

// broadcastEnvironmentChange tells the shell the environment moved, so a NEW process gets the new value.
//
// SendMessageTimeout rather than SendMessage: a hung top-level window would otherwise block an installer
// custom action indefinitely, and this is running unattended inside one. The result is deliberately ignored —
// a window that does not answer in two seconds is not a reason to fail a provision, and the registry value,
// which is the store of record, is already written.
func broadcastEnvironmentChange() {
	const (
		hwndBroadcast    = 0xFFFF
		wmSettingChange  = 0x001A
		smtoAbortIfHung  = 0x0002
		broadcastTimeout = 2000
	)
	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SendMessageTimeoutW")
	env, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	_, _, _ = proc.Call(
		uintptr(hwndBroadcast),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(env)),
		uintptr(smtoAbortIfHung),
		uintptr(broadcastTimeout),
		uintptr(unsafe.Pointer(&result)),
	)
}

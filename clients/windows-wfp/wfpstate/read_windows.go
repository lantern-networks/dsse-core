//go:build windows

// read_windows.go — the one syscall path that produces the bytes state.go decodes.
//
// It is here rather than in each caller because it was already written twice — once in the steer agent, once
// in the watchdog — and the updater would have been the third. The package comment for state.go gives the
// reason a shared decoder exists at all ("two hand-written copies of one C memory layout drift silently, with
// the symptom being a wrong 'armed' bit"), and the same argument covers the read: the oversized buffer, the
// device-missing-vs-device-silent split, and the treatment of a parse failure are decisions, not plumbing, and
// a caller that gets any of them wrong reports a healthy box as black-holed or the reverse.
package wfpstate

import "golang.org/x/sys/windows"

// DevicePath is the control device the callout driver exposes. It exists only between DriverEntry and unload,
// which is what makes its absence a definite answer rather than an error.
const DevicePath = `\\.\DsseWfp`

// ioctlGetStats is IOCTL_DSSE_WFP_GET_STATS: FILE_DEVICE_NETWORK (0x12), function 0x802, METHOD_BUFFERED,
// FILE_ANY_ACCESS. Must match the definition in driver/dsse_wfp.h.
const ioctlGetStats = (0x12 << 16) | (0x802 << 2)

// Reading is the result of asking the driver what it is doing, with the two failure modes kept apart.
//
// Present and Known are NOT interchangeable and collapsing them is the mistake this type exists to prevent.
// A device that is not there means no callout driver and therefore no redirect — a definite, safe answer. A
// device that is there but will not answer is a genuine unknown, and treating it as "not armed" would let a
// caller conclude a box is fine at exactly the moment it cannot see.
type Reading struct {
	State State
	// Present is false when the control device does not exist: no driver is loaded.
	Present bool
	// Known is false when the device exists but produced no usable answer — it would not open, the IOCTL
	// failed, or the reply was from a driver too old to carry the state block.
	Known bool
}

// Read opens the control device and asks for DSSE_STATS.
//
// A caller that wants a verdict rather than a reading should pass the result to VerifyDisarmed, which applies
// the fail-loud rule: an unverifiable disarm is not a disarm.
func Read() Reading {
	p, err := windows.UTF16PtrFromString(DevicePath)
	if err != nil {
		return Reading{}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			// Definite absence: the device only exists while the driver is loaded.
			return Reading{Present: false, Known: true}
		}
		// Present but unreachable — most often a permissions failure, which is a fault and not an answer.
		return Reading{Present: true, Known: false}
	}
	defer windows.CloseHandle(h)

	// Oversized on purpose: an output buffer smaller than the driver's struct returns STATUS_BUFFER_TOO_SMALL,
	// so a tight fit would blind every caller the next time a field is appended to DSSE_STATS.
	var buf [256]byte
	var ret uint32
	if err := windows.DeviceIoControl(h, ioctlGetStats, nil, 0, &buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return Reading{Present: true, Known: false}
	}
	st, perr := Parse(buf[:ret])
	if perr != nil {
		// A driver too old for the state block cannot say whether it is redirecting. That is an UNKNOWN, never
		// "not armed".
		return Reading{Present: true, Known: false}
	}
	return Reading{State: st, Present: true, Known: true}
}

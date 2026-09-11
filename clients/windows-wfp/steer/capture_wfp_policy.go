//go:build windows

// capture_wfp_policy.go — the driver<->userspace control-plane contract (see
// ). Userspace pushes the connect-time bypass policy (which apps/dests
// the callout must NOT redirect, and which local port to redirect the rest to) to the kernel driver via
// DeviceIoControl. The driver evaluates this table in its ALE_CONNECT_REDIRECT classify -- so the bypass
// decision is made at connect-time with race-free identity (the WFP analog of appBypassDecision, but
// fail-CLOSED is safe because the owner is always known mid-connect).
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/wfpstate"
)

// selfImageBypass returns the agent's own executable basename (lowercased, e.g. "dsse-steer.exe") for use as an
// always-bypass image-path substring in the WFP policy. Empty if the path can't be determined.
func selfImageBypass() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return strings.ToLower(filepath.Base(exe))
}

const (
	wfpDevicePath   = `\\.\DsseWfp`
	wfpMaxApps      = 16  // max bypass image-path substrings
	wfpMaxDests     = 32  // max bypass destination rules
	wfpAppSubLen    = 64  // bytes per lowercased ASCII image-path substring (NUL-terminated)
	wfpMaxExactApps = 16  // max verified exact-APP_ID entries (signature-verified bypass)
	wfpExactAppLen  = 260 // UTF-16 units per verified NT device path (incl. NUL), == DSSE_EXACT_APP_LEN
	wfpPolicyVer    = 2
)

// wfpDestRule is a never-redirect destination (race-free, no process lookup). Addr bytes are network order
// (as in the IP header); Port is native order (driver converts when matching the connection's port).
type wfpDestRule struct {
	Family uint32 // afInet / afInet6
	Addr   [16]byte
	Port   uint16 // native order
	_      uint16
}

// wfpPolicy is the fixed-layout policy blob handed to the driver. Keep byte-for-byte in lockstep with the
// driver's definition. Fixed-size arrays (vs variable length) keep the IOCTL marshalling trivial on both
// sides.
type wfpPolicy struct {
	Version   uint32
	LocalPort uint16 // proxy port the driver redirects steered flows to
	_         uint16
	NumApps   uint32
	NumDests  uint32
	Apps      [wfpMaxApps][wfpAppSubLen]byte
	Dests     [wfpMaxDests]wfpDestRule
	ProxyPid  uint32 // PID of THIS proxy process; the driver sets it as localRedirectTargetPID so the
	// framework completes the localhost connect-redirect (without it the connect fails ACCESS_DENIED).
	ObserveOnly uint32 // discovery/audit: non-zero => driver records would-be-steered flows (PID+dest)
	// and permits them direct (no redirect); drain via IOCTL_DSSE_GET_OBSERVATIONS. 0 = normal steering.
	NumExactApps uint32 // count of valid ExactApps entries
	// ExactApps are verified NT device paths (UTF-16, NUL-terminated) of processes whose Authenticode identity
	// userspace verified against a signature exclusion; the kernel bypasses a flow whose ALE_APP_ID matches one
	// EXACTLY (case-insensitive). This is how signature rules (subject:/thumbprint:/...) gain kernel-backend
	// enforcement — identity owned by userspace, enforced by exact APP_ID in the driver.
	ExactApps [wfpMaxExactApps][wfpExactAppLen]uint16
}

// buildWFPPolicy serialises the capture config into the driver policy blob (pure; unit-tested).
func buildWFPPolicy(cfg captureConfig) wfpPolicy {
	var p wfpPolicy
	p.Version = wfpPolicyVer
	p.LocalPort = cfg.localPort
	p.ProxyPid = uint32(os.Getpid()) // we are the local proxy that accepts the redirected connections
	// The effective bypass-app set: the static --bypass-app baseline until the server-signed steer-exclusion
	// sync merges a verified set on top. Reading it here means a re-push (apply) and a supervisor restart
	// both carry the latest exclusions to the kernel.
	apps := cfg.bypassApps
	if cfg.exclusions != nil {
		apps = cfg.exclusions.effective()
	}
	// The agent's own image is ALWAYS bypassed (added first so it survives even a full 16-app list): a fail-open
	// direct dial from the agent must not be redirected back into the terminator (infinite self-loop -> port
	// exhaustion). Empty in unit tests, so buildWFPPolicy stays deterministic there.
	if self := strings.ToLower(strings.TrimSpace(cfg.selfImage)); self != "" && !isSignatureRule(self) {
		b := []byte(self)
		if len(b) > wfpAppSubLen-1 {
			b = b[:wfpAppSubLen-1]
		}
		copy(p.Apps[p.NumApps][:], b)
		p.NumApps++
	}
	for _, sub := range apps {
		if p.NumApps >= wfpMaxApps {
			break
		}
		s := strings.ToLower(strings.TrimSpace(sub))
		if s == "" {
			continue
		}
		// Signature-based identifiers (publisher:/signed:) are NOT kernel-enforceable — the WFP callout
		// matches image-PATH substrings only. Skip them so they are never pushed as a literal substring
		// (which would never match); the app then stays steered (fail-closed). They ARE enforced on the
		// userspace windivert backend (appBypass.matchAppRule). See wfpSignatureRuleCount.
		if isSignatureRule(s) {
			continue
		}
		b := []byte(s)
		if len(b) > wfpAppSubLen-1 {
			b = b[:wfpAppSubLen-1]
		}
		copy(p.Apps[p.NumApps][:], b) // NUL-terminated by zero-value remainder
		p.NumApps++
	}
	for _, d := range cfg.effectiveDests() {
		if p.NumDests >= wfpMaxDests {
			break
		}
		var rule wfpDestRule
		if d.Addr().Is4() {
			rule.Family = afInet
			a4 := d.Addr().As4()
			copy(rule.Addr[:4], a4[:])
		} else {
			rule.Family = afInet6
			a16 := d.Addr().As16()
			copy(rule.Addr[:], a16[:])
		}
		rule.Port = d.Port() // native order; driver converts when matching
		p.Dests[p.NumDests] = rule
		p.NumDests++
	}
	// Verified exact-APP_ID bypass: NT device paths whose signer identity userspace verified against a signature
	// exclusion (subject:/thumbprint:/publisher:/signed:). The kernel matches the connecting flow's ALE_APP_ID
	// EXACTLY (case-insensitive). Populated by the app-id resolver loop; nil/empty otherwise (legacy behavior).
	if cfg.verifiedExactApps != nil {
		if ep := cfg.verifiedExactApps.Load(); ep != nil {
			for _, ntPath := range *ep {
				if p.NumExactApps >= wfpMaxExactApps {
					break
				}
				u16, err := syscall.UTF16FromString(ntPath)
				if err != nil || len(u16) > wfpExactAppLen {
					continue // contains a NUL, or too long to store WITH its terminator — skip (never truncate a path)
				}
				copy(p.ExactApps[p.NumExactApps][:], u16) // u16 includes the NUL; the array remainder stays zero
				p.NumExactApps++
			}
		}
	}
	return p
}

// CTL_CODE(DeviceType, Function, Method, Access) = (DeviceType<<16)|(Access<<14)|(Function<<2)|Method.
func wfpCtlCode(function uint32) uint32 {
	const (
		fileDeviceNetwork = 0x12
		methodBuffered    = 0
		fileAnyAccess     = 0
	)
	return (fileDeviceNetwork << 16) | (fileAnyAccess << 14) | (function << 2) | methodBuffered
}

var (
	ioctlWFPSetPolicy   = wfpCtlCode(0x800)
	ioctlWFPClearPolicy = wfpCtlCode(0x801)
	ioctlWFPGetStats    = wfpCtlCode(0x802) // read-only; health probe (W-3) AND the arming-state read
	ioctlWFPArmOwner    = wfpCtlCode(0x809) // nominate this handle as the redirect policy's owner
)

// wfpOwnerArm mirrors DSSE_OWNER_ARM in driver/dsse_wfp.h.
type wfpOwnerArm struct {
	Version      uint32
	DisarmOnExit uint32
}

const wfpOwnerArmVersion = 1

// armPolicyOwner nominates a NEWLY OPENED handle as the owner of the driver's redirect policy and returns it.
// The caller must hold the handle for as long as it is accepting redirected connections, and close it when it
// stops — including by dying, which is the whole point.
//
// The returned handle is not used for anything else. pushPolicy and removePolicy keep opening and closing
// their own short-lived handles, and they must: ownership has to be tied to one nominated handle rather than
// to any close, or every policy push would look like the owner leaving. The driver's process-hold owner
// (g_procWaitOwner) is arranged the same way for the same reason.
//
// disarmOnExit is the endpoint's INSTALL-TIME posture, not a runtime preference. Passing true says "if this
// agent dies, let the box reach the network unsteered"; passing false says "keep refusing connections", which
// is what a fail-closed installation asked for. This function does not decide which — see the caller.
func armPolicyOwner(disarmOnExit bool) (syscall.Handle, error) {
	h, err := openWFPDevice()
	if err != nil {
		return syscall.InvalidHandle, err
	}
	req := wfpOwnerArm{Version: wfpOwnerArmVersion}
	if disarmOnExit {
		req.DisarmOnExit = 1
	}
	var ret uint32
	if err := syscall.DeviceIoControl(h, ioctlWFPArmOwner,
		(*byte)(unsafe.Pointer(&req)), uint32(unsafe.Sizeof(req)), nil, 0, &ret, nil); err != nil {
		syscall.CloseHandle(h)
		return syscall.InvalidHandle, err
	}
	return h, nil
}

// driverAbsent reports whether opening \\.\DsseWfp failed because there is no such device — the driver is not
// installed or not loaded.
//
// This is NOT the same as "I could not tell". No driver means no callout, which means no redirect, which
// means nothing to recover: a box running the WinDivert backend, or one whose driver was already unloaded, is
// genuinely disarmed. Collapsing the two would make --mode recover report a problem on every machine that
// never had the WFP backend, and a recovery path that cries wolf is one operators learn to ignore.
func driverAbsent(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND)
}

// readDriverState asks the driver what it is doing right now. See wfp_driver_state.go for why the answer
// matters and why an unreadable driver is an error rather than "not armed".
func readDriverState() (wfpstate.State, error) {
	h, err := openWFPDevice()
	if err != nil {
		return wfpstate.State{}, err
	}
	defer syscall.CloseHandle(h)
	// Oversized on purpose, like the W-3 liveness probe: an output buffer smaller than the driver's struct
	// returns STATUS_BUFFER_TOO_SMALL, so a tight fit would break this read the next time a field is appended.
	var buf [256]byte
	var ret uint32
	if err := syscall.DeviceIoControl(h, ioctlWFPGetStats, nil, 0, &buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return wfpstate.State{}, err
	}
	return wfpstate.Parse(buf[:ret])
}

// removePolicyVerified clears the redirect policy and then CHECKS that the driver agrees it is cleared.
//
// removePolicy alone is best-effort by its own admission, and a best-effort disarm that quietly failed leaves
// the exact black hole the disarm exists to prevent — while the log line says it worked. Anything about to
// hand the machine to an installer, or about to exit, should use this and report what came back.
func removePolicyVerified() wfpstate.DisarmVerification {
	err := removePolicy()
	if err != nil && driverAbsent(err) {
		// No driver, no redirect. Genuinely disarmed, not merely unverifiable.
		return wfpstate.DisarmVerification{Verified: true}
	}
	state, rerr := readDriverState()
	if rerr != nil && driverAbsent(rerr) {
		return wfpstate.DisarmVerification{Verified: true}
	}
	v := wfpstate.VerifyDisarmed(state, rerr)
	if err != nil && !v.Verified {
		// The clear returned an error AND the driver still will not confirm it is clear. Report both: "the
		// IOCTL failed" and "the redirect is still in force" are different claims, and only the second one
		// means the box is down.
		v.Reason = "clear-policy failed (" + err.Error() + "); " + v.Reason
	}
	return v
}

func openWFPDevice() (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(wfpDevicePath)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
}

// pushPolicy sends the bypass/redirect policy to the kernel driver. Returns an error (device not found) if
// the callout driver is not installed/loaded -- which is how the WFP backend fails cleanly pre-P3.
func pushPolicy(cfg captureConfig) error {
	pol := buildWFPPolicy(cfg)
	h, err := openWFPDevice()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	var ret uint32
	return syscall.DeviceIoControl(h, ioctlWFPSetPolicy,
		(*byte)(unsafe.Pointer(&pol)), uint32(unsafe.Sizeof(pol)),
		nil, 0, &ret, nil)
}

// removePolicy tells the driver to stop redirecting (best-effort, on shutdown).
func removePolicy() error {
	h, err := openWFPDevice()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	var ret uint32
	return syscall.DeviceIoControl(h, ioctlWFPClearPolicy, nil, 0, nil, 0, &ret, nil)
}

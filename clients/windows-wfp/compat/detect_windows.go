//go:build windows

package compat

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Detect reads the machine's real compatibility facts from the registry. Every probe is best-effort: a missing
// key/value leaves the corresponding field at its zero value (safe: booleans default off, arch to Unknown),
// so detection never fails the install by itself — Evaluate decides.
func Detect() Facts {
	f := Facts{Arch: ArchUnknown}
	f.Arch = detectArch()
	f.SMode = detectSMode()
	f.SecureBoot = regDWORDIs1(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	f.HVCI = regDWORDIs1(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled")
	f.WindowsBuild, f.DisplayVersion = detectWindowsVersion()
	return f
}

// detectArch reads the NATIVE processor architecture. PROCESSOR_ARCHITECTURE in the system environment key
// reflects the native arch (unlike the per-process env var, which a WOW64 process sees as x86).
func detectArch() Arch {
	s := regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "PROCESSOR_ARCHITECTURE")
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "AMD64":
		return ArchAMD64
	case "ARM64":
		return ArchARM64
	case "X86":
		return ArchX86
	default:
		return ArchUnknown
	}
}

// detectSMode is a best-effort heuristic: S Mode sets a SKU code-integrity policy requirement. The authoritative
// check is the licensing API (SLGetWindowsInformationDWORD), but this registry signal is a reliable-enough gate
// input and needs no cgo. False negatives fail open (install proceeds) — acceptable since S Mode also blocks the
// install itself, so the user still gets a (less friendly) failure rather than a broken state.
func detectSMode() bool {
	return regDWORDIs1(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\CI\Policy`, "SkuPolicyRequired")
}

func detectWindowsVersion() (int, string) {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	build := 0
	if s := regString(registry.LOCAL_MACHINE, path, "CurrentBuildNumber"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			build = n
		}
	}
	return build, regString(registry.LOCAL_MACHINE, path, "DisplayVersion")
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

func regDWORDIs1(root registry.Key, path, name string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return false
	}
	return v == 1
}

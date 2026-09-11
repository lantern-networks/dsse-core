//go:build windows

// osuser_windows.go — resolve a flow's owning PID to the logged-in OS user (the per-flow "who"). WFP already
// captures the connect-time PID race-free; this takes it one step further: PID -> process token -> user SID ->
// account name. The steer-mux OPEN frame carries it to the Edge so traffic can be attributed to the PERSON
// (a shared workstation has many users), not just the enrolled device. Best-effort + fail-safe: any
// failure yields "" and the "u=" suffix is simply omitted (never a wrong/guessed user).

package main

import "golang.org/x/sys/windows"

func init() {
	osUserForPID = resolveOSUserForPID
	osAppForPID = resolveOSAppForPID
}

// resolveOSAppForPID returns the originating executable's base name (e.g. "chrome.exe"), the per-flow "what
// tool" signal. Fail-safe: unknown PID / lookup failure -> "" (the app suffix is then omitted, never guessed).
// The base name is cheap (one QueryFullProcessImageNameW) — a full signing-identity verification per flow would
// be too costly here; the base name is the stable identifier the handoff specifies as the practical fallback.
func resolveOSAppForPID(pid uint32) string {
	if pid == 0 {
		return ""
	}
	p, ok := processImagePath(pid)
	if !ok || p == "" {
		return ""
	}
	return baseName(p)
}

func resolveOSUserForPID(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()

	tu, err := tok.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return ""
	}
	sid := tu.User.Sid
	// Skip non-interactive principals at the source: SYSTEM (S-1-5-18) / LOCAL SERVICE (S-1-5-19) / NETWORK
	// SERVICE (S-1-5-20) are not a person, and their account names ("NT AUTHORITY\SYSTEM") contain a SPACE that
	// would split the space-separated OPEN metadata (u=/a=). Returning "" omits u= for these flows.
	if sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinLocalServiceSid) ||
		sid.IsWellKnown(windows.WinNetworkServiceSid) {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return ""
	}
	// Belt-and-suspenders for other service principals (e.g. NT SERVICE\*, virtual accounts) that the SID
	// well-known check does not cover: their domain is one of these authorities. Drop them too.
	switch domain {
	case "NT AUTHORITY", "NT SERVICE", "NT VIRTUAL MACHINE", "Window Manager", "Font Driver Host":
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

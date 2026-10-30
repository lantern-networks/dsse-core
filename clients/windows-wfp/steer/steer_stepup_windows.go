//go:build windows

package main

import (
	"fmt"
	neturl "net/url"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The agent runs as a LocalSystem Windows service in session 0. A plain spawn (exec.Command) would land the
// browser/toast in session 0 -- no user desktop and no per-user default-browser association -- so the user
// never sees the step-up portal. Authentication uses the WFP flow owner's session
// through WTSQueryUserToken + CreateProcessAsUserW, checking its SID again.
// Passive warnings and authentication both require the originating flow owner's session.
var (
	wtsapi32                    = syscall.NewLazyDLL("wtsapi32.dll")
	userenv                     = syscall.NewLazyDLL("userenv.dll")
	procWTSQueryUserToken       = wtsapi32.NewProc("WTSQueryUserToken")
	procWTSGetActiveConsole     = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procCreateProcessAsUserW    = advapi32.NewProc("CreateProcessAsUserW")
	procStepupCloseHandle       = kernel32.NewProc("CloseHandle")
	procCreateEnvironmentBlock  = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock = userenv.NewProc("DestroyEnvironmentBlock")
)

const (
	createNoWindow           = 0x08000000
	createUnicodeEnvironment = 0x00000400
	invalidSessionID         = 0xFFFFFFFF
)

// Callers without a verified flow owner cannot choose a desktop. Production uses
// defaultStepUpLauncherForOwner; there is no SYSTEM or embedded-WebView fallback.
func defaultStepUpLauncher(resource, portalURL string) {
	fmt.Printf("steer_stepup_requires_flow_owner\n")
}

// validatedStepUpURL performs command-line hygiene after the coordinator has
// checked the signed Portal list and request lifetime. It requires HTTPS and no whitespace, quotes, backslashes, or
// control characters that could break out of the quoted argument or the FileProtocolHandler invocation. Returns
// ("", false) otherwise so the caller refuses to launch it.
func validatedStepUpURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '`' || r == '\\' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return "", false
		}
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme != "https" {
		return "", false
	}
	if strings.TrimSpace(u.Host) == "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	return raw, true
}

// stepUpDestLabel derives a clean "host:port" for the window's --dest display from the step-up resource. The mux
// path's resource is the OPEN authority, which may carry NUL-separated "u="/"a=" metadata; truncate at the NUL
// and sanitize so only host:port-safe characters reach the child command line (injection guard).
func stepUpDestLabel(resource string) string {
	if i := strings.IndexByte(resource, 0); i >= 0 {
		resource = resource[:i]
	}
	return sanitizeResource(resource)
}

// stepUpToastScript pops a tray balloon (NotifyIcon) -- no external dependency, no app registration. The
// resource is substituted via the __DSSE_RESOURCE__ placeholder AFTER sanitization (sanitizeResource keeps
// only host:port-safe characters) so a destination value can never inject into the script.
const stepUpToastScript = `$ErrorActionPreference='SilentlyContinue';` +
	`Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;` +
	`$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Shield;` +
	`$n.BalloonTipIcon=[System.Windows.Forms.ToolTipIcon]::Warning;$n.BalloonTipTitle='Authentication required';` +
	`$n.BalloonTipText='Sign in to reach __DSSE_RESOURCE__. Your browser is opening the step-up portal; complete it, then retry.';` +
	`$n.Visible=$true;$n.ShowBalloonTip(8000);Start-Sleep -Seconds 9;$n.Dispose()`

// AUTH_RESULT is received only on the authenticated mux flow that raised the
// request. Show its outcome in that flow owner's desktop; never fall back to
// the active console or SYSTEM when the original session has disappeared.
func showStepUpResultForOwner(result string, owner stepUpOwner) {
	if owner.Session == 0 || owner.SID == "" || owner.LogonID == 0 {
		return
	}
	message := "This connection was not resumed. Reconnect from the original app."
	if result == "resumed" {
		message = "The authenticated connection resumed."
	} else if result != "not_resumed" {
		return
	}
	script := `$ErrorActionPreference='SilentlyContinue';` +
		`Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;` +
		`$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Shield;` +
		`$n.BalloonTipTitle='Lantern DSSE';$n.BalloonTipText='` + message + `';` +
		`$n.Visible=$true;$n.ShowBalloonTip(8000);Start-Sleep -Seconds 9;$n.Dispose()`
	command := fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "%s"`, script)
	if err := launchInSession(command, uintptr(owner.Session), owner.SID, owner.LogonID); err != nil {
		fmt.Printf("steer_stepup_result_notice_unavailable reason=session_changed\n")
	}
}

// showStepUpToast shows the balloon in the active console session (best-effort; the browser open is the
// actionable bit). The resource is sanitized then substituted into the script literal.
func showStepUpToast(resource string) {
	script := strings.ReplaceAll(stepUpToastScript, "__DSSE_RESOURCE__", sanitizeResource(resource))
	cmd := fmt.Sprintf(`powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command "%s"`, script)
	if err := launchInActiveSession(cmd); err != nil {
		// session-0 fallback (foreground test); harmless if it shows nowhere.
		c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = c.Start()
	}
}

// sanitizeResource keeps only characters valid in a recovered host:port (IPv4/IPv6/host + ':' + digits), so
// the value is safe to interpolate into the PowerShell toast literal. Anything else is dropped.
func sanitizeResource(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == ':' || r == '-' || r == '_' || r == '[' || r == ']':
			return r
		default:
			return -1
		}
	}, s)
}

// launchInActiveSession runs commandLine in the active console session (the logged-in user), attached to the
// interactive desktop, so a session-0 service can surface UI to the user. Returns an error when there is no
// active user session or the token/process creation fails (caller falls back to a best-effort session-0 spawn).
func launchInActiveSession(commandLine string) error {
	sid, _, _ := procWTSGetActiveConsole.Call()
	if uint32(sid) == invalidSessionID {
		return fmt.Errorf("no active console session")
	}
	return launchInSession(commandLine, sid, "")
}

func launchInSession(commandLine string, sid uintptr, expectedSID string, expectedLogonID ...uint64) error {
	var token syscall.Handle
	r1, _, e1 := procWTSQueryUserToken.Call(sid, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return fmt.Errorf("WTSQueryUserToken(session=%d): %v", uint32(sid), e1)
	}
	defer procStepupCloseHandle.Call(uintptr(token))
	if expectedSID != "" {
		identity, err := windows.Token(token).GetTokenUser()
		if err != nil || identity.User.Sid.String() != expectedSID {
			return fmt.Errorf("session owner changed")
		}
	}
	if len(expectedLogonID) == 1 && expectedLogonID[0] != 0 {
		logonID, err := stepUpTokenLogonID(windows.Token(token))
		if err != nil || logonID != expectedLogonID[0] {
			return fmt.Errorf("session login changed")
		}
	}

	// Build the TARGET USER's environment block. Without it CreateProcessAsUserW passes NULL -> the child
	// inherits the SERVICE's (session-0 SYSTEM) environment, and `rundll32 url.dll,FileProtocolHandler` then
	// cannot resolve the user's default-browser association (USERPROFILE/APPDATA/LOCALAPPDATA + the loaded
	// HKCU are the SYSTEM account's), so rundll32 runs but NO browser opens — even though the token/desktop are
	// correct (a self-contained command like the PowerShell toast still works, which is why the toast shows but
	// the portal did not). CreateEnvironmentBlock(token) gives the child the real user env; pass it with
	// CREATE_UNICODE_ENVIRONMENT. Failure refuses the launch; never inherit SYSTEM.
	var envBlock uintptr
	creationFlags := uintptr(createNoWindow)
	if r, _, _ := procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&envBlock)), uintptr(token), 0); r != 0 && envBlock != 0 {
		creationFlags |= createUnicodeEnvironment
		defer procDestroyEnvironmentBlock.Call(envBlock)
	} else {
		return fmt.Errorf("target user environment unavailable")
	}

	// CreateProcessAsUserW mutates the command-line buffer in place, so pass a writable UTF-16 slice.
	cmd16, err := syscall.UTF16FromString(commandLine)
	if err != nil {
		return err
	}
	desktop, _ := syscall.UTF16FromString(`winsta0\default`)
	si := syscall.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = &desktop[0]
	pi := syscall.ProcessInformation{}

	r2, _, e2 := procCreateProcessAsUserW.Call(
		uintptr(token),
		0,                                  // lpApplicationName (NULL -> parsed from command line)
		uintptr(unsafe.Pointer(&cmd16[0])), // lpCommandLine (writable)
		0, 0,                               // process/thread security attributes
		0,             // bInheritHandles = FALSE
		creationFlags, // dwCreationFlags (+ CREATE_UNICODE_ENVIRONMENT when an env block is supplied)
		envBlock,      // lpEnvironment (the validated target user's block)
		0,             // lpCurrentDirectory (NULL)
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r2 == 0 {
		return fmt.Errorf("CreateProcessAsUser: %v", e2)
	}
	procStepupCloseHandle.Call(uintptr(pi.Thread))
	procStepupCloseHandle.Call(uintptr(pi.Process))
	return nil
}

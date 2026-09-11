//go:build windows

package main

import (
	"fmt"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// The agent runs as a LocalSystem Windows service in session 0. A plain spawn (exec.Command) would land the
// browser/toast in session 0 -- no user desktop and no per-user default-browser association -- so the user
// never sees the step-up portal. These launch the portal in the ACTIVE CONSOLE SESSION (the logged-in user)
// via WTSQueryUserToken + CreateProcessAsUserW. Raw syscalls (no x/sys/windows dependency), consistent with
// service_windows.go. kernel32/advapi32 are the package-level lazy DLLs declared in the other _windows files.
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

// defaultStepUpLauncher is the Windows step-up surface. It prefers the Lantern DSSE-branded, app-owned OOB
// window (dsse-stepup-window.exe — a WebView2 host, task #14, parity with the macOS StepUpAuthWindow) launched
// into the active console session, replacing the "surprise default-browser tab". The window hosts the REAL IdP
// login page (the client never sees the secret -> phishing-resistant) and auto-closes on the Edge "Access
// approved" callback; the held flow then auto-releases server-side (task #5). If the window exe is missing or
// cannot launch, it FALLS BACK to opening the portal in the user's default browser (+ a tray balloon) so the
// ceremony never strands. Best-effort and non-fatal: a launch failure must never wedge the steering data path.
func defaultStepUpLauncher(resource, portalURL string) {
	// The portal URL is EDGE-SUPPLIED and reaches a command line / FileProtocolHandler, so validate it before
	// launching (fail-open review #29): only a well-formed http/https URL with no command-line-breaking or
	// argument characters is launched. This blocks argument injection (a URL with a quote/space) and arbitrary
	// protocol-handler launch (a non-web scheme like file:/javascript:/an .exe path). An invalid URL is refused
	// and surfaced — never launched.
	safeURL, ok := validatedStepUpURL(portalURL)
	if !ok {
		fmt.Printf("steer_stepup_rejected_invalid_portal_url resource=%s url=%q\n", stepUpDestLabel(resource), portalURL)
		showStepUpToast(resource)
		return
	}
	if exe := stepUpWindowExePath(); exe != "" {
		dest := stepUpDestLabel(resource)
		host := fmt.Sprintf(`"%s" --portal "%s" --dest "%s"`, exe, safeURL, dest)
		if err := launchInActiveSession(host); err == nil {
			return // the branded window IS the surface; no toast needed on the happy path
		} else {
			fmt.Printf("steer_stepup_window_fallback resource=%s err=%v\n", dest, err)
		}
	}
	// Fallback: default browser in the user session (prior behaviour) + a tray balloon cue. Pass the validated URL
	// as a SINGLE argv element (no shell string) so it cannot inject; the launchInActiveSession string form uses
	// the same validated value.
	// rundll32 from the system directory, in BOTH forms — see package winbin. The string form is handed to the
	// logged-in user's session, where %PATH% is the user's and not this service's.
	rundll32, rerr := winbin.System("rundll32.exe")
	if rerr != nil {
		fmt.Printf("steer_stepup_browser_unavailable resource=%s err=%v\n", resource, rerr)
		showStepUpToast(resource)
		return
	}
	browser := fmt.Sprintf(`"%s" url.dll,FileProtocolHandler %s`, rundll32, safeURL)
	if err := launchInActiveSession(browser); err != nil {
		fmt.Printf("steer_stepup_browser_session_fallback resource=%s err=%v\n", resource, err)
		c := exec.Command(rundll32, "url.dll,FileProtocolHandler", safeURL)
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = c.Start()
	}
	showStepUpToast(resource)
}

// validatedStepUpURL returns the URL only if it is a well-formed http/https URL safe to place on a command line:
// a parseable absolute URL, scheme http or https, a non-empty host, and no whitespace, quotes, backslashes, or
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
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", false
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", false
	}
	return raw, true
}

// stepUpWindowExePath resolves the branded OOB window exe next to the agent binary. Returns "" if it is not
// present, so the caller falls back to the browser.
func stepUpWindowExePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// Name comes from runtimeCompanions (companions.go) rather than a literal here, so the packaging test and
	// the startup report cannot drift from what is actually looked up.
	p := filepath.Join(filepath.Dir(exe), stepUpWindowCompanion().Exe)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// stepUpWindowCompanion is the declared entry for the branded window.
func stepUpWindowCompanion() companion {
	for _, c := range runtimeCompanions {
		if strings.Contains(c.Exe, "stepup-window") {
			return c
		}
	}
	// Unreachable while the table is intact; companions_test.go pins it.
	return companion{Exe: "dsse-stepup-window.exe"}
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
	var token syscall.Handle
	r1, _, e1 := procWTSQueryUserToken.Call(sid, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return fmt.Errorf("WTSQueryUserToken(session=%d): %v", uint32(sid), e1)
	}
	defer procStepupCloseHandle.Call(uintptr(token))

	// Build the TARGET USER's environment block. Without it CreateProcessAsUserW passes NULL -> the child
	// inherits the SERVICE's (session-0 SYSTEM) environment, and `rundll32 url.dll,FileProtocolHandler` then
	// cannot resolve the user's default-browser association (USERPROFILE/APPDATA/LOCALAPPDATA + the loaded
	// HKCU are the SYSTEM account's), so rundll32 runs but NO browser opens — even though the token/desktop are
	// correct (a self-contained command like the PowerShell toast still works, which is why the toast shows but
	// the portal did not). CreateEnvironmentBlock(token) gives the child the real user env; pass it with
	// CREATE_UNICODE_ENVIRONMENT. Best-effort: if it fails, fall back to NULL (prior behavior).
	var envBlock uintptr
	creationFlags := uintptr(createNoWindow)
	if r, _, _ := procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&envBlock)), uintptr(token), 0); r != 0 && envBlock != 0 {
		creationFlags |= createUnicodeEnvironment
		defer procDestroyEnvironmentBlock.Call(envBlock)
	} else {
		envBlock = 0
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
		envBlock,      // lpEnvironment (the target user's block, or NULL on failure)
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

//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// warnToastScript pops a PASSIVE tray balloon (Info icon, no action button, no sound) for the Warn-stage notice.
// Reuses the same NotifyIcon approach as the step-up toast — no window, no browser (a WARN flow is already
// allowed; this is informational only). __DSSE_DEST__ / __DSSE_SVC__ are substituted AFTER sanitization so a
// destination/service value can never inject into the script.
const warnToastScript = `$ErrorActionPreference='SilentlyContinue';` +
	`Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;` +
	`$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Information;` +
	`$n.BalloonTipIcon=[System.Windows.Forms.ToolTipIcon]::Info;$n.BalloonTipTitle='Lantern DSSE - この接続は監視されています';` +
	`$n.BalloonTipText='__DSSE_DEST__ (__DSSE_SVC__) への接続は監視されています。まもなく認証が必要になります。';` +
	`$n.Visible=$true;$n.ShowBalloonTip(8000);Start-Sleep -Seconds 9;$n.Dispose()`

// defaultWarnLauncher shows the passive Warn notice only in the originating flow owner's session.
// A different user may own the active console by the time the Edge sends WARN, so there is no active-console
// or session-0 fallback. Best-effort and non-fatal: it never holds or opens anything.
func defaultWarnLauncher(dest, service string, owner stepUpOwner) {
	if !warnOwnerStillCurrent(owner, captureStepUpOwner) {
		fmt.Fprintln(os.Stderr, "steer warn: originating user session unavailable")
		return
	}
	script := strings.ReplaceAll(warnToastScript, "__DSSE_DEST__", sanitizeResource(dest))
	script = strings.ReplaceAll(script, "__DSSE_SVC__", sanitizeResource(service))
	// Resolved from the system directory for both forms — see package winbin. The string form runs in the
	// logged-in user's session, whose %PATH% is not this service's and is writable by that user.
	ps, err := winbin.PowerShell()
	if err != nil {
		fmt.Fprintf(os.Stderr, "steer warn: the notice could not be shown (%v)\n", err)
		return
	}
	cmd := fmt.Sprintf(`"%s" -NoProfile -NonInteractive -WindowStyle Hidden -Command "%s"`, ps, script)
	if err := launchInSession(cmd, uintptr(owner.Session), owner.SID, owner.LogonID); err != nil {
		fmt.Fprintln(os.Stderr, "steer warn: originating user session unavailable")
	}
}

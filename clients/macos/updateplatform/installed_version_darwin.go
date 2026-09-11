//go:build darwin

package updateplatform

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// InstalledAppBundle is where the agent's application bundle lives once installed. The updater reads its
// version from here, which is the one answer that survives the agent being dead.
const InstalledAppBundle = "/Applications/LanternDsseAgent.app"

// InstalledVersion is the agent version this Mac HAS, as opposed to the one it is running.
//
// ★ A ROLLBACK IS ORDERED ON A MACHINE WHOSE AGENT IS BROKEN, SO "RUNNING" IS THE ANSWER LEAST LIKELY TO
// EXIST (2026-08-13, twenty-seventh review). macOS passed no LeavingVersion at all, so on the device the
// rollback exists for — a crash-looping extension, a stale or absent runtime marker — nothing was poisoned:
// `agentupdate.Rollback` ran with running="" and leaving="", `journal.Refuse` was never called, and the next
// thirty-minute pass found the bad version still offered and INSTALLED IT AGAIN. The device could not stay
// rolled back. Windows hit exactly this on win-dev-1 and fixed it by passing its registry InstalledVersion;
// this is the same answer from the place macOS keeps it.
//
// The form matches what the agent reports and what the rollback intent carries:
// "<CFBundleShortVersionString>+<CFBundleVersion>". Empty when the bundle is absent or unreadable, which is
// honest — the caller then poisons nothing, exactly as before, rather than poisoning a guess.
func InstalledVersion() string {
	short := plistValue(InstalledAppBundle+"/Contents/Info.plist", "CFBundleShortVersionString")
	build := plistValue(InstalledAppBundle+"/Contents/Info.plist", "CFBundleVersion")
	switch {
	case short != "" && build != "":
		return short + "+" + build
	case short != "":
		return short
	default:
		return ""
	}
}

// plistValue reads one key with PlistBuddy, the tool that is present on every Mac and understands both the
// binary and XML forms an Info.plist can be in.
func plistValue(path, key string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/libexec/PlistBuddy", "-c", "Print :"+key, path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

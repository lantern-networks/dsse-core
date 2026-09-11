//go:build windows

// Package winbin resolves the executables that ship WITH Windows — msiexec, sc, netsh, powershell, rundll32 —
// from the system directory, without consulting %PATH%.
//
// ★ IT EXISTS BECAUSE THE LOOKUP FAILED ON A REAL BOX. win-dev-1, update journal, 2026-08-11T21:45:52Z:
//
//	execute failed: locate msiexec: exec: "msiexec.exe": executable file not found in %PATH%;
//	★ steering could NOT be restored afterwards: DsseSteer was restarted but the driver does not report
//	an armed redirect within 1m0s; this endpoint is NOT steering
//
// msiexec.exe was exactly where it always is, and the same lookup succeeded from a shell, from a scheduled task
// running as SYSTEM, and from an interactive session on the same machine minutes later. The environment that
// produced the failure has NOT been reproduced. This package is written so that it does not have to be: the
// answer no longer depends on what any process inherited.
//
// What it cost is the reason it is a package rather than a line. The update sequencing takes steering DOWN
// before handing over on a fail-open endpoint, so resolving a name decided whether the box was protected — and
// when the launch failed, the restoration behind it failed too.
//
// ★ AND IT IS THE RIGHT SHAPE WITHOUT THE INCIDENT. These processes run as LocalSystem. %PATH% is an ordered
// list that an administrator — or anything running as one — can prepend to, so a SYSTEM service that finds
// sc.exe, netsh or powershell by searching is trusting whatever answers first, on the paths that install
// software, control services and change the firewall.
//
// There is deliberately NO fallback to exec.LookPath. Falling back would restore the dependency quietly on
// precisely the box where the primary answer failed, which is the one place it must not.
package winbin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// System resolves an executable in the Windows system directory (normally C:\Windows\System32).
//
// The name is joined, never searched: passing something that is not a system binary is a programming error and
// gets an error naming the path that was tried, rather than a silent search elsewhere.
func System(name string) (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil || strings.TrimSpace(dir) == "" {
		// %SystemRoot% is the weaker answer — an environment variable, inside a package whose whole subject is
		// not trusting the environment — but it is the only other one, and one of the two is always right.
		root := strings.TrimSpace(os.Getenv("SystemRoot"))
		if root == "" {
			return "", fmt.Errorf("locate %s: the system directory could not be read (%v) and %%SystemRoot%% is not set", name, err)
		}
		dir = filepath.Join(root, "System32")
	}
	p := filepath.Join(dir, name)
	if _, serr := os.Stat(p); serr != nil {
		return "", fmt.Errorf("locate %s: %w", name, serr)
	}
	return p, nil
}

// PowerShell resolves Windows PowerShell, which does NOT sit directly in the system directory.
//
// Kept as its own function rather than a string constant at each call site: "System32\\WindowsPowerShell\\v1.0"
// is the kind of literal that gets copied with a typo into one of five places and is then found only by the
// call site that runs least often.
//
// Windows PowerShell (5.1, shipped with the OS) and NOT pwsh, deliberately: pwsh is an optional install, it is
// not in a fixed location, and the callers here run firewall and notification scripts that must work on a
// machine where nothing extra was installed.
func PowerShell() (string, error) {
	return System(filepath.Join("WindowsPowerShell", "v1.0", "powershell.exe"))
}

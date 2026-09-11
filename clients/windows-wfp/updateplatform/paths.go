// Package updateplatform is the Windows half of agentupdate.Platform: the doing, with the sequencing left
// where it already is.
//
// agentupdate owns the ORDER an update happens in and is tested without a Windows box. What is missing on
// this platform is the five things it cannot do itself — read the running version, observe the device, secure
// restore material, take steering down and confirm it, and hand control to an installer. Each is small; the
// interesting decisions are which source answers which question, and those are recorded next to the code that
// depends on them.
//
// Nothing this package does is invented from scratch. The running version comes from runstate (the value the
// live agent recorded, paired with the SCM), the restore material from rollbackstore (what the installer
// stashed), the disarm verdict from wfpstate (the driver's own answer, not this process's belief), and the
// disarm itself is performed the way the watchdog already performs it — by running the agent binary rather
// than by reaching into it.
//
// paths.go holds the parts with no syscalls in them, so the naming decisions are exercised on any host.
package updateplatform

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// StagedRoot is where a verified artifact waits for the installer: %ProgramData%\DSSE\staged.
//
// Beside the rollback store rather than in %TEMP%, for two reasons. A staged package is the input to a
// privileged execution, and %TEMP% is writable by more principals than %ProgramData%\DSSE — a staged file
// somebody else can replace between verification and execution defeats the digest check entirely. And
// cleaners empty %TEMP% on a schedule, which would turn a device that was waiting for its update window into
// one that silently re-downloads on every tick.
func StagedRoot() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "DSSE", "staged")
	}
	return filepath.Join("DSSE", "staged")
}

// StagedPath is where the artifact for a version is staged.
//
// The name is produced by rollbackstore.FileName deliberately, rather than by a second formatter here. That
// function already refuses the versions that must never reach a path — a version arrives from a signed
// manifest, so it is an input, and `..\..\Windows\System32\x` would otherwise steer a privileged install at
// a file of someone else's choosing. Two formatters would mean two chances to get that wrong; one means the
// staging path inherits the validation the store already has a test for.
func StagedPath(version string) (string, error) {
	name, err := rollbackstore.FileName(version)
	if err != nil {
		return "", fmt.Errorf("updateplatform: staged path for %q: %w", version, err)
	}
	return filepath.Join(StagedRoot(), name), nil
}

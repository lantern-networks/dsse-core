//go:build windows

// stash_rollback_windows.go — the install-time half of rollback material.
//
// agentupdate.Run refuses to start an update when CaptureRestoreMaterial cannot produce anything, on the
// argument that an update which cannot be rolled back is the same as having no rollback. Nothing was putting
// packages anywhere for it to find, so that refusal would have fired on every box forever — which presents
// as "the updater is broken", not as "the installer never stashed".
//
// WHY THE INSTALLER AND NOT THE UPDATER. The package to keep is the one that produced the version now being
// installed, and the only moment it is reliably on hand is while it is being installed. Afterwards msiexec's
// cache is not something to build a rollback on: it is keyed by product code, discarded by cleanup tooling,
// and holds the LAST package rather than the one for a chosen version.
//
// WHY THE VERSION COMES FROM THE BINARY. The key has to be the exact string the updater will later look up,
// and that one comes from the live agent's agentVersion() via runstate. MSI's ProductVersion cannot be it:
// three numeric fields cannot carry "+2e39256d", so the stash and the lookup would disagree on every box
// while both looked correct in isolation. Asking the just-installed dsse-steer.exe means one function
// produces both strings — they agree by construction rather than by two literals staying in step.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/rollbackstore"
)

// steerExeName is the agent as the MSI lays it down (DsseAgent.wxs File Source="dsse-steer.exe").
const steerExeName = "dsse-steer.exe"

// versionProbeTimeout bounds the --version child. A custom action runs inside the msiexec transaction, so a
// child that never returns does not merely fail this step — it wedges the install. The agent checks
// --version immediately after flag.Parse(), before its log redirect and posture banner, so this is generous
// by a wide margin and only ever fires on a binary that is already broken.
const versionProbeTimeout = 30 * time.Second

// doStashRollbackMSI copies msiPath into the rollback store under the version the installed agent reports.
//
// Every failure here is reported and non-fatal by design: the custom action is Return="ignore". A box with no
// stashed package refuses future updates and says why, which is a degraded but honest state; failing the
// install instead would turn "this box cannot roll back later" into "this box has no agent now".
func doStashRollbackMSI(msiPath string, keep int) error {
	if msiPath == "" {
		return errors.New("--stash-rollback-msi requires the path to the installer package")
	}
	// MSI hands this over as [OriginalDatabase], which is absolute. A relative value means someone ran this by
	// hand, and resolving it against the current directory is the least surprising thing to do — but the
	// installer path must never be resolved against the exe dir the way --config is, because the package is
	// not installed beside the binaries and silently finding the wrong file would be worse than failing.
	if !filepath.IsAbs(msiPath) {
		abs, err := filepath.Abs(msiPath)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", msiPath, err)
		}
		msiPath = abs
	}

	version, err := installedAgentVersion()
	if err != nil {
		return fmt.Errorf("determine the version this package installs: %w", err)
	}

	store := rollbackstore.New(rollbackstore.DefaultRoot())
	stored, err := store.Stash(msiPath, version)
	if err != nil {
		return fmt.Errorf("stash %s: %w", msiPath, err)
	}
	fmt.Printf("profileapply: rollback material stored for %s at %s\n", version, stored)

	// ★ Record that THIS package can be rolled back TO.
	//
	// The check that admits a deliberate downgrade is the MSI's own launch condition on DSSEROLLBACK, and it
	// travels inside the package. So "can this stored MSI be installed over a newer one" is a property of the
	// stored bytes, not of the box and not of the updater — and nothing about the file says which kind it is.
	// This binary ships in the same package as that condition, so its writing the marker IS the evidence.
	//
	// Without it, --rollback on a box whose stored MSI predates the condition would launch msiexec, be refused
	// in seconds, and leave a journal saying a rollback was in progress on a machine nothing had touched — the
	// false "check this box's network" alarm, recreated in the recovery path. With it, the updater refuses
	// before launching anything and says why, on a good day rather than during the incident.
	//
	// Non-fatal like everything else here: a box that cannot roll back is degraded and honest, and failing the
	// install over it would turn that into a box with no agent.
	if err := store.MarkAcceptsRollbackIntent(version); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: could not record that %s accepts a declared rollback (non-fatal, "+
			"but this box will refuse to roll back TO %s and say so): %v\n", version, version, err)
	}

	// Housekeeping, and explicitly last: a prune failure must not make a successful stash look failed. The
	// version just installed is protected by name because it is the one a rollback from the NEXT update needs,
	// and on a long-stable box it is also the one a last-modified rule would reach for first.
	//
	// ★ AND THE VERSION A ROLLBACK WOULD ACTUALLY INSTALL (2026-08-12, found on the lab MAC and fixed here
	// before a Windows box could reach the same state). Protecting only the version just installed is a rule
	// about what is probably useful; the journal's from_version is the fact — it names where this device would
	// go back to. A store that has pruned it leaves a box that BELIEVES it can roll back and cannot, discovered
	// only during the incident that made someone reach for it.
	//
	// Best-effort: an unreadable journal protects nothing extra and the keep-newest rule still bounds the
	// directory. Failing an install over housekeeping would be the worse trade, here as everywhere else in this
	// function.
	protect := []string{version}
	if from := rollbackTargetFromJournal(); from != "" && from != version {
		protect = append(protect, from)
	}
	if err := store.Prune(keep, protect...); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: rollback store prune (non-fatal): %v\n", err)
	}
	return nil
}

// rollbackTargetFromJournal reads the version a rollback would install, or "" when it cannot be established.
//
// Deliberately a direct read of the journal file rather than a dependency on the updater's config plumbing:
// this binary runs inside an MSI custom action, where the less it needs to be true the better.
func rollbackTargetFromJournal() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(root, "DSSE", "update", "journal.json"))
	if err != nil {
		return ""
	}
	var j struct {
		FromVersion string `json:"from_version"`
	}
	if jerr := json.Unmarshal(raw, &j); jerr != nil {
		return ""
	}
	return strings.TrimSpace(j.FromVersion)
}

// doClearRollbackStore removes every stored package on uninstall.
//
// It exists for the same reason --clear does: the store is written outside MSI component tracking, so
// RemoveFiles never sees it. The difference is the size of what would be left behind — tens of megabytes per
// retained version, in a directory nobody would think to look in after the product is gone.
//
// Prune(0) with nothing protected is the whole operation: it removes exactly the files this package wrote and
// leaves anything else alone, which matters because %ProgramData%\DSSE is shared with other DSSE state and a
// blanket RemoveAll there would take more than ours.
func doClearRollbackStore() error {
	store := rollbackstore.New(rollbackstore.DefaultRoot())
	if err := store.Prune(0); err != nil {
		return err
	}
	// Best-effort, and only succeeds when the directory is empty — which is the point. A leftover file means
	// something we did not write is in there, and removing it is not ours to do.
	if err := os.Remove(store.Root()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "profileapply: rollback store directory left in place: %v\n", err)
	}
	fmt.Println("profileapply: rollback store cleared")
	return nil
}

// installedAgentVersion asks the agent binary sitting beside this one what version it is.
//
// Beside this one, rather than a path threaded through CustomActionData: profileapply.exe and dsse-steer.exe
// co-install in INSTALLDIR, so the exe's own directory is INSTALLDIR by construction — the same reasoning
// --config already uses to accept a bare "profile.json".
//
// This deliberately reports the version ON DISK. It is the right one here and the wrong one for the update
// gate: the installer is recording what this package installs, while the gate must know what is executing.
// The two differ on exactly the box that matters, which is why they have separate sources.
func installedAgentVersion() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this executable: %w", err)
	}
	steer := filepath.Join(filepath.Dir(exe), steerExeName)
	if _, err := os.Stat(steer); err != nil {
		return "", fmt.Errorf("agent binary %s: %w", steer, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, steer, "--version").Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("%s --version did not return within %s", steerExeName, versionProbeTimeout)
	}
	if err != nil {
		// Include stderr when the child produced any: "exit status 1" alone has sent people to the wrong file.
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s --version failed: %w: %s", steerExeName, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("%s --version failed: %w", steerExeName, err)
	}
	return parseVersionOutput(string(out))
}

// parseVersionOutput takes the first non-empty line of --version's output.
//
// First LINE rather than the whole thing, because anything a Go runtime decides to print (a cgo warning, a
// deprecation notice) would otherwise be appended to the key and produce a name that matches nothing. A
// version containing whitespace is refused rather than trimmed into shape: it means the output was not a
// version at all, and inventing a key from it would store real material under a name no lookup will use.
func parseVersionOutput(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			return "", fmt.Errorf("expected a bare version, got %q", line)
		}
		return line, nil
	}
	return "", errors.New("--version printed nothing")
}

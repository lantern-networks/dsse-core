package updateplatform

// publisher_darwin.go — asking the two questions of the operating system. The judgement is in publisher.go;
// this file only runs the tools and refuses to guess when they cannot be run.

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrPublisherUntrusted is what a caller can test for: the bytes on disk are not a package this device's
// publisher built. It is deliberately DISTINCT from a digest mismatch — those bytes were not the ones named,
// these are the ones named by a manifest that should not have named them.
var ErrPublisherUntrusted = errors.New("the package was not built by the publisher this device trusts")

// publisherToolTimeout bounds each tool. Both are local and answer in well under a second on a stapled package;
// a call that hangs would otherwise hang the updater's whole pass, and an update daemon that stops ticking is
// how a fleet stops being patchable.
const publisherToolTimeout = 60 * time.Second

// VerifyPublisher is the gate between a verified download and a privileged installer.
//
// It refuses in every direction that is not a clear pass, including "the tool would not run", because the
// alternative — treating an unanswerable question as a yes — is the failure this whole file exists to remove.
// The cost of refusing wrongly is that a device stays on the version it is already running, which is a state it
// was in a second ago and can be diagnosed from a report; the cost of passing wrongly is arbitrary code as root.
//
// ★ NOT CONFIGURED IS NOT A PASS EITHER, BUT IT IS NOT A REFUSAL. A device whose configuration names no
// publisher is one that shipped before this check existed, and refusing there would strand exactly the fleet
// that most needs to be able to update to a build that has it. It returns nil with a sentence that says what is
// missing and what it costs — and the installer gate refuses to install a NEW configuration without the field,
// so the population that can be in this state only shrinks.
func VerifyPublisher(pkgPath string, req PublisherRequirement) (note string, err error) {
	if !req.Configured() {
		return RequirementMissingNote, nil
	}

	sigOut, sigErr := runPublisherTool("/usr/sbin/pkgutil", "--check-signature", pkgPath)
	if sigOut == "" {
		// No output at all means the tool did not run — a missing binary, a sandbox, a machine mid-upgrade. The
		// answer is unknown, and unknown must not install.
		return "", fmt.Errorf("%w: pkgutil --check-signature could not be run on %s (%v), so who signed this "+
			"package is unknown — and a check that cannot run must not pass", ErrPublisherUntrusted, pkgPath, sigErr)
	}
	if err := parsePkgutilSignature(sigOut, req.TeamID); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPublisherUntrusted, err)
	}

	assessOut, assessErr := runPublisherTool("/usr/sbin/spctl", "--assess", "--type", "install", "-vv", pkgPath)
	if assessOut == "" {
		return "", fmt.Errorf("%w: spctl --assess could not be run on %s (%v), so whether this package was "+
			"notarized is unknown", ErrPublisherUntrusted, pkgPath, assessErr)
	}
	if err := parseSpctlAssessment(assessOut, req.TeamID); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPublisherUntrusted, err)
	}

	return fmt.Sprintf("publisher verified: notarized Developer ID Installer, team %s", req.TeamID), nil
}

// VerifyPublisherFromConfig is the wiring the install paths use: read the requirement, then apply it.
//
// A configuration that cannot be READ refuses, and that is not the same rule as a configuration with no
// publisher field. This file is the one the updater already got its signing keys from moments earlier; if it
// has become unreadable since, the device cannot state what it trusts, and installing on the strength of a
// check whose parameters just vanished is the shape of the bug this product keeps finding in itself.
func VerifyPublisherFromConfig(configPath, pkgPath string) (note string, err error) {
	req, rerr := LoadPublisherRequirement(configPath)
	if rerr != nil {
		return "", fmt.Errorf("%w: this device's publisher requirement could not be read (%v), so it cannot say "+
			"whose packages it accepts", ErrPublisherUntrusted, rerr)
	}
	return VerifyPublisher(pkgPath, req)
}

// runPublisherTool returns whatever the tool printed, whether or not it exited zero.
//
// ★ THE EXIT CODE IS NOT THE ANSWER, and using it would invert one of the two checks: `spctl --assess` exits
// NON-ZERO precisely when it rejects a package, so a helper that discarded output on error would turn every
// rejection into "the tool could not be run" — and if that were ever softened to a warning, into a pass.
func runPublisherTool(name string, args ...string) (string, error) {
	// ★ CommandContext RATHER THAN A HAND-WRITTEN TIMEOUT (2026-08-13, thirtieth review #23). The first version
	// ran CombinedOutput in a goroutine and raced a time.After against it. On a timeout it returned while that
	// goroutine was still writing the shared out/err variables — a data race — and it leaked the goroutine for
	// as long as the tool took to die, in a daemon that runs this every pass. The kill was also guarded by a nil
	// check on cmd.Process, which is set inside CombinedOutput: a tool that hung before Start returned would not
	// have been killed at all.
	//
	// The context does all of it, correctly and in one line: it kills the process and CombinedOutput returns.
	ctx, cancel := context.WithTimeout(context.Background(), publisherToolTimeout)
	defer cancel()
	// CombinedOutput: spctl writes its verdict to stderr and pkgutil to stdout, and reading only one of them
	// depends on remembering which is which.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("%s did not answer within %s", name, publisherToolTimeout)
	}
	return strings.TrimSpace(string(out)), err
}

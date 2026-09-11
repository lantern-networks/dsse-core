package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// self_integrity.go — the agent checks who can rewrite it, and says so at startup.
//
// WHY. On 2026-07-28 the steering agent was found running from a build-output directory that an unresolved
// AppContainer principal could write to. That is a path to SYSTEM on the machine, but the part that matters
// here is narrower and worse: EVERY GUARANTEE THIS AGENT MAKES IS VOID IF SOMEBODY ELSE CAN REWRITE IT. Policy,
// logging, revocation, the kill-switch — all of it is whatever the binary says it is, and a binary a third
// party can replace says whatever they like. There is no enforcement left to reason about.
//
// It was found by a person looking at ACLs, not by the product. So the product now looks. This is the same
// shape as the keychain-writability and Secure-Enclave probes on macOS: state the precondition out loud at
// startup, so it is visible BEFORE the day it matters rather than during the incident.
//
// WHAT IT DOES NOT DO. It does not refuse to start. A steering agent that quits because of a permissions
// finding leaves the endpoint completely unprotected, which is worse than running with a caveat — and an agent
// that refuses to start gets removed from the fleet rather than fixed. It reports, loudly, and keeps working.
//
// It also does not verify a signature or a hash. Knowing the file is unchanged says nothing about whether it
// can be changed a second from now, and the exposure here was about WRITE ACCESS, not about a tampered file.

// selfIntegrityReport is what the check found about the running executable's directory.
type selfIntegrityReport struct {
	Path string
	// WorldWritable / GroupWritable are the POSIX view, and are ONLY set on platforms that honour it.
	//
	// ★ NOT ON WINDOWS, AND THAT WAS THE DEFECT (2026-08-14, reported from the Windows box). Go synthesises
	// Mode().Perm() on Windows from the read-only attribute alone, so anything writable reads 0666/0777 and
	// this check called C:\Windows\System32 world-writable. A check that cannot pass is a check that gets
	// ignored — and this one guards the precondition every other guarantee rests on, so teaching operators to
	// scroll past it is worse than not having it. Windows answers the real question instead: which principals
	// hold write access in the DACL. See UntrustedWriters.
	WorldWritable bool
	GroupWritable bool
	// UntrustedWriters names the principals that may rewrite this executable, on platforms where the question
	// is an ACL rather than three permission bits. Empty means the probe ran and found only trusted ones
	// (SYSTEM, Administrators, TrustedInstaller) — which is not the same as the probe not running, hence the
	// error return on failure.
	UntrustedWriters []string
	// InBuildOutput flags an executable running from somewhere that a build regenerates. Permissions there are
	// reset by the next build, so tightening them is not a fix — the location is the problem. This is exactly
	// where the Windows agent was found running from.
	InBuildOutput bool
	Note          string
}

// buildOutputMarkers name path segments that indicate a build-output or source tree. A service executable in
// one of these is a standing hazard even when today's permissions happen to be correct.
//
// Written with forward slashes and matched against a path normalised the same way, INDEPENDENT of the host's
// separator. The first version used os.PathSeparator, which silently stopped recognising Windows paths when
// the check was exercised from a Mac — the platform where this logic is developed and tested is not the
// platform it runs on.
var buildOutputMarkers = []string{
	"/outputs/",
	"/build/",
	"/dist/",
	"/target/",
	"/bin/debug/",
	"/bin/release/",
}

// normalisePathForMatching makes a path comparable regardless of which OS produced it or which one is reading
// it: backslashes become slashes and case is folded (Windows paths are case-insensitive).
func normalisePathForMatching(path string) string {
	return strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
}

// directoryProbe answers "who may rewrite what is in this directory".
//
// ★ IT IS A PARAMETER FOR THE SAME REASON stat IS (2026-08-14). The two platform implementations do not read
// the same source: POSIX reads permission bits off the FileInfo it is handed, while Windows reads the live
// DACL off the disk and ignores the FileInfo entirely. When the Windows half was added it went straight to
// the filesystem, which quietly took the seam away — every test that passed a hypothetical path
// (`/opt/dsse`, `/usr/local/bin`) started failing on Windows with "cannot find the path", because the probe
// no longer honoured the injection the test had set up. The logic layered ON TOP of the probe (which
// locations count as build output, which finding outranks which) is platform-independent and must stay
// testable without a filesystem, so the probe comes in through the door rather than being reached for.
type directoryProbe func(dir string, info os.FileInfo, report *selfIntegrityReport) error

// checkSelfIntegrity inspects the running executable and the directory holding it.
//
// The DIRECTORY matters as much as the file: write access to the directory means the executable can be
// replaced by rename even when the file itself looks protected.
func checkSelfIntegrity(exePath string, stat func(string) (os.FileInfo, error), probe directoryProbe) (selfIntegrityReport, error) {
	report := selfIntegrityReport{Path: exePath}
	if strings.TrimSpace(exePath) == "" {
		return report, fmt.Errorf("no executable path")
	}
	// Matched against the WHOLE path, not just the directory: filepath.Dir cannot split a Windows path when
	// running on a Unix host, and the markers are directory segments either way.
	normalised := normalisePathForMatching(exePath)
	for _, marker := range buildOutputMarkers {
		if strings.Contains(normalised, marker) {
			report.InBuildOutput = true
			break
		}
	}

	dir := filepath.Dir(exePath)

	info, err := stat(dir)
	if err != nil {
		return report, fmt.Errorf("stat %s: %w", dir, err)
	}
	if perr := probe(dir, info, &report); perr != nil {
		// A probe that cannot answer must say UNKNOWN rather than report "nothing found": on the platform this
		// agent runs on, "I could not read the ACL" and "the ACL is fine" are different facts.
		return report, perr
	}

	report.Note = noteFor(report)
	return report, nil
}

// noteFor picks the one finding worth putting in front of an operator, most actionable first.
//
// Extracted so the ORDER is testable. A named writer outranks the rest deliberately: "somebody can rewrite
// this" is a fact to act on today, while "this is a build directory" is a fact about where it was installed —
// and when both hold, leading with the weaker one buries the urgent half.
func noteFor(report selfIntegrityReport) string {
	switch {
	case len(report.UntrustedWriters) > 0:
		return "the directory holding this executable is WRITABLE BY " + strings.Join(report.UntrustedWriters, ", ")
	case report.WorldWritable:
		return "the directory holding this executable is WORLD-WRITABLE"
	case report.InBuildOutput:
		return "this executable is running from a build-output directory"
	case report.GroupWritable:
		return "the directory holding this executable is group-writable"
	}
	return ""
}

// logSelfIntegrity reports the finding once at startup.
//
// Worth stating even when everything is fine, briefly: an operator reading the log needs to be able to tell
// "the check ran and found nothing" from "the check never ran", and those look identical when success is
// silent.
func logSelfIntegrity(report selfIntegrityReport, err error, logf func(string, ...any)) {
	if logf == nil {
		return
	}
	if err != nil {
		logf("self_integrity UNKNOWN path=%q error=%v — could not determine who may rewrite this agent", report.Path, err)
		return
	}
	if report.Note == "" {
		logf("self_integrity ok path=%q", report.Path)
		return
	}
	logf("⚠ self_integrity %s (%s) — every guarantee this agent makes depends on nobody else being able to "+
		"replace it: policy, logging and revocation are all only whatever the binary says they are. Move it to "+
		"a location only SYSTEM and Administrators can write, and point the service at the new path.",
		report.Note, report.Path)
}

// reportSelfIntegrity runs the check against the running executable.
func reportSelfIntegrity(logf func(string, ...any)) {
	exe, err := os.Executable()
	if err != nil {
		if logf != nil {
			logf("self_integrity UNKNOWN error=%v — could not determine this agent's own path", err)
		}
		return
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	report, err := checkSelfIntegrity(exe, os.Stat, probeDirectoryWritability)
	logSelfIntegrity(report, err, logf)
}

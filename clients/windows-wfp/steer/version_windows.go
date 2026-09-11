//go:build windows

// version_windows.go — build identity for the Windows steering agent, stamped at link time.
//
// Until 2026-08-05 this agent reported agent_version:"wfp-steer" on every registration and heartbeat. That is
// the name of a steering backend, not a version: every Windows box in a fleet reported the same string, so
// the Console's version distribution was a single meaningless bucket and no operator could answer "which
// build is that machine running?" — the question an agent rollout exists to answer. It is step 0 of
// docs/agent_auto_update_design.ja.md, and the macOS agent already reports a real stamp.
//
// Stamped by the same shared script every other Go artifact uses, so a Windows binary and an Edge binary
// answer the version question the same way:
//
//	go build -ldflags "$(sh scripts/build_stamp.sh)" ./clients/windows-wfp/steer
//
// The defaults are what an UNSTAMPED build reports, and they say so — an unstamped binary must be
// recognisable as unstamped rather than quietly claiming a version it does not have. Reporting "0.0.0-dev"
// from a fleet is a signal; reporting a plausible wrong number is not.
package main

import "strings"

var (
	buildVersion = "0.0.0-dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
	buildDirty   = "unknown"
)

// agentVersion is what this agent reports to the Edge: "<version>+<commit>", the same semver build-metadata
// shape the macOS agent uses ("0.1.0+20260805170618"), so one Console column reads consistently across
// platforms. A dirty tree is marked, because an artifact that matches no commit is exactly the one an
// operator must not mistake for a release.
func agentVersion() string {
	version := strings.TrimSpace(buildVersion)
	if version == "" {
		version = "0.0.0-dev"
	}
	commit := strings.TrimSpace(buildCommit)
	if commit == "" || commit == "unknown" {
		return version
	}
	if strings.EqualFold(strings.TrimSpace(buildDirty), "true") {
		commit += ".dirty"
	}
	return version + "+" + commit
}

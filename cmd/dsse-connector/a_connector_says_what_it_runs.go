package main

// a_connector_says_what_it_runs.go — what the connector reports about itself on every heartbeat: the build it
// runs and how long this process has been up.
//
// ★★ THE CONNECTOR NEVER SENT EITHER (2026-11-08, the fourth review of the acceptance C third-walk fixes,
// C3-R4-1). The Console's connector detail read "Version unknown, Uptime unknown". The third walk's fix taught the
// control plane to keep both from the Edges' reports, and said the Edge had been reporting them all along; the
// Edge does copy them from a heartbeat — and the shipped connector's heartbeat had neither field. The image build
// passes -X main.buildVersion to this binary as it does to the Edge, and this package had no such variable, so
// the linker dropped the value without a word.

import (
	"strings"
	"time"
)

// Stamped at build time (deploy/Dockerfile, scripts/build_stamp.sh), as for every other binary of the image.
var (
	buildVersion = ""
	buildCommit  = ""
)

// processStarted is when this connector process started; uptime is counted from it.
var processStarted = time.Now()

// connectorVersion is the build this process runs, in the shape the Edge reports its own builds in
// (version+commit). Empty when the binary was built without a stamp: that is reported as nothing, and the
// Console says "unknown", rather than inventing a version.
func connectorVersion() string {
	v := strings.TrimSpace(buildVersion)
	if v == "" {
		return ""
	}
	if c := strings.TrimSpace(buildCommit); c != "" && c != "unknown" {
		return v + "+" + c
	}
	return v
}

// connectorUptimeSeconds is how long this process has been running, never less than one second: the Edge
// records an uptime only when it is positive.
func connectorUptimeSeconds(now time.Time) int64 {
	s := int64(now.Sub(processStarted) / time.Second)
	if s < 1 {
		return 1
	}
	return s
}

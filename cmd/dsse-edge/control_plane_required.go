package main

import (
	"log"
	"strings"
)

// edgeIsControlPlane records whether THIS process is the control plane. Set once at startup. It is read by the
// revocation feed, which may only mark a set authoritative when it is the authority — a puller echoing what it
// pulled must never claim its empty set means zero.
var edgeIsControlPlane bool

// The control plane is not an optional component of this system.
//
// Config, admission and revocation are AUTHORED on the control plane and distributed from it. An Edge started
// without one does not become a smaller deployment; it becomes a node whose truth is whatever happens to be on
// its disk, drifting from every other node and from the console an operator is reading. Worse, the drift is
// invisible from the Edge's own surfaces — it answers every query consistently, because it is consistent with
// itself.
//
// So this is a startup refusal rather than a warning. A warning at boot is read once, by whoever was already
// watching, and then scrolls away; the misconfiguration it described survives every restart afterwards. The
// process that will not start is the one that gets fixed.
//
// -no-control-plane is the way out for single-process test harnesses, which genuinely are not deployments. It
// is deliberately verbose and unambiguous: a reader scanning a command line should be able to tell that the
// process is not part of a fleet without knowing anything else about the flag.
func requireControlPlaneOrExit(mode string, isControlPlane bool, configSourceURL, configSourceEndpoints string, noControlPlane bool) {
	edgeIsControlPlane = isControlPlane
	if controlPlaneRequired(mode, isControlPlane, configSourceURL, configSourceEndpoints, noControlPlane) {
		log.Fatalf("REFUSING TO START: this Edge has no control plane. Set -config-source-url (single CP) or -config-source-endpoints (multi-region), so that config, admission and revocation reach this node from where they are authored. An Edge that holds its own truth drifts from the rest of the fleet and reports itself healthy the whole time. If this really is a single-process test harness rather than a deployment, pass -no-control-plane.")
	}
	if usingTheHarnessEscapeHatch(mode, isControlPlane, configSourceURL, configSourceEndpoints, noControlPlane) {
		// Loud on the way past, because a harness flag that leaks into a deployment must be legible in the log
		// of the machine that has the problem, not only in the command line of whoever started it.
		log.Printf("WARNING: -no-control-plane — this Edge has NO control plane and is using local files and flags as its only source of truth. Config, admission and revocation authored on a control plane will NOT reach it. This is a test-harness mode; it is not a deployment.")
	}
}

// controlPlaneRequired reports whether this process must be refused for having no control plane. Split from the
// exiting wrapper so the decision can be tested — a rule enforced by killing the process is otherwise only
// testable by starting one, which is how the control-plane exemption below went missing from the first version.
func controlPlaneRequired(mode string, isControlPlane bool, configSourceURL, configSourceEndpoints string, noControlPlane bool) bool {
	if !isEdgeNeedingAControlPlane(mode, isControlPlane) {
		return false
	}
	return !hasAControlPlane(configSourceURL, configSourceEndpoints) && !noControlPlane
}

// usingTheHarnessEscapeHatch is true only where the escape hatch actually did something, so a control plane or a
// worker that happens to carry the flag does not warn about a rule it was never subject to.
func usingTheHarnessEscapeHatch(mode string, isControlPlane bool, configSourceURL, configSourceEndpoints string, noControlPlane bool) bool {
	return noControlPlane && isEdgeNeedingAControlPlane(mode, isControlPlane) && !hasAControlPlane(configSourceURL, configSourceEndpoints)
}

// isEdgeNeedingAControlPlane separates the processes this rule is about from the ones it is not.
//
// The control plane runs this SAME binary, so the requirement has to exempt the thing it requires — a control
// plane demanding a control plane would refuse to start the only process that could satisfy it, and it would do
// so on its next restart rather than at deploy time. Nothing on the command line used to say which one a
// process was; the difference lived in which stores happened to be wired, which is not a distinction a startup
// check can read, nor one a person reading a compose file should have to infer.
//
// The remaining run modes are batch workers (export, audit publishing, domain events). They enforce nothing and
// steer nothing, so a control plane is not what they are missing. An UNSET mode is treated as an Edge: empty is
// the zero value a caller gets wrong long before it is a worker's deliberate choice.
func isEdgeNeedingAControlPlane(mode string, isControlPlane bool) bool {
	if isControlPlane {
		return false
	}
	m := strings.TrimSpace(mode)
	return m == "" || m == "edge"
}

func hasAControlPlane(configSourceURL, configSourceEndpoints string) bool {
	return strings.TrimSpace(configSourceURL) != "" || strings.TrimSpace(configSourceEndpoints) != ""
}

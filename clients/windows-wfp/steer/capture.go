// Package main (windivert-steer) — the swappable capture layer boundary (W2). The edge-steering layer
// depends ONLY on these types, never on WinDivert, so the capture backend can be replaced by Wintun/WFP
// later with no change above this seam. See.
package main

import (
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

// SteeredFlow is one transparently-captured outbound TCP flow handed up to the edge-steering layer: an
// already-terminated local connection plus the original destination the application intended. The
// consumer reads bytes from Conn and steers them to the edge; it never learns how the flow was captured.
type SteeredFlow struct {
	OrigDst netip.AddrPort
	Conn    net.Conn
	// PID is the owning process id resolved at connect-time (WFP backend; 0 when unknown / other backends). It
	// lets the steerer attribute the flow to the logged-in OS user that owns the process — a PER-FLOW "who" that
	// a shared device's transport cert (the machine identity) cannot provide.
	PID uint32
}

// osUserForPID resolves a process id to the logged-in OS account that owns it ("DOMAIN\\user" or "user"),
// best-effort and FAIL-SAFE: any failure (or an unknown/other-backend PID) yields "" so the flow is never
// attributed to a wrong or guessed user. The real resolver is installed by the Windows build (osuser_windows.go);
// on other platforms it stays this no-op so the cross-platform steer path still compiles. Called off the accept
// path (in the per-flow goroutine) so a slow directory lookup never stalls new connections.
var osUserForPID = func(pid uint32) string { return "" }

// osAppForPID resolves a process id to the originating app identifier (the executable base name, e.g.
// "chrome.exe") — the per-flow "what tool" that pairs with the OS user. Same contract as osUserForPID:
// fail-safe "" on any failure, real resolver installed by the Windows build, resolved in the per-flow goroutine.
var osAppForPID = func(pid uint32) string { return "" }

// noteSteeredPID reports that a flow from this PID is about to be STEERED. It exists so a signature-form
// steer exclusion (signed:/publisher:/subject:/thumbprint:) can be learned from a real flow instead of only
// from a periodic process scan: the WFP kernel backend can only bypass an EXACT image path, userspace has to
// supply it, and a process that starts and exits between two scans is never sampled — which is exactly how
// `signed:winget.exe` was distributed, verified, reported as effective, and silently did nothing (2026-08-06).
// A steered flow is the one moment the process is guaranteed to be alive AND provably interesting, so it is
// the cheapest possible discovery signal.
//
// Contract: fail-safe and NON-BLOCKING. It must never delay or fail a flow — the real implementation resolves
// the image path inline (microseconds) because the process may exit immediately after, but hands the
// Authenticode verification off asynchronously and drops the event rather than block. No-op unless the Windows
// build installs a resolver AND at least one signature-form rule is active.
var noteSteeredPID = func(pid uint32) {}

// deviceConnectHeaders returns the PER-DEVICE signal HTTP header lines (each "Name: value\r\n") to add to the
// steer-mux CONNECT request: device OS + posture (disk encryption, firewall). It is per-connection ≈ per-device
// granularity (NOT per-flow). Fail-safe: any signal that cannot be read is simply omitted (the Edge shows it as
// unknown). The real collector is installed by the Windows build (device_posture_windows.go); other platforms
// keep this no-op so the cross-platform steer path compiles.
var deviceConnectHeaders = func() string { return "" }

// SteeringCapture is the capture backend behind a stable interface. An implementation transparently
// captures outbound TCP, terminates it locally, recovers the original destination, and surfaces each
// flow on Flows(). WinDivert is the current backend; Wintun/WFP can implement the same interface later.
//
// Contract (hardened for durable, supervised operation):
//   - Flows() returns the same channel for the life of the capture; it is closed exactly once, when the
//     capture stops (clean stop via Close/timeout, OR a backend failure). The consumer ranges over it.
//   - After Flows() is closed, Err() reports WHY it stopped: nil for a clean stop (Close/timeout), or the
//     terminal backend error (e.g. the OS capture handle died). A supervisor uses this to distinguish an
//     intentional shutdown from a failure and decide whether to recreate the backend (see superviseCapture).
//   - Close() is idempotent and safe to call concurrently / after a failure; it releases OS resources.
type SteeringCapture interface {
	// Flows yields each captured+terminated flow. It is closed when the capture stops (timeout/Close/fail).
	Flows() <-chan SteeredFlow
	// Backend is a non-secret backend identifier for boundary logs (e.g. "windivert").
	Backend() string
	// Close stops capture and releases OS resources. Idempotent.
	Close() error
	// Err returns the terminal error that stopped the capture, or nil if it stopped cleanly. Only
	// meaningful to read after Flows() has closed. Enables supervised restart for permanent operation.
	Err() error
}

// captureConfig holds the capture-layer parameters (which single destination to steer, and the local
// terminator port). It carries no edge/policy concern -- that lives in edgeConfig.
type captureConfig struct {
	targetIP   [4]byte
	targetPort uint16
	localPort  uint16
	timeout    time.Duration
	// bypassApps are image-path substrings (the Windows AppID analog) whose flows must never be steered
	// (e.g. "automation" to protect the Automation CLI/desktop). The capture also always bypasses the agent
	// itself. This is the steer-all safety primitive: excluded apps keep direct connectivity.
	bypassApps []string
	// bypassDests are destination host:ports never to steer, checked race-free (no process lookup). The
	// edge's own endpoint is auto-added so the agent's connection to the edge can never be steered into
	// an infinite loop -- this is the race-free complement to the AppID self-exclusion. DNS (port 53) and
	// loopback destinations are also never steered (steer-all readiness).
	bypassDests []netip.AddrPort
	// dests, when set, SUPERSEDES bypassDests: it is the same set made live so a late or corrected Edge
	// resolution reaches the running backend. Read it through effectiveDests(), never directly, or a caller
	// silently goes back to the arm-time snapshot -- which is the defect liveDests exists to close.
	dests *liveDests
	// steerAll captures ALL outbound TCP (minus the loopback/DNS/edge/AppID exclusions) instead of a
	// single target. The original destination of each flow is recovered per-flow from conntrack.
	steerAll bool
	// exclusions, when non-nil, is the live merged bypass-app set driven by the admin-managed, server-signed
	// steer-exclusion sync (exclusionSync). The backend reads it via effective() at (re)creation and is
	// registered for live updates; nil => use the static bypassApps baseline only.
	exclusions *liveExclusions
	// selfImage is the agent's own image-path substring (e.g. "dsse-steer.exe"), ALWAYS bypassed so the agent's
	// own outbound connections are never redirected. The WinDivert backend bypasses its selfPath the same way;
	// the WFP backend needs this so a fail-open DIRECT dial (agent -> arbitrary destination) is not redirected
	// back into the local terminator, which would loop the agent into itself and exhaust ephemeral ports
	// (connectex WSAEADDRINUSE). Empty in tests (keeps buildWFPPolicy pure/deterministic).
	selfImage string
	// verifiedExactApps, when non-nil, holds NT device paths (shared, atomically swappable) whose signer
	// identity the app-id resolver verified against a signature exclusion (subject:/thumbprint:/...).
	// buildWFPPolicy serialises them into the driver's exact-APP_ID table so signature rules ENFORCE on the WFP
	// kernel backend (identity owned by userspace, enforced by exact APP_ID in the driver). nil = legacy
	// substring-only behavior.
	verifiedExactApps *atomic.Pointer[[]string]
	// disarmOnAgentExit tells the kernel driver what to do with the redirect policy if THIS process goes away
	// without disarming: clear it (the box reaches the network unsteered) or leave it armed (the box refuses
	// every connection). It is the endpoint's INSTALL-TIME posture — resolved from the signed install profile's
	// fail-open decision — and deliberately not a runtime knob, because "the agent died, so traffic flows" is
	// fail-open by another name and that permission is granted at install and nowhere else.
	//
	// Default false is the conservative direction: an unconfigured build behaves exactly as it did before this
	// existed. A device that is entitled to fail open has to say so.
	disarmOnAgentExit bool
}

func (c captureConfig) targetAddrPort() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(c.targetIP), c.targetPort)
}

// remotePort extracts the TCP port from a net.Addr (the client's ephemeral source port, used as the
// conntrack key to recover the original destination).
func remotePort(a net.Addr) uint16 {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return uint16(tcp.Port)
	}
	_, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return uint16(p)
}

// effectiveDests is the destination bypass set to enforce right now. Every consumer must go through this:
// cfg.bypassDests is the arm-time snapshot and is only the answer on a build with no live set wired.
func (c captureConfig) effectiveDests() []netip.AddrPort {
	if c.dests != nil {
		return c.dests.effective()
	}
	return c.bypassDests
}

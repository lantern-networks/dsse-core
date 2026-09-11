package edgeplane

import (
	"log"
	"sync/atomic"
)

// networkExtensionHotPathLogsEnabled gates the HIGH-VOLUME per-request interception logs (request_observed,
// handshake_completed, http_forward_started/completed, http_response_written, tunnel copy ended, ...). Default
// OFF (quiet): a busy page load (e.g. rakuten.co.jp with dozens of images) otherwise emits ~9 log lines AND
// computes 4 sha256 fingerprints PER subresource, all contending on the global log mutex, pressuring stderr,
// and growing the log unboundedly — measurable overhead under concurrency. Errors/aborts and one-time setup
// logs are NOT gated; they always emit. Enable via -network-extension-runtime-verbose-logs for debugging; tests
// enable it in TestMain so log-asserting tests keep working.
var networkExtensionHotPathLogsEnabled atomic.Bool

// SetNetworkExtensionHotPathLogs toggles the verbose per-request interception logs (default OFF).
func SetNetworkExtensionHotPathLogs(enabled bool) { networkExtensionHotPathLogsEnabled.Store(enabled) }

// NetworkExtensionHotPathLogsOn reports whether the verbose per-request logs are enabled. Call it to guard a
// log site whose ARGUMENTS are expensive (e.g. sha256 fingerprints), so the computation itself is skipped when
// quiet — args to NetworkExtensionHotPathLog are still evaluated eagerly by Go, so cheap-arg sites use the
// helper while expensive-arg sites wrap an explicit `if`.
func NetworkExtensionHotPathLogsOn() bool { return networkExtensionHotPathLogsEnabled.Load() }

// NetworkExtensionHotPathLog emits a verbose per-request log only when enabled. Use ONLY for sites whose
// arguments are cheap to compute (already-resolved values / simple category strings).
func NetworkExtensionHotPathLog(format string, args ...any) {
	if networkExtensionHotPathLogsEnabled.Load() {
		log.Printf(format, args...)
	}
}

// ★★ ONLY THE FAILURE SIDE OF THE TUNNEL LIFECYCLE WAS VISIBLE (2026-08-18, measured while the reference Edge
// was at 94% CPU and its admin port had twice stopped answering).
//
// `docker logs --since 10m` showed 103 lines of tunnel_idle_timeout, 3 of tunnel_started and 0 of
// tunnel_completed. The ratio is not a fact about the deployment: started/completed go through
// NetworkExtensionHotPathLog and are OFF by default, while the reaper's line is an unconditional log.Printf.
// So the one signal an operator can see is the one they cannot put a denominator under — 103 reaps out of how
// many tunnels is the entire question, and the log answers it with silence.
//
// Counting all three fixes that without adding per-flow noise: the reap keeps its line (a reaped flow is worth
// naming), and the population it was reaped from is now a number beside it.
var (
	neTunnelsStarted   atomic.Uint64
	neTunnelsCompleted atomic.Uint64
	neTunnelsReaped    atomic.Uint64
)

// CountNetworkExtensionTunnelStarted records a tunnel entering the bridge.
func CountNetworkExtensionTunnelStarted() { neTunnelsStarted.Add(1) }

// CountNetworkExtensionTunnelCompleted records a tunnel leaving it, however it ended.
func CountNetworkExtensionTunnelCompleted() { neTunnelsCompleted.Add(1) }

// NetworkExtensionTunnelCounts reports started, completed and idle-reaped since start.
//
// started-completed is the live population; a value that climbs under steady load is the shape of the leak
// this file's own comments have been chasing since the 1024-connection ceiling on the macOS extension.
func NetworkExtensionTunnelCounts() (started, completed, reaped uint64) {
	return neTunnelsStarted.Load(), neTunnelsCompleted.Load(), neTunnelsReaped.Load()
}

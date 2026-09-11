package main

import (
	"log"
	"strings"
	"sync/atomic"

	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	"github.com/lantern-networks/dsse-core/edgeplane"
)

// edgelog.go — the minimal level discipline for the OPERATIONAL stderr plane (Plane A), per
//  It is deliberately NOT a logging framework: four levels, one atomic
// current level, thin wrappers over the stdlib logger. The point is a single, cheap gate so the hot-path
// diagnostics stop both spamming stderr AND paying their formatting cost in steady state.
//
// Semantics: a message at level L is emitted when L <= currentLevel. Default currentLevel = INFO, so
// ERROR/WARN/INFO emit and DEBUG does not. Setting the level to DEBUG turns the per-flow diagnostics back on.
//
// Plane B (the structured event stream: access/audit/inspection) is NOT this — it goes through logs.Writer and
// is governed by event_log_design.md. Never route a per-flow fact here; use the flow record.

type logLevel int32

const (
	logLevelError logLevel = iota // 0
	logLevelWarn                  // 1
	logLevelInfo                  // 2 (default)
	logLevelDebug                 // 3
)

// currentLogLevel is the live threshold. Default INFO (2): a healthy edge under load is nearly silent.
var currentLogLevel atomic.Int32

func init() { currentLogLevel.Store(int32(logLevelInfo)) }

// parseLogLevel maps the -log-level flag value to a level; unknown/empty defaults to INFO.
func parseLogLevel(s string) logLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return logLevelError
	case "warn", "warning":
		return logLevelWarn
	case "debug":
		return logLevelDebug
	default:
		return logLevelInfo
	}
}

// setLogLevel publishes the live threshold. Also unifies the pre-existing interception verbose-log gate: DEBUG
// turns those per-request logs on so there is ONE knob, not two.
func setLogLevel(l logLevel) {
	currentLogLevel.Store(int32(l))
	debug := l >= logLevelDebug
	edgeplane.SetNetworkExtensionHotPathLogs(debug) // per-request interception firehose
	dnsresolver.SetDNSQueryLogVerbose(debug)        // per-query DNS log
}

// logDebugEnabled reports whether DEBUG is active. Guard hot-path sites whose ARGUMENTS are expensive
// (fingerprints, map builds, string joins) with `if logDebugEnabled { logDebugf(...) }` so the arguments are
// not even evaluated when quiet — that eager-evaluation cost, not the byte volume, is what the incident surfaced.
func logDebugEnabled() bool { return logLevel(currentLogLevel.Load()) >= logLevelDebug }

func logDebugf(format string, args ...any) {
	if logLevel(currentLogLevel.Load()) >= logLevelDebug {
		log.Printf("DEBUG "+format, args...)
	}
}

func logInfof(format string, args ...any) {
	if logLevel(currentLogLevel.Load()) >= logLevelInfo {
		log.Printf("INFO "+format, args...)
	}
}

func logWarnf(format string, args ...any) {
	if logLevel(currentLogLevel.Load()) >= logLevelWarn {
		log.Printf("WARN "+format, args...)
	}
}

// logErrorf always emits (ERROR is the lowest threshold).
func logErrorf(format string, args ...any) {
	log.Printf("ERROR "+format, args...)
}

// Install the edge logger into the extracted data-plane package (its default is a
// no-op). Done in an init so every entrypoint — server, tests, run modes — gets it.
func init() {
	edgeplane.Debugf = logDebugf
	edgeplane.Warnf = logWarnf
	edgeplane.Infof = logInfof
	edgeplane.Errorf = logErrorf
}

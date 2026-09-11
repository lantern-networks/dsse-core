package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]logLevel{
		"error": logLevelError, "warn": logLevelWarn, "warning": logLevelWarn,
		"info": logLevelInfo, "debug": logLevelDebug,
		"": logLevelInfo, "bogus": logLevelInfo, "  DEBUG  ": logLevelDebug,
	}
	for in, want := range cases {
		if got := parseLogLevel(in); got != want {
			t.Errorf("parseLogLevel(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestLogLevelGate(t *testing.T) {
	prev := logLevel(currentLogLevel.Load())
	defer setLogLevel(prev)

	// Default INFO: debug is off, and the interception verbose gate is off with it.
	setLogLevel(logLevelInfo)
	if logDebugEnabled() {
		t.Fatal("debug must be OFF at INFO")
	}
	if edgeplane.NetworkExtensionHotPathLogsOn() {
		t.Fatal("interception verbose logs must be OFF at INFO")
	}

	// DEBUG turns both on via the single knob.
	setLogLevel(logLevelDebug)
	if !logDebugEnabled() {
		t.Fatal("debug must be ON at DEBUG")
	}
	if !edgeplane.NetworkExtensionHotPathLogsOn() {
		t.Fatal("DEBUG must also enable the interception verbose logs (one knob)")
	}

	// WARN is below INFO: debug still off.
	setLogLevel(logLevelWarn)
	if logDebugEnabled() {
		t.Fatal("debug must be OFF at WARN")
	}
}

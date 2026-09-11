package main

// device_runtime_fleet.go — the bounds of the fleet history read, and the helpers that read a shipped row.
//
// The merge itself moved to device_runtime_projection.go on 2026-08-14: it used to run this query on EVERY
// Console load, which stopped being affordable the day a steering device began re-shipping its state once a
// minute. What is left here is the query the projection is SEEDED from, once, at startup — the same bounds,
// run a few orders of magnitude less often.

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// fleetDeviceRuntimeLookback is how far back to read shipped device-state changes.
//
// Long, because these are CHANGE events: a device that has been steering steadily through another Edge for six
// hours emitted its last event when it started. Too short a window and the fleet view forgets exactly the
// devices that are behaving.
const fleetDeviceRuntimeLookback = 48 * time.Hour

// stringsFromRow reads a []any of strings out of a shipped row.
func stringsFromRow(row map[string]any, key string) []string {
	raw, ok := row[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s := strings.TrimSpace(fmt.Sprint(v)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// fleetDeviceRuntimeQuery asks for every device-state change in the lookback, newest first.
func fleetDeviceRuntimeQuery(now time.Time) url.Values {
	q := url.Values{}
	q.Set("limit", "2000")
	q.Set("from", now.Add(-fleetDeviceRuntimeLookback).UTC().Format(time.RFC3339))
	return q
}

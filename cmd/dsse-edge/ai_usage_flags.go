package main

import "flag"

// AI-usage report tunables. A SIBLING file, not main.go: the Phase 0 ratchet
//
//	freezes main.go's flag count, so a new flag lands
//
// next to the feature it belongs to instead of growing the file the split exists to shrink.
//
// Register before flag.Parse, apply after — the returned closure is what carries the parsed value back, so the
// flag's name, its default, and the variable it drives all stay in one place.
func registerAIUsageReportFlags() func() {
	rowCap := flag.Int("ai-usage-row-cap", aiUsageReportRowCap, "rows the AI usage report may load per request. Hitting it reports a SHORTER span than asked for — the response says so (coverage.truncated), and lowering this is how that path is exercised on a live edge.")
	maxWindow := flag.Duration("ai-usage-max-window", reportMaxWindow, "furthest back a report request may ask. A longer ask is refused, never clamped. A COST bound, not a truth bound — how far records actually reach is reported as coverage.retained_from. Raise it on a deployment that retains longer than the 30d access-log default.")
	aggregate := flag.Bool("ai-usage-aggregate", aiUsageAggregateEnabled, "let the hot store GROUP BY for the AI usage report when it can (Postgres), instead of loading rows and grouping in Go. Both paths run the same aggregation, and the response says which one answered (coverage.source). Set false to force row-loading if a number ever looks wrong.")
	return func() {
		if *rowCap > 0 {
			aiUsageReportRowCap = *rowCap
		}
		aiUsageAggregateEnabled = *aggregate
		if *maxWindow > 0 {
			reportMaxWindow = *maxWindow
		}
	}
}

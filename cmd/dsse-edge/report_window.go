package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The time window a report is built over, resolved from the request in ONE place. Two admin reports (the AI
// usage report and the AI-ops access trends) offer the operator the same 24h/7d/30d control, and the Console
// renders both with the same helper — so what "7d" means has to be decided once. It was decided in neither
// before: one endpoint hardcoded a constant, the other accepted ?window= and ignored it.

// reportDefaultWindow is the DEFAULT window when the caller names none, not the only one — see
// resolveReportWindow. It bounds the read so the growing Postgres access table is not fully scanned on every
// load. The raw rows persist beyond this for arbitrary historical graphing.
const reportDefaultWindow = 7 * 24 * time.Hour

// reportMaxWindow is the furthest back a caller may ask. Beyond it is a 400, NOT a clamp: a silently clamped
// window is the same lie as the undeclared fixed window this replaced.
//
// It is a COST guard, not a truth guard, and the distinction decides its default. Truth is handled elsewhere now:
// coverage.retained_from states how far the records actually reach, so a window longer than the data gets an
// honest answer rather than an error. What this bounds is how much a single request may scan. The default is 30d
// because that is the -hot-events-retention default for the access stream; a deployment that retains longer can
// raise it with -ai-usage-max-window.
//
// Deliberately NOT read from the retention config: retention is per-stream and admin-overridable at runtime, so
// wiring it here would make whether a report is ACCEPTED depend on a store that can change between two
// identical requests — and would buy nothing that retained_from does not already say.
var reportMaxWindow = 30 * 24 * time.Hour

// reportWindowPresets is a whitelist, not a duration parser: the values match the Console's period control, and
// time.ParseDuration cannot express "7d" regardless. An unrecognised preset is an error, never a fallback to the
// default — silently ignoring a window parameter is exactly the defect this work exists to remove.
var reportWindowPresets = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// resolveReportWindow turns the request's query into the concrete [from, to) the report is built over.
// Precedence: an absolute from/to range wins; else a named preset; else the default window — so a caller that
// passes nothing gets exactly the behaviour that predates the parameters. Pure over (query, now) so the
// precedence and the rejections are unit-testable without a server.
func resolveReportWindow(query url.Values, now time.Time) (from, to time.Time, requested string, err error) {
	rawFrom := strings.TrimSpace(query.Get("from"))
	rawTo := strings.TrimSpace(query.Get("to"))
	rawWindow := strings.TrimSpace(query.Get("window"))
	switch {
	case rawFrom != "" || rawTo != "":
		if rawWindow != "" {
			return time.Time{}, time.Time{}, "", fmt.Errorf("pass either window or from/to, not both")
		}
		parsedFrom, parsedTo, parseErr := adminLogTimeRange(query)
		if parseErr != nil {
			return time.Time{}, time.Time{}, "", parseErr
		}
		to = now
		if parsedTo != nil {
			to = *parsedTo
		}
		from = to.Add(-reportDefaultWindow)
		if parsedFrom != nil {
			from = *parsedFrom
		}
		requested = "custom"
	case rawWindow != "":
		span, ok := reportWindowPresets[rawWindow]
		if !ok {
			return time.Time{}, time.Time{}, "", fmt.Errorf("unknown window %q (want one of %s)", rawWindow, strings.Join(sortedReportWindowPresets(), ", "))
		}
		to, from, requested = now, now.Add(-span), rawWindow
	default:
		to, from, requested = now, now.Add(-reportDefaultWindow), "7d"
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, "", fmt.Errorf("from (%s) must be before to (%s)", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	}
	if to.Sub(from) > reportMaxWindow {
		return time.Time{}, time.Time{}, "", fmt.Errorf("window %s exceeds the %s maximum", to.Sub(from), reportMaxWindow)
	}
	return from.UTC(), to.UTC(), requested, nil
}

func sortedReportWindowPresets() []string {
	presets := make([]string, 0, len(reportWindowPresets))
	for name := range reportWindowPresets {
		presets = append(presets, name)
	}
	sort.Strings(presets)
	return presets
}

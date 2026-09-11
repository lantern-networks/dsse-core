package main

import "testing"

// ★ THE GUARD FOR A MEASURED FACT. win-dev-1, 2026-08-10: a source registered with InstallAsEventCreate points
// EventMessageFile at EventCreate.exe, whose message table covers 1..1001. Probes at 101-108 rendered in full;
// 1002-1008 came back as "The description for Event ID ... cannot be found" with the text attached as an
// insert string, and 1001 rendered because it is the last entry in the table.
//
// Every ID here was 10xx/20xx before that measurement. The failure it caused is worth naming, because it is
// the reason a test guards a constant: nothing is LOST above the range — EventData always carries the full
// sentence — so a collector reading EventData sees no problem at all, while one reading the rendered Message
// gets clean text for some IDs and a wrapper for others. Inconsistent is worse than uniformly missing, because
// it looks like it works.
//
// So the next person adding an event to dsse-watchdog gets a failing test rather than a silently unreadable event.
func TestEveryEventIDIsInTheRangeWindowsCanRender(t *testing.T) {
	seen := map[uint32]string{}
	for name, id := range map[string]uint32{
		"evtRecovered":       evtRecovered,
		"evtRecoverFail":     evtRecoverFail,
		"evtRateLimited":     evtRateLimited,
		"evtReportOnly":      evtReportOnly,
		"evtStarted":         evtStarted,
		"evtCannotRecover":   evtCannotRecover,
		"evtSteeringResumed": evtSteeringResumed,
		"evtCleared":         evtCleared,
	} {
		if id == 0 {
			t.Errorf("%s is 0; event ID 0 is not usable", name)
		}
		if id > maxRenderableEventID {
			t.Errorf("%s = %d, above the renderable maximum of %d — its text will arrive as a "+
				"\"description cannot be found\" wrapper while EventData still carries it, so nothing will look broken",
				name, id, maxRenderableEventID)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s share ID %d; a collector cannot tell them apart", name, prev, id)
		}
		seen[id] = name
	}
}

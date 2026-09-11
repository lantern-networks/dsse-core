package main

// events.go — the event IDs, and the range they are allowed to live in.
//
// Deliberately NOT build-tagged, though only Windows writes events. The rule below is a decision with a
// measurement behind it, and a decision that can only be checked on the machine it was measured on is one
// nobody checks again. The guard test beside this file runs on any host.

// eventSource is the name registered in the Windows event log. Event IDs are stable so a collector can match
// on them without parsing text.
const eventSource = "DsseWatchdog"

// ★ THE RANGE IS 1–1000 AND THAT IS MEASURED, NOT CHOSEN. See maxRenderableEventID below.
const (
	evtRecovered   = 101 // a box was black-holed or DNS-orphaned and this process fixed it
	evtRecoverFail = 102 // it tried and could not — the box is still broken
	evtRateLimited = 103 // it refused to try again; the box may still be broken
	evtReportOnly  = 104 // something is wrong that this process must not touch
	evtStarted     = 105 // service start, so "no events" can be told from "not running"
	// evtCannotRecover: the box needs recovering and this process cannot do it. Its own ID, because it is the
	// one event that requires a human — filing it under evtReportOnly ("wrong, but nothing is expected to
	// happen") would tell a collector the opposite of the truth.
	evtCannotRecover = 106
	// evtSteeringResumed: recovery ran and the agent came back inside the window, so the driver is armed again
	// WITH a listener behind it. Its own ID because it is neither of the two events it would otherwise be filed
	// under, and both of those would be false: it is not evtRecoverFail (nothing failed) and it is not
	// evtRecovered (whose text promises an UNSTEERED, unenforced box). Measured on win-dev-1, where DsseSteer's
	// RESTART/5000 beat a 5.4 s recovery and a successful run was reported as an error.
	evtSteeringResumed = 107
	// evtCleared: a condition previously reported has gone away. Without it a collector that saw a report_only
	// or cannot_recover alert has no way to learn it resolved, because the throttle deliberately stops
	// repeating the alert — silence would otherwise mean both "still broken" and "fixed".
	evtCleared = 108
)

// maxRenderableEventID is the largest ID whose text Windows will RENDER for this source.
//
// Measured on win-dev-1, 2026-08-10, rather than reasoned about. The source registers with
// eventlog.InstallAsEventCreate, which points EventMessageFile at %SystemRoot%\System32\EventCreate.exe, and
// that binary's message table covers 1..1001. The probe found 101–108 rendering in full, 1002–1008 producing
// "The description for Event ID ... cannot be found" with the text attached as an insert string — and 1001
// rendering, which is not an anomaly but the last entry in the table.
//
// 1000 rather than 1001 because a limit that happens to be the last valid value invites someone to use it.
//
// Nothing is LOST above the limit — the full sentence is always in EventData/ReplacementStrings, so a
// collector reading that is unaffected. What breaks is the rendered Message column, and inconsistently: clean
// text for some IDs and a wrapper for others is worse than uniformly missing, because it looks like it works.
const maxRenderableEventID = 1000

// ★ THE RENDERED-DESCRIPTION GAP IS CLOSED, by measurement rather than by a message-resource DLL.
//
// The IDs above used to be 10xx and only 1001 rendered. The probe below settled why: EventCreate.exe's message
// table covers 1..1001, so the fix was renumbering and no native build step was needed. Every ID is now inside
// the range and a test asserts it stays there — see maxRenderableEventID.
//
// The IDs CHANGED, which is a thing a collector matches on. It was free to do now because nothing consumes
// them yet, and it would not have been free later; that is the whole reason it was worth measuring before
// something started depending on the wrong numbers.
//
// Messages still begin with a self-describing sentence. That was insurance against the wrapper form and it
// costs nothing to keep: it is also what makes an event readable in a collector that shows only the first line.

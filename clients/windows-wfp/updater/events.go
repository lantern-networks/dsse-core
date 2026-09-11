package main

// events.go — the event IDs, and the range they are allowed to live in. Not build-tagged for the same reason
// the watchdog's is not: the range is a measured decision, and one that can only be checked on Windows is one
// that stops being checked.

const eventSource = "DsseUpdater"

// Event IDs. A separate block from the watchdog's 1xx so a collector can tell the two components apart without
// parsing the source name, and stable so it can match on them at all.
//
// ★ INSIDE 1–1000, which is measured rather than chosen: this source registers with InstallAsEventCreate, so
// its EventMessageFile is EventCreate.exe, whose message table covers 1..1001. Above that the text still
// arrives in EventData but the rendered Message is a "description cannot be found" wrapper — clean for some
// IDs and wrapped for others, which is worse than uniformly missing because it looks like it works. The
// watchdog measured the boundary on win-dev-1 on 2026-08-10 and this block was renumbered from 20xx with it,
// in one change, so the two components never disagree about which space is renderable.
const (
	evtStarted         = 201 // service start, so "no events" can be told from "not running"
	evtProgress        = 202 // a state change worth recording that is not one of the below
	evtExecuting       = 203 // an installer has been launched; this device may restart its agent at any moment
	evtRefused         = 204 // an update was declined for a stated reason (un-rollbackable, poisoned, disarm failed)
	evtRefusedManifest = 205 // ★ a manifest was REFUSED by verification. Either a broken release or a substitution.
	evtStageFailed     = 206 // the device was told to update and could not obtain the bytes
	evtInterrupted     = 207 // a previous attempt stopped half way; this device's NETWORK may need checking
	evtBlocked         = 208 // nothing can be attempted (unreadable journal, unkeepable record)
	evtCleared         = 209 // a previously reported condition has gone away
)

// maxRenderableEventID is the largest ID Windows will render the text of for a source registered with
// InstallAsEventCreate. Measured on win-dev-1, 2026-08-10: EventCreate.exe's message table covers 1..1001.
// 1000 rather than 1001, because a limit that is also the last valid value invites someone to use it.
const maxRenderableEventID = 1000

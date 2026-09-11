// sessions.go — the rules for turning per-session readings into "is a person at this machine".
//
// Split out of session_windows.go and deliberately NOT build-tagged, for the reason this package already
// applies everywhere else: the syscalls cannot be exercised off Windows, but the DECISIONS can, and these
// decide whether a machine gets an installer run on it while somebody is working. They were behind
// //go:build windows with no test on any host, and the two defects below are exactly what a table test finds.
package updateplatform

import "time"

// Terminal-services connection states, from WTS_CONNECTSTATE_CLASS. Named here rather than taken from
// x/sys/windows so this file stays compilable on any host.
const (
	stateActive       = 0
	stateConnected    = 1
	stateConnectQuery = 2
	stateShadow       = 3
	stateDisconnected = 4
	stateIdle         = 5
	stateListen       = 6
	stateReset        = 7
	stateDown         = 8
	stateInit         = 9
)

// isInteractiveSessionState reports whether a session could have a person attached to it.
//
// ★ This is the guard whose absence is a silent failure. observeSessions treats a session it cannot query as
// making the WHOLE device unknown — correctly, because a session that will not answer is exactly the one that
// might have someone at it. But that rule was applied to every session the enumeration returned, and most
// machines have sessions that are not people at all: the RDP-Tcp listener, an initialising or resetting slot.
// If any of those declines to answer WTSQuerySessionInformation, the device reports "cannot tell whether
// anyone is using this" forever — and a plan with RequireUnattended then holds that device until its deadline,
// or indefinitely when there is no deadline.
//
// The failure is invisible: the device looks like one that is simply always in use. Nothing distinguishes it
// from a busy machine, and the state it is stuck in is the safe-looking one.
//
// WTS_SESSION_INFO already carries the state, from the enumeration that found the session, so the filter costs
// nothing. Not observed on win-dev-1 — every session there answered — which is why it is worth guarding rather
// than waiting for the box where it does not.
func isInteractiveSessionState(state uint32) bool {
	switch state {
	case stateActive, stateConnected, stateConnectQuery, stateShadow, stateDisconnected, stateIdle:
		return true
	case stateListen, stateReset, stateDown, stateInit:
		// A listener is a door, not a person. Reset/Down/Init are slots mid-transition with nobody in them.
		return false
	default:
		// An unrecognised state is treated as interactive on purpose: the expensive mistake is deciding nobody
		// is present, and a state this code has not heard of is not evidence of absence.
		return true
	}
}

// sessionReading is what one interactive session reports about itself.
type sessionReading struct {
	SessionID uint32
	User      string
	State     uint32
	// Locked is meaningful only when LockKnown is true.
	Locked    bool
	LockKnown bool
	// IdleFor comes from the session's own LastInputTime. IdleKnown is false when the field is zero or the
	// arithmetic is not sane — it is documented as not maintained on every configuration, and a fabricated
	// idle time updates machines while someone is using them.
	IdleFor   time.Duration
	IdleKnown bool
}

// inUse is this session's answer to "is a person at this machine". A locked session is not in use; an
// unlocked, connected session is.
func (s sessionReading) inUse() (bool, bool) {
	if s.LockKnown && s.Locked {
		return false, true
	}
	if s.State == stateDisconnected {
		// The session exists but nothing is attached to it.
		return false, true
	}
	if s.LockKnown && !s.Locked {
		return true, true
	}
	return false, false
}

// foldInUse combines the per-session answers into one for the device.
//
// In use if ANY interactive session is in use — the machine belongs to whoever is on it, and a second locked
// session does not make the first one's user less present. Unknown if any session could not say, because the
// one that could not say is the one that might have someone at it. No sessions with a user at all is a
// definite "not in use": nobody is logged on.
func foldInUse(readings []sessionReading) (inUse bool, known bool) {
	if len(readings) == 0 {
		return false, true
	}
	anyUnknown := false
	for _, r := range readings {
		used, k := r.inUse()
		if !k {
			anyUnknown = true
			continue
		}
		if used {
			return true, true
		}
	}
	if anyUnknown {
		return false, false
	}
	return false, true
}

// foldIdle returns the shortest idle time across the sessions — the most recent input anywhere on the machine.
//
// ★ The no-sessions case is UNKNOWN, and it is worth being explicit that this is a decision rather than a
// consequence of an empty loop. A machine nobody is logged on to has had no input to measure, so there is no
// honest duration to report — and the alternative, inventing "idle forever", would be this file fabricating
// the one value it exists to refuse to fabricate.
//
// The cost is real and asymmetric with foldInUse, which calls the same machine a definite "not in use": a plan
// written in RequireIdleMinutes holds the emptiest possible box, which is the most updatable one there is. That
// is a reason to express the intent as RequireUnattended — which answers correctly here — and not a reason to
// guess a number. On Windows it is currently moot for a second reason: LastInputTime comes back zero for the
// console session, so idle is unknown on those boxes regardless.
func foldIdle(readings []sessionReading) (time.Duration, bool) {
	if len(readings) == 0 {
		return 0, false
	}
	shortest := time.Duration(1<<63 - 1)
	for _, r := range readings {
		if !r.IdleKnown {
			// The session that cannot report is the one that might have someone at it.
			return 0, false
		}
		if r.IdleFor < shortest {
			shortest = r.IdleFor
		}
	}
	return shortest, true
}

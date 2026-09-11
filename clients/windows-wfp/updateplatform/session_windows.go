//go:build windows

// session_windows.go — is a person using this machine?
//
// GetLastInputInfo cannot answer it from a service: it reports input for the CALLING session, and a service
// lives in session 0, so it returns "idle forever" no matter who is typing. That is the whole reason
// Conditions used to report IdleKnown=false, which in turn made any rollout plan carrying RequireIdleMinutes
// unsatisfiable on a service-hosted updater.
//
// The terminal-services API answers it from outside the session, which is what this file uses.
// WTSQuerySessionInformation with WTSSessionInfoEx returns, per session, both the LOCK state and the
// session's own LastInputTime — so an unattended box is recognisable without a component in the user's
// session.
//
// WHY LOCK MATTERS AS MUCH AS IDLE. An unlocked session idle for thirty minutes may be someone reading, or
// watching, or presenting. A locked one means the person deliberately walked away, and an auto-lock implies
// the machine was already idle for the lock timeout before it happened. Lock is the better proxy for the
// thing RequireIdleMinutes is actually trying to express, so it is observed and reported rather than being
// collapsed into a duration.
package updateplatform

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32               = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInf = wtsapi32.NewProc("WTSQuerySessionInformationW")
)

const (
	wtsCurrentServerHandle = 0
	wtsSessionInfoEx       = 25

	// SessionFlags values. UNKNOWN is what a session that cannot say reports, and it is passed through as an
	// unknown rather than assumed unlocked.
	wtsSessionStateUnknown = 0xFFFFFFFF
	wtsSessionStateLock    = 0
	wtsSessionStateUnlock  = 1
)

// wtsInfoExLevel1 mirrors WTSINFOEX_LEVEL1_W. The array sizes are the WINSTATIONNAME_LENGTH (32),
// USERNAME_LENGTH (20) and DOMAIN_LENGTH (17) constants plus their terminators; they are load-bearing,
// because every field after them is read at an offset these sizes determine. A wrong size here does not fail
// loudly — it yields plausible garbage — which is why the diagnostic below prints the user name: a name that
// reads correctly is evidence the later timestamps are being read from the right place.
type wtsInfoExLevel1 struct {
	SessionID               uint32
	SessionState            int32
	SessionFlags            int32
	WinStationName          [33]uint16
	UserName                [21]uint16
	DomainName              [18]uint16
	LogonTime               int64
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	CurrentTime             int64
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
}

// wtsInfoEx mirrors WTSINFOEXW. The explicit pad is the union's 8-byte alignment made visible rather than
// left to chance.
type wtsInfoEx struct {
	Level uint32
	_     uint32
	Data  wtsInfoExLevel1
}

// observeSessions enumerates the interactive sessions and asks each one about itself.
//
// Every failure yields known=false rather than a guess, and the guess that would be made — "nobody is here" —
// is the dangerous one: it updates a machine somebody is working on.
func observeSessions() (readings []sessionReading, known bool) {
	var raw *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServerHandle, 0, 1, &raw, &count); err != nil {
		return nil, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(raw)))

	list := unsafe.Slice(raw, count)
	for _, s := range list {
		// Session 0 is the services session: it has no interactive user by design (Session 0 Isolation), and
		// counting it would make every box look occupied or unoccupied for the wrong reason.
		if s.SessionID == 0 {
			continue
		}
		// Filtered BEFORE querying, using the state the enumeration already handed over. A listener or a slot
		// mid-transition is not a person, and letting one that declines to answer make the whole device unknown
		// is a silent way to stop updating it — see isInteractiveSessionState.
		if !isInteractiveSessionState(s.State) {
			continue
		}
		r, ok := querySession(s.SessionID)
		if !ok {
			// One unreadable session makes the whole answer unknown. A partial view would let a machine with
			// one readable idle session and one unreadable busy session read as free.
			return nil, false
		}
		// Sessions with no user are listening station slots, not people.
		if r.User == "" {
			continue
		}
		readings = append(readings, r)
	}
	return readings, true
}

func querySession(id uint32) (sessionReading, bool) {
	var buf *wtsInfoEx
	var n uint32
	r, _, _ := procWTSQuerySessionInf.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(id),
		uintptr(wtsSessionInfoEx),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 || buf == nil {
		return sessionReading{}, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if buf.Level != 1 || n < uint32(unsafe.Sizeof(wtsInfoEx{})) {
		return sessionReading{}, false
	}
	d := buf.Data

	out := sessionReading{
		SessionID: d.SessionID,
		User:      windows.UTF16ToString(d.UserName[:]),
		State:     uint32(d.SessionState),
	}
	switch uint32(d.SessionFlags) {
	case wtsSessionStateLock:
		out.Locked, out.LockKnown = true, true
	case wtsSessionStateUnlock:
		out.Locked, out.LockKnown = false, true
	case wtsSessionStateUnknown:
		// Left unknown deliberately.
	}
	// LastInputTime and CurrentTime are FILETIMEs. A zero LastInputTime means the field is not being
	// maintained for this session, which is a documented possibility and not an error.
	if d.LastInputTime > 0 && d.CurrentTime > d.LastInputTime {
		out.IdleFor = time.Duration(d.CurrentTime-d.LastInputTime) * 100 * time.Nanosecond
		out.IdleKnown = true
	}
	return out, true
}

// observeDevice reads the sessions ONCE and answers both questions from that one reading.
//
// One enumeration rather than two, and the reason is not the round trip. deviceIdle and deviceInUse used to
// enumerate separately, so a session locking between the two calls produced a pair of answers describing two
// different moments — the same "two answers to one question" this package extracted runstate.Live() to avoid.
func observeDevice() (idle time.Duration, idleKnown bool, inUse bool, inUseKnown bool) {
	readings, ok := observeSessions()
	if !ok {
		return 0, false, false, false
	}
	idle, idleKnown = foldIdle(readings)
	inUse, inUseKnown = foldInUse(readings)
	return idle, idleKnown, inUse, inUseKnown
}

// DescribeSessions is a human-readable snapshot, for the question an operator asks when a device is not
// updating: who is on this machine and why does it count as busy?
//
// It is exported because "the rollout is stalled" is diagnosed from the endpoint, and a number with no
// explanation sends people to the wrong place.
func DescribeSessions() string {
	readings, ok := observeSessions()
	if !ok {
		return "sessions: could not be enumerated, so it is unknown whether anyone is using this device"
	}
	if len(readings) == 0 {
		return "sessions: none with a logged-on user — nobody is using this device"
	}
	var b strings.Builder
	for i, r := range readings {
		if i > 0 {
			b.WriteString("; ")
		}
		lock := "lock=unknown"
		if r.LockKnown {
			if r.Locked {
				lock = "locked"
			} else {
				lock = "unlocked"
			}
		}
		idle := "idle=unknown"
		if r.IdleKnown {
			idle = "idle=" + r.IdleFor.Round(time.Second).String()
		}
		fmt.Fprintf(&b, "session %d user=%q state=%d %s %s", r.SessionID, r.User, r.State, lock, idle)
	}
	return "sessions: " + b.String()
}

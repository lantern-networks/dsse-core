package updateplatform

import (
	"testing"
	"time"
)

// These rules decide whether an installer runs on a machine somebody is working on, and until now they lived
// behind //go:build windows with no test on any host. Everything here runs everywhere.

func locked(id uint32) sessionReading {
	return sessionReading{SessionID: id, User: "someone", State: stateActive, Locked: true, LockKnown: true}
}

func unlocked(id uint32) sessionReading {
	return sessionReading{SessionID: id, User: "someone", State: stateActive, LockKnown: true}
}

func lockUnreadable(id uint32) sessionReading {
	return sessionReading{SessionID: id, User: "someone", State: stateActive}
}

func TestOneSessionsAnswer(t *testing.T) {
	cases := []struct {
		name       string
		in         sessionReading
		want       bool
		wantKnown  bool
		wantReason string
	}{
		{"locked is nobody to interrupt", locked(1), false, true, ""},
		{"unlocked and active is someone", unlocked(1), true, true, ""},
		{"disconnected has nothing attached", sessionReading{State: stateDisconnected, LockKnown: true}, false, true, ""},
		{"lock state unreadable is unknown, never 'nobody'", lockUnreadable(1), false, false, ""},
	}
	for _, c := range cases {
		got, known := c.in.inUse()
		if got != c.want || known != c.wantKnown {
			t.Errorf("%s: inUse = (%v, %v), want (%v, %v)", c.name, got, known, c.want, c.wantKnown)
		}
	}
}

// The machine belongs to whoever is on it: one active user outweighs any number of locked sessions.
func TestAnyActiveUserMakesTheDeviceInUse(t *testing.T) {
	if used, known := foldInUse([]sessionReading{locked(1), locked(2), unlocked(3)}); !used || !known {
		t.Fatalf("foldInUse = (%v, %v), want (true, true)", used, known)
	}
}

// ★ An unreadable session must poison the answer rather than be skipped: it is exactly the one that might
// have somebody at it. This is the direction that costs updates rather than interrupting people.
func TestOneUnreadableSessionMakesTheDeviceUnknown(t *testing.T) {
	used, known := foldInUse([]sessionReading{locked(1), lockUnreadable(2)})
	if known {
		t.Fatalf("foldInUse = (%v, %v); a session that could not say must not be counted as absent", used, known)
	}
}

// Nobody logged on is a definite answer, not an unknown: there is nobody to interrupt.
func TestNobodyLoggedOnIsDefinitelyNotInUse(t *testing.T) {
	used, known := foldInUse(nil)
	if used || !known {
		t.Fatalf("foldInUse(nil) = (%v, %v), want (false, true)", used, known)
	}
}

func TestIdleIsTheMostRecentInputAnywhere(t *testing.T) {
	got, known := foldIdle([]sessionReading{
		{IdleFor: 40 * time.Minute, IdleKnown: true},
		{IdleFor: 3 * time.Minute, IdleKnown: true},
	})
	if !known || got != 3*time.Minute {
		t.Fatalf("foldIdle = (%v, %v), want (3m, true)", got, known)
	}
}

func TestOneSessionThatCannotReportIdleMakesIdleUnknown(t *testing.T) {
	if _, known := foldIdle([]sessionReading{{IdleFor: time.Hour, IdleKnown: true}, {}}); known {
		t.Fatal("a device reported an idle time while one of its sessions could not measure one")
	}
}

// The asymmetry with foldInUse, pinned so it is a decision rather than a surprise: nobody logged on is a
// definite "not in use" and an UNKNOWN idle. There is no input to measure, and inventing "idle forever" would
// be this code fabricating the one value it exists to refuse to fabricate — at the cost that a plan written in
// RequireIdleMinutes holds the emptiest box on the fleet.
func TestNobodyLoggedOnLeavesIdleUnknown(t *testing.T) {
	got, known := foldIdle(nil)
	if known {
		t.Fatalf("foldIdle(nil) = (%v, %v); an invented duration is worse than an admitted unknown", got, known)
	}
	if _, inUseKnown := foldInUse(nil); !inUseKnown {
		t.Fatal("the sibling answer must stay definite; if both are unknown, RequireUnattended stops working too")
	}
}

// ★ The silent one. A session that is not a person — an RDP listener, a slot mid-transition — must not be
// queried, because a query that fails there makes the whole device unknown and a device that is permanently
// unknown is one that silently never updates. It reads as a machine that is always busy.
func TestNonInteractiveSessionsAreNotTreatedAsPeople(t *testing.T) {
	for _, state := range []uint32{stateListen, stateReset, stateDown, stateInit} {
		if isInteractiveSessionState(state) {
			t.Errorf("state %d was treated as a session that could have a person in it", state)
		}
	}
	for _, state := range []uint32{stateActive, stateConnected, stateConnectQuery, stateShadow, stateDisconnected, stateIdle} {
		if !isInteractiveSessionState(state) {
			t.Errorf("state %d was skipped; a session with a person in it must never be filtered out", state)
		}
	}
}

// An unrecognised state leans the safe way. Deciding nobody is present is the expensive mistake, and a state
// this code has not heard of is not evidence of absence.
func TestAnUnknownSessionStateIsTreatedAsPossiblyOccupied(t *testing.T) {
	if !isInteractiveSessionState(9999) {
		t.Fatal("an unrecognised session state was assumed empty")
	}
}

package main

import (
	"errors"
	"testing"
	"time"
)

// ★★★ THE DOOR THE OPERATOR LISTED FIRST IS THE ONE A CONNECTOR SITS ON, AND IT WAS THE ONE IT COULD NOT
// LEAVE (2026-09-02, measured on a real deployment: three minutes into a blackhole of its region, with two
// live doors in its own list, the connector was still dialling the dead one).
//
// resetToPreferred() sets the index to 0 and does nothing when it is already 0. A tunnel that held longer than
// connectorFailbackAfter took that branch, so the failure was consumed and advance() was never reached — and
// in steady state a tunnel always holds longer than that. Region failover therefore worked only for a
// connector that had ALREADY failed over once.
func TestAConnectorLeavesItsPreferredDoorWhenThatDoorDies(t *testing.T) {
	doors := parseConnectorEndpoints("osaka=https://agents.osaka.example;tokyo=https://agents.tokyo.example")
	if !doors.atPreferred() {
		t.Fatal("a fresh connector starts on the door the operator listed first")
	}

	// The shape that was measured: it held for a long time, then the region went away.
	held := 4 * time.Hour
	if held >= connectorFailbackAfter && !doors.atPreferred() {
		doors.resetToPreferred()
	} else {
		doors.advance(errors.New("i/o timeout"))
	}

	if doors.atPreferred() {
		t.Fatal("the connector stayed on the door that had just died, which is what the outage measured: " +
			"every private application behind it stays unreachable while two live doors sit in its list")
	}

	// And the other half of the rule still holds: away from home, a tunnel that held sends it home.
	held = 4 * time.Hour
	if held >= connectorFailbackAfter && !doors.atPreferred() {
		doors.resetToPreferred()
	} else {
		doors.advance(errors.New("ordinary close"))
	}
	if !doors.atPreferred() {
		t.Fatal("a connector that failed over must come home once the door it prefers proves good again")
	}
}

// ★★★ THE CONNECTOR DECIDED TO GO HOME EVERY THREE MINUTES AND RECONNECTED TO THE REGION IT WAS LEAVING
// (2026-09-02, measured after the region came back). Going home ends the tunnel; the tunnel-end handler saw a
// connection that had not held for a minute — because it had just been moved — and advanced, putting it
// straight back. The log said "returning to osaka" and two seconds later "tunnel connected to tokyo-east",
// three times over, and neither line is wrong on its own.
func TestGoingHomeIsNotEvidenceAgainstHome(t *testing.T) {
	doors := parseConnectorEndpoints("osaka=https://agents.osaka.example;tokyo=https://agents.tokyo.example")
	doors.advance(errors.New("i/o timeout")) // failed over to tokyo
	if doors.atPreferred() {
		t.Fatal("setup: the connector should be away from home")
	}

	doors.resetToPreferred() // the home watch decides to go back
	// The tunnel it was holding now ends, because going home ended it. That must not move it again.
	doors.advance(errors.New("use of closed network connection"))
	if !doors.atPreferred() {
		t.Fatal("the connector left home again on a tunnel it ended itself — the loop that was measured")
	}

	// And the very next real failure still moves it.
	doors.advance(errors.New("dial tcp: i/o timeout"))
	if doors.atPreferred() {
		t.Fatal("a genuine failure after going home must still fail the connector over")
	}
}

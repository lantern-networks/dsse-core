package main

import (
	"testing"
	"time"
)

// shortenTheLeadershipWait keeps these checks fast without changing what they check.
func shortenTheLeadershipWait(t *testing.T) {
	t.Helper()
	wait, poll := adminLeadershipWait, adminLeadershipPoll
	adminLeadershipWait, adminLeadershipPoll = 60*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { adminLeadershipWait, adminLeadershipPoll = wait, poll })
}

func TestAnAdministrativeWriteWaitsForALeaderInsteadOfFailing(t *testing.T) {
	shortenTheLeadershipWait(t)
	var calls int
	// Two refusals for the reason a just-started deployment gives, then a leader exists.
	code, raw, err := waitForALeaderToExist(409, []byte(`{"error":"does not hold leadership"}`),
		func() (int, []byte, error) {
			calls++
			if calls < 3 {
				return 409, []byte(`{"error":"does not hold leadership"}`), nil
			}
			return 201, []byte(`{"activation_link":"https://example.test/a?t=x"}`), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if code != 201 {
		t.Errorf("it still gives up on a deployment that has not elected a leader yet: %d %s", code, raw)
	}
	if calls < 3 {
		t.Errorf("it asked %d time(s); a 409 here is not final, and asking once is what made an operator "+
			"have to know to wait", calls)
	}
}

// ★ AND THE WAIT IS BOUNDED. A step that hangs and says nothing is worse than one that fails.
func TestTheWaitForALeaderGivesUp(t *testing.T) {
	shortenTheLeadershipWait(t)
	code, _, err := waitForALeaderToExist(409, nil, func() (int, []byte, error) {
		return 409, []byte(`{"error":"does not hold leadership"}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 409 {
		t.Errorf("a control plane that never leads was reported as %d", code)
	}
}

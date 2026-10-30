package main

import (
	"sync"
	"testing"
	"time"
)

func testWarnOwner(pid uint32, session uint32, sid string, logon uint64) stepUpOwner {
	return stepUpOwner{PID: pid, Created: uint64(pid) + 100, Session: session, SID: sid, LogonID: logon}
}

// a WARN frame shows the notice once per service|destination, parses the payload, and is nil-safe.
func TestWarnNotifierCoalescesPerResource(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	done := make(chan struct{}, 16)
	owner := testWarnOwner(42, 1, "user-a", 10)
	announce := func(dest, service string, gotOwner stepUpOwner) {
		if gotOwner != owner {
			t.Errorf("notice escaped the originating owner: %+v", gotOwner)
		}
		mu.Lock()
		got[service+"|"+dest]++
		mu.Unlock()
		done <- struct{}{}
	}
	w := newWarnNotifier(announce, nil)

	frames := []string{
		`{"message":"m","destination":"10.20.0.10","service":"ssh"}`,
		`{"message":"m","destination":"10.20.0.10","service":"ssh"}`, // dup -> coalesced
		`{"message":"m","destination":"10.20.0.10","service":"smb"}`, // same host, different service -> new
		`{"message":"m","destination":"10.20.0.20","service":"ssh"}`, // different host -> new
	}
	for _, f := range frames {
		w.NotifyForOwner([]byte(f), owner)
	}
	// announce runs on a goroutine; wait for the 3 expected calls.
	for i := 0; i < 3; i++ {
		<-done
	}
	mu.Lock()
	defer mu.Unlock()
	if got["ssh|10.20.0.10"] != 1 {
		t.Errorf("ssh|10.20.0.10 announced %d times, want 1 (coalesced)", got["ssh|10.20.0.10"])
	}
	if got["smb|10.20.0.10"] != 1 || got["ssh|10.20.0.20"] != 1 {
		t.Errorf("distinct service/host not announced: %v", got)
	}
	if len(got) != 3 {
		t.Errorf("want 3 distinct notices, got %d: %v", len(got), got)
	}
}

func TestWarnNotifierIgnoresBadPayloadAndNilReceiver(t *testing.T) {
	var w *warnNotifier
	owner := testWarnOwner(42, 1, "user-a", 10)
	w.NotifyForOwner([]byte(`{"destination":"x"}`), owner) // nil receiver must not panic

	called := false
	w = newWarnNotifier(func(_, _ string, _ stepUpOwner) { called = true }, nil)
	w.NotifyForOwner([]byte(`not json`), owner)          // bad JSON -> ignored
	w.NotifyForOwner([]byte(`{"service":"ssh"}`), owner) // no destination -> ignored
	if called {
		t.Error("announce fired on an invalid/destination-less payload")
	}
}

func TestWarnNotifierSeparatesOwnersAndRefusesUnknownOwner(t *testing.T) {
	a := testWarnOwner(42, 1, "user-a", 10)
	b := testWarnOwner(43, 2, "user-b", 11)
	got := make(chan stepUpOwner, 3)
	w := newWarnNotifier(func(_, _ string, owner stepUpOwner) { got <- owner }, nil)
	payload := []byte(`{"destination":"10.20.0.10","service":"ssh"}`)
	w.NotifyForOwner(payload, stepUpOwner{})
	w.NotifyForOwner(payload, a)
	w.NotifyForOwner(payload, a)
	w.NotifyForOwner(payload, b)
	seen := map[stepUpOwner]bool{}
	for i := 0; i < 2; i++ {
		select {
		case owner := <-got:
			seen[owner] = true
		case <-time.After(time.Second):
			t.Fatalf("missing owner-bound notice: %+v", seen)
		}
	}
	if !seen[a] || !seen[b] || len(seen) != 2 {
		t.Fatalf("notices must remain owner-bound, got %+v", seen)
	}
	select {
	case owner := <-got:
		t.Fatalf("unexpected duplicate or unowned notification: %+v", owner)
	default:
	}
}

func TestWarnOwnerMustRemainTheSameProcessAndLogon(t *testing.T) {
	owner := testWarnOwner(42, 1, "user-a", 10)
	if !warnOwnerStillCurrent(owner, func(uint32) stepUpOwner { return owner }) {
		t.Fatal("current originating owner was rejected")
	}
	for _, changed := range []stepUpOwner{
		{},
		testWarnOwner(42, 2, "user-b", 11), // fast user switch
		testWarnOwner(42, 1, "user-a", 11), // new logon in the same session
		{PID: 42, Created: owner.Created + 1, Session: 1, SID: "user-a", LogonID: 10}, // reused PID
	} {
		if warnOwnerStillCurrent(owner, func(uint32) stepUpOwner { return changed }) {
			t.Fatalf("stale or different owner accepted: %+v", changed)
		}
	}
	if warnOwnerStillCurrent(stepUpOwner{}, func(uint32) stepUpOwner { return owner }) {
		t.Fatal("unknown owner accepted")
	}
}

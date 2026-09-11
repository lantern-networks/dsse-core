package main

import (
	"sync"
	"testing"
)

// a WARN frame shows the notice once per service|destination, parses the payload, and is nil-safe.
func TestWarnNotifierCoalescesPerResource(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	done := make(chan struct{}, 16)
	announce := func(dest, service string) {
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
		w.Notify([]byte(f))
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
	w.Notify([]byte(`{"destination":"x"}`)) // nil receiver must not panic

	called := false
	w = newWarnNotifier(func(_, _ string) { called = true }, nil)
	w.Notify([]byte(`not json`))          // bad JSON -> ignored
	w.Notify([]byte(`{"service":"ssh"}`)) // no destination -> ignored
	if called {
		t.Error("announce fired on an invalid/destination-less payload")
	}
}

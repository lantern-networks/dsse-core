package main

import (
	"reflect"
	"testing"
)

func TestLiveExclusionsEffectiveBaselineUntilFirstSet(t *testing.T) {
	l := newLiveExclusions([]string{"automation", "agent"})
	if got := l.effective(); !reflect.DeepEqual(got, []string{"automation", "agent"}) {
		t.Fatalf("effective before set = %v, want the baseline", got)
	}
}

func TestLiveExclusionsSetAppliesAndUpdatesEffective(t *testing.T) {
	l := newLiveExclusions([]string{"automation"})
	var applied []string
	l.register(func(apps []string) { applied = apps })

	l.set([]string{"automation", "corpvpn.exe"})

	if !reflect.DeepEqual(applied, []string{"automation", "corpvpn.exe"}) {
		t.Fatalf("onApply got %v, want the merged set", applied)
	}
	if got := l.effective(); !reflect.DeepEqual(got, []string{"automation", "corpvpn.exe"}) {
		t.Fatalf("effective after set = %v, want the merged set (so a restart seeds from it)", got)
	}
}

func TestLiveExclusionsLatestRegistrationWins(t *testing.T) {
	l := newLiveExclusions(nil)
	firstCalled, secondCalled := false, false
	l.register(func([]string) { firstCalled = true })
	l.register(func([]string) { secondCalled = true }) // a supervisor-recreated backend re-registers

	l.set([]string{"x"})

	if firstCalled {
		t.Fatal("the stale (pre-restart) updater must not be called")
	}
	if !secondCalled {
		t.Fatal("the latest registered updater must receive the apply")
	}
}

func TestLiveExclusionsSetWithoutRegistrationNoPanic(t *testing.T) {
	l := newLiveExclusions([]string{"automation"})
	l.set([]string{"automation", "y"}) // no backend registered yet (sync may apply before a capture is up)
	if got := l.effective(); !reflect.DeepEqual(got, []string{"automation", "y"}) {
		t.Fatalf("effective = %v, want the set even with no registered backend", got)
	}
}

func TestLiveExclusionsEffectiveReturnsCopy(t *testing.T) {
	l := newLiveExclusions([]string{"automation"})
	got := l.effective()
	got[0] = "tampered"
	if again := l.effective(); again[0] != "automation" {
		t.Fatalf("effective must return a defensive copy; baseline mutated to %v", again)
	}
}

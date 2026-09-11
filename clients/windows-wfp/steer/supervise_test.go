package main

import (
	"errors"
	"testing"
	"time"
)

// fakeCapture is a SteeringCapture stub for supervisor tests: it surfaces a preset terminal error and a
// closed (empty) flows channel so steer() returns immediately.
type fakeCapture struct {
	err error
}

func (f *fakeCapture) Flows() <-chan SteeredFlow {
	ch := make(chan SteeredFlow)
	close(ch) // empty + closed: a steerer ranging over it returns at once
	return ch
}
func (f *fakeCapture) Backend() string { return "fake" }
func (f *fakeCapture) Close() error    { return nil }
func (f *fakeCapture) Err() error      { return f.err }

func noSteer(SteeringCapture) {}

func TestSuperviseCleanStopEndsAndDoesNotRestart(t *testing.T) {
	creations := 0
	factory := func() (SteeringCapture, error) { creations++; return &fakeCapture{err: nil}, nil }
	err := superviseCapture(factory, noSteer, superviseConfig{permanent: true, maxRestarts: 5})
	if err != nil {
		t.Fatalf("clean stop should return nil, got %v", err)
	}
	if creations != 1 {
		t.Fatalf("clean stop should create the capture once, got %d", creations)
	}
}

func TestSuperviseNonPermanentReturnsFailureWithoutRestart(t *testing.T) {
	boom := errors.New("backend died")
	creations := 0
	factory := func() (SteeringCapture, error) { creations++; return &fakeCapture{err: boom}, nil }
	err := superviseCapture(factory, noSteer, superviseConfig{permanent: false})
	if !errors.Is(err, boom) {
		t.Fatalf("non-permanent should return the failure, got %v", err)
	}
	if creations != 1 {
		t.Fatalf("non-permanent should not restart, created %d", creations)
	}
}

func TestSupervisePermanentRestartsUntilMaxThenReturns(t *testing.T) {
	boom := errors.New("backend died")
	creations := 0
	factory := func() (SteeringCapture, error) { creations++; return &fakeCapture{err: boom}, nil }
	waits := 0
	cfg := superviseConfig{
		permanent:   true,
		maxRestarts: 3,
		backoff:     func(int) time.Duration { return time.Millisecond },
		sleep:       func(time.Duration) { waits++ }, // don't actually sleep
	}
	err := superviseCapture(factory, noSteer, cfg)
	if !errors.Is(err, boom) {
		t.Fatalf("exhausted restarts should return the failure, got %v", err)
	}
	// 1 initial run + 3 restart attempts = 4 creations; the 4th exceeds maxRestarts and returns.
	if creations != 4 {
		t.Fatalf("expected 4 creations (1 + 3 restarts), got %d", creations)
	}
	if waits != 3 {
		t.Fatalf("expected 3 backoff waits, got %d", waits)
	}
}

func TestSupervisePermanentRecreatesAfterFactoryError(t *testing.T) {
	boom := errors.New("cannot open handle")
	creations := 0
	// Factory fails twice, then a clean capture succeeds and stops cleanly -> supervision ends nil.
	factory := func() (SteeringCapture, error) {
		creations++
		if creations <= 2 {
			return nil, boom
		}
		return &fakeCapture{err: nil}, nil
	}
	cfg := superviseConfig{permanent: true, maxRestarts: 5, sleep: func(time.Duration) {}, backoff: func(int) time.Duration { return 0 }}
	if err := superviseCapture(factory, noSteer, cfg); err != nil {
		t.Fatalf("should recover after transient factory errors, got %v", err)
	}
	if creations != 3 {
		t.Fatalf("expected 3 creations (2 fails + 1 success), got %d", creations)
	}
}

// ★ THE DEFECT THIS EXISTS FOR (2026-08-14, win-dev-1). In service mode the supervisor returned nil whenever
// the capture ended with Err()==nil, treating "the backend went away" as "somebody asked for a shutdown". The
// service then exited with WIN32_EXIT_CODE 0 — so the SCM did not restart it either — and the box was left
// steered-but-agentless, its resolver pointing at a loopback proxy that no longer existed. Connectivity was
// completely lost and had to be recovered by hand.
//
// The stop channel is the only evidence of intent. If it is not closed, this must restart.
func TestACaptureThatVanishesWithoutBeingAskedIsRestarted(t *testing.T) {
	stop := make(chan struct{})
	created := 0
	newCapture := func() (SteeringCapture, error) {
		created++
		if created == 3 {
			close(stop) // third life: now a real shutdown is requested
		}
		return &fakeCapture{}, nil // Err() == nil: a clean stop nobody asked for
	}
	err := superviseCapture(newCapture, func(SteeringCapture) {}, superviseConfig{
		permanent: true, stop: stop, sleep: func(time.Duration) {},
	})
	if err != nil {
		t.Fatalf("superviseCapture returned %v; a requested stop must still end it cleanly", err)
	}
	if created < 3 {
		t.Fatalf("the backend was created %d time(s): a capture that ends with no error and no stop request was "+
			"taken for an intentional shutdown, which is how this endpoint stopped steering in silence", created)
	}
}

// The contained-burst and foreground paths have NO stop channel and END on a clean close — that is their
// contract, and the fix above must not turn it into an endless restart loop.
func TestAForegroundRunStillEndsOnACleanStop(t *testing.T) {
	created := 0
	newCapture := func() (SteeringCapture, error) {
		created++
		return &fakeCapture{}, nil
	}
	err := superviseCapture(newCapture, func(SteeringCapture) {}, superviseConfig{
		permanent: true, sleep: func(time.Duration) {}, // stop == nil: foreground
	})
	if err != nil {
		t.Fatalf("a foreground clean stop returned %v, want nil", err)
	}
	if created != 1 {
		t.Fatalf("the foreground path restarted %d time(s); a clean close is how it is meant to end", created)
	}
}

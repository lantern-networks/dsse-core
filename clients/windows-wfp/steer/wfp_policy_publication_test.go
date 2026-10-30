package main

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWFPPolicyPublicationOrdersAllUpdates(t *testing.T) {
	var p wfpPolicyPublication
	var applied int
	gen, _, err := p.begin(func() error { applied = 0; return nil })
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = p.update(gen, func() error {
			close(entered)
			<-release
			applied = 1 // older snapshot, delayed in the kernel writer
			return nil
		})
	}()
	<-entered
	var wg sync.WaitGroup
	wg.Add(1)
	attempting := make(chan struct{})
	secondEntered := make(chan struct{})
	go func() {
		defer wg.Done()
		close(attempting)
		_, _ = p.update(gen, func() error {
			close(secondEntered)
			applied = 2 // newer snapshot
			return nil
		})
	}()
	<-attempting
	select {
	case <-secondEntered:
		close(release)
		t.Fatal("newer publication entered while the older IOCTL was still in flight")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	<-firstDone
	wg.Wait()
	if applied != 2 {
		t.Fatalf("last applied policy = %d, want latest desired policy 2", applied)
	}
}

func TestWFPPolicyPublicationRejectsPostCloseUpdate(t *testing.T) {
	var p wfpPolicyPublication
	sets := 0
	gen, _, err := p.begin(func() error { sets++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := p.end(gen, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	applied, err := p.update(gen, func() error { sets++; return nil })
	if err != nil || applied || sets != 1 {
		t.Fatalf("post-close update: applied=%t err=%v sets=%d", applied, err, sets)
	}
}

func TestWFPPolicyPublicationClearFollowsInFlightSet(t *testing.T) {
	var p wfpPolicyPublication
	state := ""
	gen, _, err := p.begin(func() error { state = "set"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	updateDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		_, _ = p.update(gen, func() error {
			close(entered)
			<-release
			state = "set"
			return nil
		})
	}()
	<-entered
	endDone := make(chan struct{})
	go func() {
		defer close(endDone)
		_ = p.end(gen, func() error { state = "clear"; return nil })
	}()
	close(release)
	<-updateDone
	<-endDone
	if state != "clear" {
		t.Fatalf("close was overwritten by in-flight SET: %s", state)
	}
}

func TestWFPPolicyPublicationSuspendAndResume(t *testing.T) {
	var p wfpPolicyPublication
	sets := 0
	latest, appliedValue := 1, 0
	failRearm := false
	gen, _, err := p.begin(func() error {
		if failRearm {
			return errors.New("device unavailable")
		}
		sets++
		appliedValue = latest
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.suspend(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	latest = 2
	applied, err := p.update(gen, func() error { sets++; return nil })
	if err != nil || applied || sets != 1 {
		t.Fatalf("update while disarmed: applied=%t err=%v sets=%d", applied, err, sets)
	}
	if err := p.resume(); err != nil {
		t.Fatal(err)
	}
	if sets != 2 || appliedValue != 2 {
		t.Fatalf("rearm sets=%d applied=%d, want latest policy 2", sets, appliedValue)
	}
	if err := p.suspend(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	failRearm = true
	if err := p.resume(); err == nil {
		t.Fatal("failed rearm returned success")
	}
	applied, err = p.update(gen, func() error { sets++; return nil })
	if err != nil || applied || sets != 2 {
		t.Fatalf("update after failed rearm: applied=%t err=%v sets=%d", applied, err, sets)
	}
}

func TestWFPPolicyPublicationSuspendedSupervisorReplacement(t *testing.T) {
	var p wfpPolicyPublication
	sets, clears := 0, 0
	first, _, err := p.begin(func() error { sets++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := p.suspend(func() error { clears++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.end(first, func() error { clears++; return nil }); err != nil {
		t.Fatal(err)
	}
	second, appliedAtBegin, err := p.begin(func() error { sets++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if second == first || appliedAtBegin || sets != 1 {
		t.Fatalf("replacement during disarm: first=%d second=%d sets=%d", first, second, sets)
	}
	if err := p.end(first, func() error { clears++; return nil }); err != nil {
		t.Fatal(err)
	}
	if clears != 2 {
		t.Fatalf("stale capture cleared replacement policy: clears=%d", clears)
	}
	if err := p.resume(); err != nil {
		t.Fatal(err)
	}
	if sets != 2 {
		t.Fatalf("replacement rearm sets=%d, want 2", sets)
	}
}

func TestWFPPolicyPublicationFailedInitialWriteDoesNotActivate(t *testing.T) {
	var p wfpPolicyPublication
	gen, _, err := p.begin(func() error { return errors.New("policy exceeds current ABI") })
	if err == nil || gen != 0 {
		t.Fatalf("failed initial policy accepted: generation=%d error=%v", gen, err)
	}
	sets := 0
	applied, err := p.update(gen, func() error { sets++; return nil })
	if err != nil || applied || sets != 0 {
		t.Fatalf("failed initial policy permitted a later callback: applied=%t err=%v sets=%d", applied, err, sets)
	}
}

func TestCaptiveDeadlineFollowsOwnerAndCompleteRearm(t *testing.T) {
	p := &wfpPolicyPublication{}
	if _, err := p.armCaptive(time.Second); err == nil {
		t.Fatal("armed without owner")
	}
	generation, _, err := p.begin(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	finishes := 0
	p.bindDeadline(generation, func(time.Duration) (uint64, time.Duration, error) { return 7, time.Second, nil }, func(n uint64) error {
		if n != 7 {
			t.Fatalf("generation=%d", n)
		}
		finishes++
		return nil
	})
	if _, err := p.armCaptive(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := p.suspend(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := p.finishCaptive(); err == nil || finishes != 0 {
		t.Fatal("finished before full rearm")
	}
	if err := p.resume(); err != nil {
		t.Fatal(err)
	}
	if err := p.finishCaptive(); err != nil || finishes != 1 {
		t.Fatalf("finish: %v, calls=%d", err, finishes)
	}
	if err := p.end(generation, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := p.armCaptive(time.Second); err == nil {
		t.Fatal("closed owner armed guard")
	}
	if err := p.finishCaptive(); err == nil {
		t.Fatal("closed owner finished guard")
	}
}

func TestCaptiveFinishFailureRetainsGenerationForRetry(t *testing.T) {
	p := &wfpPolicyPublication{}
	generation, _, _ := p.begin(func() error { return nil })
	calls := 0
	p.bindDeadline(generation, func(time.Duration) (uint64, time.Duration, error) { return 12, time.Second, nil }, func(n uint64) error {
		if n != 12 {
			t.Fatalf("lost generation: %d", n)
		}
		calls++
		if calls == 1 {
			return fmt.Errorf("readback failed")
		}
		return nil
	})
	if _, err := p.armCaptive(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := p.finishCaptive(); err == nil {
		t.Fatal("failure ignored")
	}
	if err := p.finishCaptive(); err != nil {
		t.Fatal(err)
	}
}

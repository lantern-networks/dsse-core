package main

import (
	"context"
	"testing"
	"time"
)

func TestRenewalDeclarationInterruptsLongWaitAndCoalesces(t *testing.T) {
	d := newRenewalDeclaration()
	cutoff := time.Now().UTC()
	// Publication before scheduler startup must not be lost.
	for i := 0; i < 100; i++ {
		d.publish(cutoff)
	}
	if len(d.wake) != 1 {
		t.Fatal("duplicate policy declarations did not coalesce")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := make(chan time.Time, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCertificateRenewalLoop(ctx, 6*time.Hour, d.wake, func() time.Duration {
			checks <- currentRenewCutoff(&d.cutoff)
			return 6 * time.Hour
		})
	}()
	select {
	case got := <-checks:
		if !got.Equal(cutoff) {
			t.Fatal("wake ran before the cutoff became visible")
		}
	case <-time.After(time.Second):
		t.Fatal("operator declaration stayed behind the six-hour timer")
	}
	d.publish(cutoff.Add(time.Minute))
	select {
	case got := <-checks:
		if !got.Equal(cutoff.Add(time.Minute)) {
			t.Fatal("new declaration was not read")
		}
	case <-time.After(time.Second):
		t.Fatal("new declaration did not interrupt the renewed six-hour wait")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal loop did not stop")
	}
}

func TestDeclarationDuringCheckIsNotLost(t *testing.T) {
	d := newRenewalDeclaration()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	second, done := make(chan time.Time, 1), make(chan struct{})
	go func() {
		defer close(done)
		first := true
		runCertificateRenewalLoop(ctx, 0, d.wake, func() time.Duration {
			if first {
				first = false
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
			} else {
				second <- currentRenewCutoff(&d.cutoff)
			}
			return 6 * time.Hour
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial timer did not run")
	}
	cutoff := time.Now().UTC()
	d.publish(cutoff)
	d.publish(cutoff.Add(time.Minute))
	release <- struct{}{}
	select {
	case got := <-second:
		if !got.Equal(cutoff.Add(time.Minute)) {
			t.Fatal("did not read the latest declaration")
		}
	case <-time.After(time.Second):
		t.Fatal("declaration arriving during a check was lost")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not stop")
	}
}

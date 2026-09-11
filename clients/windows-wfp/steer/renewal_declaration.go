package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// The verified policy arrives every minute; that sampling period must neither
// delay a new operator declaration behind a six-hour timer nor repeatedly wake
// renewal for the same declaration. Store before notifying, and coalesce bursts.
type renewalDeclaration struct {
	cutoff atomic.Pointer[time.Time]
	wake   chan struct{}
}

func newRenewalDeclaration() *renewalDeclaration {
	return &renewalDeclaration{wake: make(chan struct{}, 1)}
}

func (d *renewalDeclaration) publish(cutoff time.Time) {
	previous := d.cutoff.Swap(&cutoff)
	if previous != nil && previous.Equal(cutoff) {
		return
	}
	if cutoff.IsZero() {
		log.Printf("certificate_renewal declaration_cleared")
		return
	}
	log.Printf("certificate_renewal declaration_received renew_before=%s", cutoff.UTC().Format(time.RFC3339Nano))
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// A single owner runs checks and timers. A declaration received during a check
// stays buffered, so it cannot be lost between returning and resetting the timer.
func runCertificateRenewalLoop(ctx context.Context, initial time.Duration, wake <-chan struct{}, check func() time.Duration) {
	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-wake:
			if !ok {
				wake = nil
				continue
			}
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if ctx.Err() != nil {
			return
		}
		next := check()
		if next <= 0 {
			next = time.Second
		}
		timer.Reset(next)
	}
}

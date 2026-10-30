package main

import (
	"fmt"
	"sync"
	"time"
)

// wfpPolicyPublication orders every in-process SET/CLEAR and binds live updates
// to the capture that registered them. The driver serializes individual IOCTLs,
// but cannot tell whether a later IOCTL was built from an older userspace state.
// Callbacks may outlive a capture or run while fail-open intentionally disarms it.
type wfpPolicyPublication struct {
	mu                sync.Mutex
	generation        uint64
	active            bool
	suspended         bool
	rearm             func() error // the active capture's config, including its live exact-AppID table
	armDeadline       func(time.Duration) (uint64, time.Duration, error)
	finishDeadline    func(uint64) error
	captiveGeneration uint64
}

// bindDeadline binds the driver operations to the SAME owner handle as the active
// capture. The publication lock prevents close/replacement during an IOCTL.
func (p *wfpPolicyPublication) bindDeadline(generation uint64, arm func(time.Duration) (uint64, time.Duration, error), finish func(uint64) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active && p.generation == generation {
		p.armDeadline, p.finishDeadline = arm, finish
	}
}

func (p *wfpPolicyPublication) armCaptive(timeout time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.armDeadline == nil {
		return 0, fmt.Errorf("no active WFP owner supports an independent captive deadline")
	}
	generation, remaining, err := p.armDeadline(timeout)
	if err != nil {
		return 0, err
	}
	if generation == 0 {
		return 0, fmt.Errorf("driver returned an invalid captive generation")
	}
	p.captiveGeneration = generation
	return remaining, nil
}

// Called only after the complete DNS/QUIC/WFP rearm transaction succeeded.
// Failure leaves the guard intact and the controller retries. A new owner may
// adopt the existing generation, but cannot extend its kernel deadline.
func (p *wfpPolicyPublication) finishCaptive() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.suspended || p.finishDeadline == nil {
		return fmt.Errorf("captive completion requires the active, rearmed WFP owner")
	}
	if err := p.finishDeadline(p.captiveGeneration); err != nil {
		return err
	}
	p.captiveGeneration = 0
	return nil
}

func (p *wfpPolicyPublication) begin(write func() error) (uint64, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active {
		return 0, false, fmt.Errorf("WFP capture already active")
	}
	// A capture recreated during intentional disarm may prepare its listeners, but
	// must wait for the explicit rearm before publishing any redirect policy.
	applied := !p.suspended
	if applied {
		if err := write(); err != nil {
			return 0, false, err
		}
	}
	p.generation++
	p.active = true
	p.rearm = write
	return p.generation, applied, nil
}

func (p *wfpPolicyPublication) update(generation uint64, write func() error) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.suspended || generation == 0 || generation != p.generation {
		return false, nil
	}
	if err := write(); err != nil {
		return false, err
	}
	return true, nil
}

func (p *wfpPolicyPublication) suspend(clear func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Mark suspended before CLEAR. A failed or unverified CLEAR remains an
	// uncertain driver state, but no background callback is allowed to re-SET.
	p.suspended = true
	return clear()
}

func (p *wfpPolicyPublication) resume() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.rearm == nil {
		return fmt.Errorf("no active WFP capture to rearm")
	}
	if err := p.rearm(); err != nil {
		return err // remain suspended; the recovery monitor can retry
	}
	p.suspended = false
	return nil
}

func (p *wfpPolicyPublication) end(generation uint64, clear func() error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || generation == 0 || generation != p.generation {
		return nil // stale capture must not clear a newer capture's policy
	}
	p.active = false
	p.rearm = nil
	p.armDeadline, p.finishDeadline = nil, nil
	return clear()
}

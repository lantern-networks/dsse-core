package main

import (
	"context"
	"errors"
	"time"
)

// waitForServiceStopped requires an observed STOPPED state, not merely a
// successful stop request. A recovery must not restore DNS while its service
// can still publish a new snapshot or retake the resolver.
func waitForServiceStopped(ctx context.Context, query func() (uint32, error), stopped uint32) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		state, err := query()
		if err != nil {
			return err
		}
		if state == stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("service did not reach STOPPED before recovery deadline")
		case <-tick.C:
		}
	}
}

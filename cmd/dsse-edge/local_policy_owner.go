package main

import (
	"context"
	"fmt"
)

// Bound the caller, not the OS syscall. Once admitted, exactly one worker owns
// writeMu through Save and confirmed-state publication. Cancellation never
// releases that exclusion, retries cannot start another Save, and late success
// must not clear preservation that the caller was unable to confirm.
func runLocalPolicyWrite(ctx context.Context, mu *cpWriterMutex, save func() error, unconfirmed func()) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	if err := mu.LockContext(ctx); err != nil {
		unconfirmed()
		return err
	}
	done := make(chan error, 1)
	go func() {
		err := ctx.Err()
		if err == nil {
			err = save()
		}
		if ctx.Err() != nil {
			// This runs after the candidate was published, so even cancellation
			// just before setLocal captured its pending generation stays pending.
			unconfirmed()
			err = fmt.Errorf("local policy save outcome is unconfirmed: %w", ctx.Err())
		}
		mu.Unlock()
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		unconfirmed()
		return fmt.Errorf("local policy save outcome is unconfirmed: %w", ctx.Err())
	}
}

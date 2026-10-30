package main

import "fmt"

// Explicit recovery must prove the independent gate is clear before any driver
// unload. Unloading after a failed clear would silently discard its protection.
// recovered distinguishes an unverified guard (unload/cleanup must stop) from a
// failed driver stop after verified recovery (safe network cleanup must continue).
func recoverBeforeDriverUnload(recover func() error, unload func() error) (recovered bool, err error) {
	if err := recover(); err != nil {
		return false, fmt.Errorf("recover before driver unload: %w", err)
	}
	if unload != nil {
		if err := unload(); err != nil {
			return true, fmt.Errorf("driver stop after verified recovery: %w", err)
		}
	}
	return true, nil
}

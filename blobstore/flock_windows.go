//go:build windows

package blobstore

// withFileLock runs fn without an inter-process lock on this platform.
//
// The stores this guards are Edge-side and the Edge runs on Linux; the agent does not use them. If that
// changes, LockFileEx is the equivalent — and this is a no-op rather than a silent nothing so that the day it
// matters, the gap is here to find rather than absent from the code.
func withFileLock(_ string, fn func() error) error { return fn() }

package main

import (
	"testing"
	"time"
)

// useTransportInstallClock makes the install boundary judge validity against the same clock a test mints
// with. Without it a fixture minted at a fixed date is refused by the real clock — which is the install
// check doing its job, and not what those tests are about.
func useTransportInstallClock(t *testing.T, at func() time.Time) {
	t.Helper()
	previous := transportInstallClock
	transportInstallClock = at
	t.Cleanup(func() { transportInstallClock = previous })
}

// useTransportSelectorClock makes the TLS selector judge validity against the same clock a test mints with.
// The selector refuses a name whose certificate is outside its dates — which is the point of it — so a
// fixture minted at a fixed date is refused by the real clock, correctly and beside the point.
func useTransportSelectorClock(t *testing.T, at func() time.Time) {
	t.Helper()
	previous := transportSelectorClock
	transportSelectorClock = at
	t.Cleanup(func() { transportSelectorClock = previous })
}

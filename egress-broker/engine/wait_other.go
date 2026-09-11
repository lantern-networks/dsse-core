//go:build !linux

package engine

import "time"

// waitFDs is a portable stub for non-Linux dev machines so the package type-checks and `go vet`/`go build`
// stay green cross-platform. The real select(2)-based implementation lives in wait_linux.go, and the
// broker only ever runs in its Linux container (it depends on libcurl-impersonate, present only there).
//
// If this ever executes off-Linux, it degrades to a short bounded sleep: the caller's loop still makes
// progress via curl's CURLE_AGAIN polling — correctness is preserved, only readiness latency changes.
func waitFDs(_, _ int, _ bool, d time.Duration) {
	if d > 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	time.Sleep(d)
}

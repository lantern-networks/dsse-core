// steer_exclusion_live.go — the live, concurrency-safe effective bypass-app set shared between the
// admin-managed server-signed steer-exclusion sync (exclusionSync) and the active capture backend. Portable
// Go (no OS build tag) so it compiles + unit-tests on any host.
//
// Two needs it bridges:
//  1. Live update: when the sync applies a new verified+merged set, the CURRENT backend must pick it up
//     without a restart -- the windivert backend via appBypass.setAppSubs, the wfp backend by re-pushing the
//     kernel policy IOCTL. The backend registers its updater via register().
//  2. Restart consistency: the durable supervisor may recreate the backend after a failure. A freshly
//     created backend seeds itself from effective() so it never reverts to the baseline (which would briefly
//     start steering an excluded app). The latest backend wins the registration.
package main

import "sync"

type liveExclusions struct {
	mu      sync.Mutex
	base    []string       // the static --bypass-app baseline (infra/self); always kept
	current []string       // the merged set (baseline + verified server set); nil until the first signed apply
	onApply func([]string) // the active backend's live updater (appBypass.setAppSubs / wfp policy re-push)
}

// newLiveExclusions starts from the static --bypass-app baseline; the server set is merged on top later.
func newLiveExclusions(base []string) *liveExclusions {
	return &liveExclusions{base: append([]string(nil), base...)}
}

// effective returns the current merged set, or the static baseline before the first signed apply. The
// backend calls this at (re)creation so a supervisor restart never drops the latest exclusions.
func (l *liveExclusions) effective() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current != nil {
		return append([]string(nil), l.current...)
	}
	return append([]string(nil), l.base...)
}

// register installs the active backend's live updater. Called by each capture on creation; the latest
// (post-restart) backend replaces the previous registration.
func (l *liveExclusions) register(fn func([]string)) {
	l.mu.Lock()
	l.onApply = fn
	l.mu.Unlock()
}

// set stores the merged set and pushes it to the active backend (the exclusionSync apply target). The
// onApply call runs OUTSIDE the lock so a backend updater that takes its own lock or issues a kernel IOCTL
// never contends with effective()/register().
func (l *liveExclusions) set(apps []string) {
	l.mu.Lock()
	l.current = append([]string(nil), apps...)
	fn := l.onApply
	l.mu.Unlock()
	if fn != nil {
		fn(apps)
	}
}

package egressbroker

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthMonitor folds egress-broker health into the edge's own readiness. The edge is the thing a load balancer
// probes; with no in-process fallback engine, a dead broker means the decrypt-all path has NO egress transport,
// so an edge whose broker is unusable must stop attracting NEW flows — otherwise "edge + broker as one unit" is
// a claim nothing enforces.
//
// "Unusable" is DEFINED here as brokerUnusableConsecutiveFailures consecutive probe failures. Consecutive over
// a window, not a single error: the restart window of a container recreate is a few seconds, and it is already
// bridged per-request by brokerRestartBackoff — draining a node for a blip the request path absorbs would
// amplify a restart into a rotation event. Three failures at the probe interval ≈ 10–15s of sustained
// unreachability: longer than any observed restart window, shorter than a human notices.
//
// The probe is CACHED (a timer) rather than run per request, so a flapping broker cannot amplify into
// request-path latency. Readiness is PULLED by the balancer via /healthz rather than pushed by the node: a node
// broken enough to matter may be too broken to execute its own removal, and a hung one fails readiness simply
// by not answering.
//
// On a SINGLE-NODE deployment the answer to "should it ever mark itself unready when there is nothing to drain
// to" is YES: readiness is a report, not a self-kill. The data plane keeps serving (bypass and connector-tunnel
// paths do not touch the broker; decrypt-all flows fail legibly with 502s), nothing probes a single node so
// nothing drains, and the operator gets the loud UNUSABLE/RECOVERED transition in the log instead of inferring
// the outage from a traffic graph.
type HealthMonitor struct {
	url      string
	interval time.Duration
	client   *http.Client
	logf     func(string, ...any)

	mu                  sync.RWMutex
	consecutiveFailures int
	lastError           string
	lastCheckedAt       time.Time
	started             bool
}

// brokerUnusableConsecutiveFailures is the "unusable" threshold: this many consecutive probe failures flips
// readiness. See the type comment for why consecutive-over-a-window rather than a single error.
const brokerUnusableConsecutiveFailures = 3

// NewHealthMonitor probes brokerURL/healthz on a timer. interval <= 0 defaults to 5s — with the
// 3-consecutive threshold that makes "unusable" mean ~10–15s of sustained failure.
func NewHealthMonitor(brokerURL string, interval time.Duration, logf func(string, ...any)) *HealthMonitor {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &HealthMonitor{
		url:      brokerURL,
		interval: interval,
		// The probe timeout must undercut the interval so checks can never stack up behind a hung broker.
		client: &http.Client{Timeout: interval / 2},
		logf:   logf,
	}
}

// Start begins probing. Safe to call once; later calls are ignored. Probes once immediately so a broker that
// is down at boot is reported at boot (startup itself stays non-blocking — the first probe runs in the
// goroutine).
func (m *HealthMonitor) Start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go func() {
		t := time.NewTicker(m.interval)
		defer t.Stop()
		m.Check()
		for range t.C {
			m.Check()
		}
	}()
}

// Check runs one probe and updates the cached state, logging the UNUSABLE/RECOVERED transitions — the
// transition only, never every check, so the log stays a signal (the rotation change is the actionable event).
func (m *HealthMonitor) Check() {
	probeErr := m.probe()
	m.mu.Lock()
	prevFailures := m.consecutiveFailures
	if probeErr != nil {
		m.consecutiveFailures++
		m.lastError = probeErr.Error()
	} else {
		m.consecutiveFailures = 0
		m.lastError = ""
	}
	failuresNow := m.consecutiveFailures
	m.lastCheckedAt = time.Now()
	m.mu.Unlock()

	switch {
	case failuresNow == brokerUnusableConsecutiveFailures && prevFailures < brokerUnusableConsecutiveFailures:
		m.logf("egress_broker UNUSABLE after %d consecutive probe failures (last: %v) — decrypt-all egress has no engine "+
			"and no fallback; this node reports unready so an HA balancer drains it. On a single node nothing drains: "+
			"decrypt-all flows keep failing legibly (502) until the broker recovers, while bypass and connector-tunnel "+
			"paths are unaffected", failuresNow, probeErr)
	case failuresNow == 0 && prevFailures >= brokerUnusableConsecutiveFailures:
		m.logf("egress_broker RECOVERED after %d consecutive probe failures — this node reports ready again", prevFailures)
	}
}

func (m *HealthMonitor) probe() error {
	req, err := http.NewRequest(http.MethodGet, m.url+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("broker /healthz returned %s", resp.Status)
	}
	return nil
}

// Ready reports whether this node should receive NEW flows, given broker health. nil monitor (browser-mimic
// egress off, or no broker configured) and unknown (no probe completed yet) both count as ready — refusing
// traffic before the first probe would make every start-up look like an outage, the same rule as
// KeyCustodyMonitor.
func (m *HealthMonitor) Ready() (bool, string) {
	if m == nil {
		return true, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastCheckedAt.IsZero() || m.consecutiveFailures < brokerUnusableConsecutiveFailures {
		return true, ""
	}
	return false, fmt.Sprintf("egress broker unusable: %d consecutive probe failures (last: %s)", m.consecutiveFailures, m.lastError)
}

// Health returns the cached state for the /healthz body — non-sensitive, so an unauthenticated readiness
// prober can see WHY a node is out of rotation without admin auth.
func (m *HealthMonitor) Health() map[string]any {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]any{
		"consecutive_probe_failures": m.consecutiveFailures,
		"unusable_threshold":         brokerUnusableConsecutiveFailures,
	}
	if !m.lastCheckedAt.IsZero() {
		out["last_checked_at"] = m.lastCheckedAt.UTC().Format(time.RFC3339)
	}
	if m.lastError != "" {
		out["last_error"] = m.lastError
	}
	return out
}

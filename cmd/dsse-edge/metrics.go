package main

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// metrics.go is a lightweight, DEPENDENCY-FREE Prometheus text-format metrics surface. The codebase keeps a
// near-zero dependency footprint deliberately, so rather than pull in a metrics client this hand-rolls the few
// highest-value operational series. /metrics is served (unauthenticated, like /healthz) ONLY on the admin /
// management listener (data-plane and the public origin 404 it), so it is scraped from the management network.
// More series can be added incrementally; access-decision throughput + allow/deny rate is the core signal for a
// fail-closed ZTNA (a deny spike or a decision-rate drop is the first sign of an incident).

var (
	metricsStart            atomic.Int64 // unix nanos, set at startup
	metricDecisionsTotal    atomic.Int64
	metricDecisionsAllow    atomic.Int64
	metricDecisionsDeny     atomic.Int64
	metricDecisionsStepUp   atomic.Int64
	metricDecisionsObserve  atomic.Int64 // observe-mode: recorded, not enforced — its own bucket so it is not mistaken for an action
	metricDecisionsOther    atomic.Int64 // a decision value no bucket claimed; see the sum invariant below
	metricDraining          atomic.Bool  // set true when the node enters graceful drain (shutdown)
	metricInterceptReject   atomic.Int64 // upstream TLS interception handshakes rejected (cert-pinned / un-interceptable)
	metricDecisionsInFlight atomic.Int64 // pinned (in-flight) access decisions; refreshed from the store at scrape time

	// DNS-over-tunnel. On 2026-08-09 this subsystem failed for two hours — 20,616 agent-side failures — and the
	// cause could not be established afterwards, because it had no durable output of any kind: the per-query
	// audit logs no qname and is off by default, and the failure line is rate-limited into a buffer a container
	// restart discards. Those logging choices are correct and unchanged; DNS is the hottest path there is and
	// the qname is a browsing history, while the access plane already records the destination of anything that
	// actually connected. What was missing was not a log but a COUNT.
	metricDNSTunnelOK       atomic.Int64
	metricDNSTunnelFailed   atomic.Int64
	metricDNSTunnelLatSumMS atomic.Int64 // sum of resolution latencies, milliseconds
	metricDNSTunnelLatCount atomic.Int64
	// metricDNSTunnelEnabled makes a zero unambiguous. "0 failures" from a node that never registered the route
	// reads exactly like "0 failures" from a healthy one, which is the same shape as the step_up counter that
	// read zero while step-ups were happening. With this, 0 failures means healthy only when enabled is 1.
	metricDNSTunnelEnabled atomic.Bool
)

// setDNSOverTunnelEnabled records whether this Edge serves DNS-over-tunnel at all.
func setDNSOverTunnelEnabled(on bool) { metricDNSTunnelEnabled.Store(on) }

// recordDNSOverTunnel counts one resolution. Called from the resolver's observer hook on both paths; cheap
// (atomic adds), no allocation, and it never sees the queried name.
func recordDNSOverTunnel(ok bool, elapsed time.Duration) {
	if ok {
		metricDNSTunnelOK.Add(1)
	} else {
		metricDNSTunnelFailed.Add(1)
	}
	metricDNSTunnelLatSumMS.Add(elapsed.Milliseconds())
	metricDNSTunnelLatCount.Add(1)
}

// setDecisionsInFlight publishes the store's current in-flight (pinned) decision count as a gauge. The acceptable
// concurrent-session count is environment-specific (a lab is nothing like a production POP), so we surface the
// number and let each deployment alert on its own threshold rather than bound it with a baked-in constant.
func setDecisionsInFlight(n int) { metricDecisionsInFlight.Store(int64(n)) }

// initMetricsStart records the process start so /metrics can report uptime.
func initMetricsStart(now time.Time) { metricsStart.Store(now.UnixNano()) }

// recordDecisionMetric increments the decision counters by outcome. Called wherever an access decision is
// recorded (the decisionStore.Upsert sites). Cheap (atomic adds), no allocation.
// The outcome buckets MUST cover every value the evaluator can produce, and they must sum to the total. They
// did not: `authenticate_required` is a step-up in everything but its name and fell through every case, and
// `observe` did too — so a deployment could take enforcement actions while the step_up counter read zero, and
// nothing said otherwise. 14 authenticate_required decisions are on record.
//
// That is the house failure mode (docs/silent_failure_class_and_detection.md): a zero that means "we did not
// count it" reads exactly like "it did not happen". The `other` bucket is what makes the next one loud instead
// of silent — an unclassified value now shows up as a non-zero `outcome="other"` on the scrape, and the
// sum-to-total invariant is asserted by a test that reads the evaluator's own vocabulary.
func recordDecisionMetric(decision string) {
	metricDecisionsTotal.Add(1)
	switch {
	case decision == "allow":
		metricDecisionsAllow.Add(1)
	case decision == "deny":
		metricDecisionsDeny.Add(1)
	case decision == "observe":
		metricDecisionsObserve.Add(1)
	case strings.HasPrefix(decision, "require_"), decision == "authenticate_required":
		metricDecisionsStepUp.Add(1)
	default:
		metricDecisionsOther.Add(1)
	}
}

// recordInterceptionRejected increments when the interception engine's handshake to an upstream is rejected
// (the destination is cert-pinned or otherwise un-interceptable). Wired at the central cert-pin candidate
// emitter, so it fires once per rejection. A rising rate means more decrypted traffic is hitting
// un-decryptable destinations — the operational signal for tuning the bypass catalog.
func recordInterceptionRejected() { metricInterceptReject.Add(1) }

// writePrometheusMetrics renders the current metrics in Prometheus text exposition format (v0.0.4).
func writePrometheusMetrics(w io.Writer, now time.Time) {
	var uptime float64
	if start := metricsStart.Load(); start > 0 {
		uptime = now.Sub(time.Unix(0, start)).Seconds()
	}
	fmt.Fprintf(w, "# HELP dsse_edge_uptime_seconds Seconds since the Edge process started.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_uptime_seconds gauge\n")
	fmt.Fprintf(w, "dsse_edge_uptime_seconds %.0f\n", uptime)
	fmt.Fprintf(w, "# HELP dsse_access_decisions_total Access decisions evaluated, by outcome.\n")
	fmt.Fprintf(w, "# TYPE dsse_access_decisions_total counter\n")
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"all\"} %d\n", metricDecisionsTotal.Load())
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"allow\"} %d\n", metricDecisionsAllow.Load())
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"deny\"} %d\n", metricDecisionsDeny.Load())
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"step_up\"} %d\n", metricDecisionsStepUp.Load())
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"observe\"} %d\n", metricDecisionsObserve.Load())
	// A non-zero `other` means a decision value exists that no bucket claims — the buckets no longer sum to the
	// total, and something is being enforced that this surface cannot name.
	fmt.Fprintf(w, "dsse_access_decisions_total{outcome=\"other\"} %d\n", metricDecisionsOther.Load())
	var draining float64
	if metricDraining.Load() {
		draining = 1
	}
	fmt.Fprintf(w, "# HELP dsse_edge_draining 1 when the Edge has entered graceful drain (shutting down), else 0.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_draining gauge\n")
	fmt.Fprintf(w, "dsse_edge_draining %.0f\n", draining)
	fmt.Fprintf(w, "# HELP dsse_interception_handshake_rejected_total Upstream TLS interception handshakes rejected (cert-pinned / un-interceptable destination).\n")
	fmt.Fprintf(w, "# TYPE dsse_interception_handshake_rejected_total counter\n")
	fmt.Fprintf(w, "dsse_interception_handshake_rejected_total %d\n", metricInterceptReject.Load())
	// Process-level operational gauge: a climbing goroutine count with steady load is the earliest sign of a
	// leak (a stuck tunnel copy, an un-closed upstream). Cheap (runtime counter), no hot-path wiring.
	fmt.Fprintf(w, "# HELP dsse_edge_goroutines Current number of goroutines in the Edge process.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_goroutines gauge\n")
	fmt.Fprintf(w, "dsse_edge_goroutines %d\n", runtime.NumGoroutine())
	// The endpoint-tunnel population, and what the idle reaper takes out of it. started-completed is the live
	// count; a climbing value under steady load is the leak shape the macOS extension's 1024-connection ceiling
	// turns into user-visible failures. Added 2026-08-18 because the reaper's log line was the only visible
	// part of this lifecycle and nothing gave it a denominator.
	neStarted, neCompleted, neReaped := edgeplane.NetworkExtensionTunnelCounts()
	fmt.Fprintf(w, "# HELP dsse_edge_ne_tunnels_started_total Endpoint tunnels bridged since start.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_ne_tunnels_started_total counter\n")
	fmt.Fprintf(w, "dsse_edge_ne_tunnels_started_total %d\n", neStarted)
	fmt.Fprintf(w, "# HELP dsse_edge_ne_tunnels_completed_total Endpoint tunnels that left the bridge, however they ended.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_ne_tunnels_completed_total counter\n")
	fmt.Fprintf(w, "dsse_edge_ne_tunnels_completed_total %d\n", neCompleted)
	fmt.Fprintf(w, "# HELP dsse_edge_ne_tunnels_reaped_idle_total Endpoint tunnels torn down by the idle safety net.\n")
	fmt.Fprintf(w, "# TYPE dsse_edge_ne_tunnels_reaped_idle_total counter\n")
	fmt.Fprintf(w, "dsse_edge_ne_tunnels_reaped_idle_total %d\n", neReaped)
	// In-flight (pinned) access decisions: one per request currently being processed. Bounded by concurrency, not
	// by a cap — alert per-environment. A climbing value with steady load can also flag an unpin leak.
	fmt.Fprintf(w, "# HELP dsse_access_decisions_in_flight Access decisions pinned while their request is in flight.\n")
	fmt.Fprintf(w, "# TYPE dsse_access_decisions_in_flight gauge\n")
	fmt.Fprintf(w, "dsse_access_decisions_in_flight %d\n", metricDecisionsInFlight.Load())
	// DNS-over-tunnel outcomes. A rising failed rate with a flat ok rate is the shape of the 2026-08-09
	// incident, and it is the one signal that would have made that two hours a graph instead of a guess.
	// No qname is involved at any point — these are counts.
	var dnsEnabled float64
	if metricDNSTunnelEnabled.Load() {
		dnsEnabled = 1
	}
	fmt.Fprintf(w, "# HELP dsse_dns_over_tunnel_enabled 1 when this Edge serves DNS-over-tunnel, else 0. Read the counters below only when this is 1: a node that never registered the route also reports zero failures.\n")
	fmt.Fprintf(w, "# TYPE dsse_dns_over_tunnel_enabled gauge\n")
	fmt.Fprintf(w, "dsse_dns_over_tunnel_enabled %.0f\n", dnsEnabled)
	fmt.Fprintf(w, "# HELP dsse_dns_over_tunnel_total DNS-over-tunnel resolutions, by outcome. A failure is returned to the endpoint as a 502 and, on a fail-closed device, means the name does not resolve at all.\n")
	fmt.Fprintf(w, "# TYPE dsse_dns_over_tunnel_total counter\n")
	fmt.Fprintf(w, "dsse_dns_over_tunnel_total{outcome=\"ok\"} %d\n", metricDNSTunnelOK.Load())
	fmt.Fprintf(w, "dsse_dns_over_tunnel_total{outcome=\"failed\"} %d\n", metricDNSTunnelFailed.Load())
	// Sum + count rather than a histogram: this surface is deliberately dependency-free, and rate(sum)/rate(count)
	// gives the mean, which is enough to see an upstream degrade before it starts failing outright.
	fmt.Fprintf(w, "# HELP dsse_dns_over_tunnel_latency_seconds_sum Total DNS-over-tunnel resolution time. Divide by _count for the mean.\n")
	fmt.Fprintf(w, "# TYPE dsse_dns_over_tunnel_latency_seconds_sum counter\n")
	fmt.Fprintf(w, "dsse_dns_over_tunnel_latency_seconds_sum %.3f\n", float64(metricDNSTunnelLatSumMS.Load())/1000)
	fmt.Fprintf(w, "# HELP dsse_dns_over_tunnel_latency_seconds_count DNS-over-tunnel resolutions timed.\n")
	fmt.Fprintf(w, "# TYPE dsse_dns_over_tunnel_latency_seconds_count counter\n")
	fmt.Fprintf(w, "dsse_dns_over_tunnel_latency_seconds_count %d\n", metricDNSTunnelLatCount.Load())
}

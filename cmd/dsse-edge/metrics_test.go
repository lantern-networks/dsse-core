package main

import (
	"strings"
	"testing"
	"time"
)

func TestRecordDecisionMetricAndRender(t *testing.T) {
	// Reset counters (package-level; this test owns them).
	metricDecisionsTotal.Store(0)
	metricDecisionsAllow.Store(0)
	metricDecisionsDeny.Store(0)
	metricDecisionsStepUp.Store(0)

	recordDecisionMetric("allow")
	recordDecisionMetric("allow")
	recordDecisionMetric("deny")
	recordDecisionMetric("observe")
	recordDecisionMetric("require_step_up") // require_ prefix -> step_up
	recordDecisionMetric("require_approval")

	if got := metricDecisionsTotal.Load(); got != 6 {
		t.Fatalf("total: want 6, got %d", got)
	}
	if got := metricDecisionsAllow.Load(); got != 2 {
		t.Fatalf("allow: want 2, got %d", got)
	}
	if got := metricDecisionsDeny.Load(); got != 1 {
		t.Fatalf("deny: want 1, got %d", got)
	}
	if got := metricDecisionsStepUp.Load(); got != 2 {
		t.Fatalf("step_up: want 2, got %d", got)
	}

	initMetricsStart(time.Now().Add(-30 * time.Second))
	var sb strings.Builder
	writePrometheusMetrics(&sb, time.Now())
	out := sb.String()

	for _, want := range []string{
		"# TYPE dsse_access_decisions_total counter",
		`dsse_access_decisions_total{outcome="all"} 6`,
		`dsse_access_decisions_total{outcome="allow"} 2`,
		`dsse_access_decisions_total{outcome="deny"} 1`,
		`dsse_access_decisions_total{outcome="step_up"} 2`,
		"dsse_edge_uptime_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

func TestInterceptionRejectedMetricAndRender(t *testing.T) {
	metricInterceptReject.Store(0)
	recordInterceptionRejected()
	recordInterceptionRejected()
	recordInterceptionRejected()
	if got := metricInterceptReject.Load(); got != 3 {
		t.Fatalf("interception rejected: want 3, got %d", got)
	}

	var sb strings.Builder
	writePrometheusMetrics(&sb, time.Now())
	out := sb.String()

	for _, want := range []string{
		"# TYPE dsse_interception_handshake_rejected_total counter",
		"dsse_interception_handshake_rejected_total 3",
		"# TYPE dsse_edge_goroutines gauge",
		"dsse_edge_goroutines ", // value is runtime-dependent; assert the series is present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
}

// ★ The 2026-08-09 gap. DNS-over-tunnel failed for two hours and left no evidence, because its only outputs
// are a qname-free per-query audit that is off by default and a rate-limited stderr line in a buffer a restart
// discards. Those choices are right — DNS is the hottest path there is, the qname is a browsing history, and
// the access plane already records the destination of anything that actually connected. What was missing was
// a count. These assert the count exists, and that it cannot be mistaken for anything else.
func TestDNSOverTunnelMetricsCountBothOutcomes(t *testing.T) {
	okBefore, failBefore := metricDNSTunnelOK.Load(), metricDNSTunnelFailed.Load()
	cntBefore, sumBefore := metricDNSTunnelLatCount.Load(), metricDNSTunnelLatSumMS.Load()

	recordDNSOverTunnel(true, 40*time.Millisecond)
	recordDNSOverTunnel(false, 5000*time.Millisecond)

	if got := metricDNSTunnelOK.Load() - okBefore; got != 1 {
		t.Errorf("ok counter moved by %d, want 1", got)
	}
	if got := metricDNSTunnelFailed.Load() - failBefore; got != 1 {
		t.Errorf("failed counter moved by %d, want 1", got)
	}
	// Latency covers BOTH outcomes: a failing upstream that is slow before it fails is the early warning, and
	// timing only the successes would hide exactly that.
	if got := metricDNSTunnelLatCount.Load() - cntBefore; got != 2 {
		t.Errorf("latency count moved by %d, want 2 (successes AND failures are timed)", got)
	}
	if got := metricDNSTunnelLatSumMS.Load() - sumBefore; got != 5040 {
		t.Errorf("latency sum moved by %dms, want 5040", got)
	}

	var b strings.Builder
	writePrometheusMetrics(&b, time.Now())
	out := b.String()
	for _, want := range []string{
		`dsse_dns_over_tunnel_total{outcome="ok"}`,
		`dsse_dns_over_tunnel_total{outcome="failed"}`,
		"dsse_dns_over_tunnel_latency_seconds_sum",
		"dsse_dns_over_tunnel_latency_seconds_count",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %s", want)
		}
	}
	// The qname must never reach this surface. It is the whole reason the per-query audit stays silent.
	if strings.Contains(out, "qname") {
		t.Error("the metrics surface must never carry a queried name")
	}
}

// A zero must not be ambiguous. A node that never registered the route reports zero failures, and so does a
// perfectly healthy one — the same shape as the step_up counter that read zero while step-ups were happening.
func TestDNSOverTunnelEnabledGaugeDisambiguatesAZeroCount(t *testing.T) {
	t.Cleanup(func() { setDNSOverTunnelEnabled(false) })

	setDNSOverTunnelEnabled(false)
	var off strings.Builder
	writePrometheusMetrics(&off, time.Now())
	if !strings.Contains(off.String(), "dsse_dns_over_tunnel_enabled 0") {
		t.Fatal("a node not serving DNS-over-tunnel must say so")
	}

	setDNSOverTunnelEnabled(true)
	var on strings.Builder
	writePrometheusMetrics(&on, time.Now())
	if !strings.Contains(on.String(), "dsse_dns_over_tunnel_enabled 1") {
		t.Fatal("a node serving DNS-over-tunnel must say so")
	}
	// And the HELP text has to tell whoever reads the scrape why the gauge is there, or the two zeros get
	// conflated again by the next person.
	if !strings.Contains(on.String(), "also reports zero failures") {
		t.Error("the enabled gauge must explain what a zero failure count means without it")
	}
}

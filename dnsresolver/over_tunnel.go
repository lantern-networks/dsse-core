package dnsresolver

import (
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// DNS over the (T) encrypted tunnel. Instead of sending plaintext UDP:53 to the
// Edge (which would leak the queried domain on the local network / endpoint environment), the endpoint
// agent sends the raw DNS query over the encrypted endpoint↔Edge transport and the Edge resolves it.
// The wire contract is RFC 8484-style (application/dns-message): a POST whose body is a raw DNS query,
// returning the raw DNS response. Because it is a normal mux route, it is served on the (T) TLS listener
// — so the domain name only ever appears inside the encrypted tunnel, and only the Edge resolves it
// (deny / Stub IP / forward / ECH-strip / conntrack via Resolver.HandleQuery).

const (
	maxDNSMessageBytes      = 65535
	dnsMessageContentType   = "application/dns-message"
	dnsOverTunnelStatusCode = http.StatusBadGateway

	// A DNS-over-tunnel resolution slower than this is worth a (rate-limited) log line: the endpoint agent's
	// client timeout is a few seconds and a shared circuit breaker fail-opens the whole box when it is hit, so
	// a slow resolve is the precursor to an enforcement outage. 1s is well under any sane client timeout.
	dnsOverTunnelSlowThreshold = time.Second
	// Failures/slow resolves are logged at most once per this window so a storm of 502s cannot flood the log
	// (the outcome is an enum + a duration bucket — no qname/IP, so no per-query firehose either).
	dnsOverTunnelLogInterval = time.Second
)

// dnsOverTunnelLastLogNanos rate-limits the failure/slow diagnostic below. Non-secret: it records only the
// outcome enum and elapsed-ms bucket, never the queried name. Without it, the 502 path is http.Error(), which
// logs nothing — leaving the Edge blind to exactly the resolve failures the endpoint agents observe as
// fail-opens (see docs/handoff_windows_chatgpt_app_receive_fail_pipe_halfclose.ja.md).
var dnsOverTunnelLastLogNanos atomic.Int64

// overTunnelObserver is an optional per-resolution callback the host process registers to COUNT outcomes.
//
// It exists because of 2026-08-09: DNS-over-tunnel failed for two hours (20,616 agent-side failures) and the
// cause could not be established afterwards, because this subsystem's only output is stderr — the per-query
// audit deliberately logs no qname and is off by default, and the failure line above is rate-limited to one a
// second into a buffer a container restart discards.
//
// Those logging choices are RIGHT and are not being changed. DNS is the hottest path there is (one query per
// name lookup) and the qname is a complete browsing history; the access plane already records the destination
// hostname of anything that actually connected, so logging queries here would add the most sensitive field at
// the highest volume for almost no information. What was missing was never a log. It was a COUNT: one integer
// that says how often resolution is failing, with no name in it and no per-query cost.
//
// A callback rather than a counter in this package because the metrics surface lives in the host process and
// this module must not depend on it. Same shape as SetDNSQueryLogVerbose.
var overTunnelObserver atomic.Pointer[func(ok bool, elapsed time.Duration)]

// SetOverTunnelObserver registers (or with nil, clears) the per-resolution outcome callback. It is called once
// per DNS-over-tunnel request, on both the success and failure paths, and must not block.
func SetOverTunnelObserver(f func(ok bool, elapsed time.Duration)) {
	if f == nil {
		overTunnelObserver.Store(nil)
		return
	}
	overTunnelObserver.Store(&f)
}

func observeOverTunnel(ok bool, elapsed time.Duration) {
	if p := overTunnelObserver.Load(); p != nil {
		(*p)(ok, elapsed)
	}
}

// dnsOverTunnelShouldLog reports whether enough time has passed since the last diagnostic to emit another.
func dnsOverTunnelShouldLog(now time.Time) bool {
	nowNanos := now.UnixNano()
	last := dnsOverTunnelLastLogNanos.Load()
	if nowNanos-last < int64(dnsOverTunnelLogInterval) {
		return false
	}
	return dnsOverTunnelLastLogNanos.CompareAndSwap(last, nowNanos)
}

// OverTunnelHandler returns the HTTP handler that resolves a DNS query carried over the tunnel using
// the shared Edge resolver. Returns nil when no resolver is available (route not registered).
func OverTunnelHandler(resolver *Resolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxDNSMessageBytes+1))
		if err != nil {
			http.Error(w, "read dns query", http.StatusBadRequest)
			return
		}
		if len(body) == 0 || len(body) > maxDNSMessageBytes {
			http.Error(w, "dns query body must be 1..65535 bytes", http.StatusBadRequest)
			return
		}
		start := time.Now()
		resp, herr := resolver.HandleQuery(body, start)
		elapsed := time.Since(start)
		if herr != nil || len(resp) == 0 {
			observeOverTunnel(false, elapsed)
			// Non-secret: no qname/IP in the error; the resolver already audited the decision enum. The
			// rate-limited diagnostic gives the Edge side a timing signal for the fail-opens the endpoint
			// agents see (their client timeout + shared circuit breaker trips on exactly this 502).
			if dnsOverTunnelShouldLog(start) {
				log.Printf("edge_dns_over_tunnel outcome=resolve_failed elapsed_ms=%d", elapsed.Milliseconds())
			}
			http.Error(w, "dns resolution failed", dnsOverTunnelStatusCode)
			return
		}
		observeOverTunnel(true, elapsed)
		if elapsed >= dnsOverTunnelSlowThreshold && dnsOverTunnelShouldLog(start) {
			log.Printf("edge_dns_over_tunnel outcome=slow elapsed_ms=%d", elapsed.Milliseconds())
		}
		w.Header().Set("content-type", dnsMessageContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	}
}

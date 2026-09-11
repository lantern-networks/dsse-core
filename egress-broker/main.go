// egress-broker: the browser-faithful upstream leg of the decrypt-all SWG.
//
// The Edge decrypts, inspects, applies policy/DLP/header-injection, then hands the FULLY-DECIDED request to this
// broker, which RE-ORIGINATES it through a REAL Chrome network stack (curl-impersonate = real BoringSSL + a
// Chrome-matched HTTP/2 profile) — so the origin sees genuine Chrome TLS+H2+HPACK behavior, not a Go emulation.
// See README.md for the design, the build, and how to verify the live fingerprint.
//
// This is the TRANSPORT ONLY — zero security logic. It never sees admin secrets or makes decisions; it emits the
// headers it is given, in the given order, and streams the response back.
//
// STATUS: HTTP (/v1/reoriginate) and WebSocket (/v1/ws, CURLWS_RAW_MODE) both re-originate through the real
// Chrome stack. Served over h2c so the Edge can stream the WS tunnel full-duplex. Engine = lexiforest
// curl-impersonate (see engine.ImpersonateBinary for the live profile).
//
// THE ENGINE IS NOT HERE. It lives in ./engine, an importable package, because the Edge is being unified with
// this broker: the two are one deployable unit — same box, same lifecycle, same version — so the engine has to
// be shared code rather than a second implementation. This binary is one host for it; an in-process Edge is the
// other. Anything that behaves differently between the two hosts is a bug, which is only checkable because
// there is exactly one implementation to check.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/lantern-networks/dsse-core/egress-broker/engine"
	"github.com/lantern-networks/dsse-core/swg"
)

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func main() {
	// Check the address every transfer ACTUALLY connects to, before its request is sent. The Edge already
	// pre-flights the destination hostname, but that resolution and this dial are two separate lookups, so a
	// name can resolve to a public address when it is checked and an internal one when it is dialled. Every
	// other egress path in the product checks the connected peer for exactly this reason; installing the same
	// list here brings re-origination up to that standard in the sidecar topology too, not only when the
	// engine is embedded in the Edge.
	engine.SetPeerGuard(func(ip string) error {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("peer address %q is not an IP", ip)
		}
		if swg.IsBlockedEgressIP(parsed) {
			return fmt.Errorf("connected peer %s is internal/link-local/loopback/metadata", parsed)
		}
		return nil
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/v1/reoriginate", engine.ReoriginateHTTP) // pooled CGO libcurl HTTP path
	mux.HandleFunc("/v1/ws", engine.ReoriginateWS)            // CGO libcurl-impersonate raw WS tunnel
	addr := firstNonEmpty(os.Getenv("EGRESS_BROKER_LISTEN"), ":8088")
	fmt.Fprintf(os.Stderr, "egress-broker listening on %s (impersonate=%s)\n", addr, engine.ImpersonateBinary())
	// Serve h2c so the Edge can stream the WS tunnel full-duplex (request body = client->origin, response body =
	// origin->client concurrently) — Go's HTTP/1.1 client cannot do that. h2c.NewHandler also serves plain HTTP/1.1
	// (the /v1/reoriginate + /healthz callers), so both work on one listener.
	// High MaxConcurrentStreams: the Edge coalesces ALL decrypt-all egress onto ONE h2c connection to the broker,
	// so under a heavy page (a scroll firing dozens of subresources + API POSTs) the default 250-stream cap would
	// queue requests -> latency -> the browser cancels them (observed as "context canceled" -> broken infinite scroll).
	h2s := &http2.Server{MaxConcurrentStreams: 10000}
	srv := &http.Server{Addr: addr, Handler: h2c.NewHandler(mux, h2s)}

	// Drain on SIGTERM instead of dying mid-request. Without this, `docker compose up -d` killed in-flight
	// re-originations the instant the container stopped — observed 2026-08-04, when a live chatgpt.com flow hit an
	// engine upgrade and the Edge logged a broker error for it. The Edge has no fallback engine any more, so a
	// request cut here is a failed page, not a degraded one.
	//
	// Scope, so this is not read as more than it is: Shutdown waits for in-flight HTTP re-originations to finish
	// and stops accepting new ones. It does NOT wait for HIJACKED connections, which is what /v1/ws tunnels are —
	// those are still severed on exit and the browser must reconnect. Closing that gap needs connection handoff or
	// a second instance, neither of which a single-node reference has.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		fmt.Fprintf(os.Stderr, "egress-broker exited: %v\n", err)
		os.Exit(1)
	case sig := <-stop:
		// Keep the window under Docker's default 10s SIGTERM->SIGKILL grace so the drain actually completes;
		// compose sets stop_grace_period to match.
		fmt.Fprintf(os.Stderr, "egress-broker: %v received — draining in-flight re-originations\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "egress-broker: drain did not complete cleanly: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "egress-broker: drained, exiting")
	}
}

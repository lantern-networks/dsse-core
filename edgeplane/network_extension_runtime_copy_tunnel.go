package edgeplane

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	interception "github.com/lantern-networks/dsse-core/interception"
)

// Full-duplex runtime-copy tunnel.
//
// The session/round-trip endpoints are half-duplex: each exchange writes the
// upstream chunk then blocks reading the downstream behind polling waits, which
// serializes the inherently full-duplex, concurrent nature of real TLS+HTTP and
// makes real browser SPAs stall/blank. This endpoint instead hijacks the NE<->Edge
// connection into a raw byte tunnel and bridges it to the dialer's per-flow
// connection with two independent copy loops, so bytes flow in both directions
// concurrently with no per-exchange synchronization.
//
// The dialer already routes the flow: for an intercepted SNI it returns the
// in-process pipe whose other end runs serve() (tls.Server + decrypt + forward);
// for a bypassed flow it returns a raw connection to the real upstream. The same
// bridge therefore serves both the decrypt and bypass paths.
//
// See docs/edge_dataplane_full_duplex_tunnel_design.md.

const NetworkExtensionRuntimeCopyTunnelPath = "/network-extension/runtime-copy/tunnel"

// A per-flow idle safety net. Only a flow with no bytes in EITHER direction for this long is torn down: one
// direction going quiet while the other still carries is not idle. It exists to bound the flows that pile up
// when a peer half-closes and then never speaks and never closes, and it is a tunable safety net rather than
// a policy. Generous, so that a legitimately idle-but-alive connection — an interactive SSH session, a pooled
// database connection — is not cut by mistake.
//
// ★ Under steer-all with decrypt-all, EVERY flow makes a tunnel connection, including macOS's background
// ones. A reaper set too long lets idle connections accumulate toward the network extension's own limit of
// 1024 concurrent connections, which then becomes the error. DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS shortens it;
// zero or an invalid value means the default.
var networkExtensionRuntimeCopyTunnelIdleTimeout = resolveNetworkExtensionRuntimeCopyTunnelIdleTimeout()

func resolveNetworkExtensionRuntimeCopyTunnelIdleTimeout() time.Duration {
	// 180s by default: the Edge independently tears down a flow with no bytes either way for that long, so the
	// leak is bounded here as well as by the extension's own 120s reaper. SSE and long-poll normally carry
	// something inside 180s, so they are unlikely to be cut. The previous default of thirty minutes was long
	// enough to be a cause of the leak rather than a bound on it.
	const fallback = 180 * time.Second
	raw := strings.TrimSpace(os.Getenv("DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS"))
	if raw == "" {
		return fallback
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

const (
	// Wire contract with the macOS NE (DsseRuntimeCopyTunnel.swift): keep byte-identical to the dsse-renamed
	// client. Guarded by TestNoStaleRenamedWireContractStrings against a sanitization-rename miss.
	networkExtensionRuntimeCopyTunnelTenantHeader = "X-Dsse-Ne-Tunnel-Tenant"
	networkExtensionRuntimeCopyTunnelHostHeader   = "X-Dsse-Ne-Tunnel-Host"
	networkExtensionRuntimeCopyTunnelPortHeader   = "X-Dsse-Ne-Tunnel-Port"
)

type NetworkExtensionRuntimeCopyTunnelHandlerConfig struct {
	TenantID string
	// DeviceTenant resolves the tenant from the device's certificate. See DeviceTenantFunc — the tunnel
	// carries the same flows as the round trip and had the same node-scoped guard.
	DeviceTenant      DeviceTenantFunc
	Dialer            NetworkExtensionRuntimeCopyTCPDialer
	TransportIdentity TransportIdentityFunc
}

func NewNetworkExtensionRuntimeCopyTunnelHandler(config NetworkExtensionRuntimeCopyTunnelHandlerConfig) http.HandlerFunc {
	runtimeTenantID := strings.TrimSpace(config.TenantID)
	dialer := config.Dialer
	if dialer == nil {
		dialer = NetworkExtensionRuntimeCopyNetDialer{}
	}
	deviceTenant := config.DeviceTenant
	return func(w http.ResponseWriter, r *http.Request) {
		runtimeTenantID := tenantForRequest(deviceTenant, r, runtimeTenantID)
		// Every refusal below says WHY, out loud. The agent reports a refusal as handshakeFailed("non_200_status")
		// and nothing else — so when this endpoint answered non-200 the deployment went silent on both sides,
		// which is how two datapath incidents on 2026-07-31 each turned into an hour of guessing.
		// docs/2026-07-31_edge_identity_certificate_replacement_outage.ja.md.
		identity, identityVerified := resolveTransportIdentity(config.TransportIdentity, r)
		refuse := func(status int, reason string, err error) {
			log.Printf("network_extension_runtime_copy_tunnel REFUSED status=%d reason=%s identity=%q identity_verified=%t host=%q port=%q",
				status, reason, identity, identityVerified,
				strings.TrimSpace(r.Header.Get(networkExtensionRuntimeCopyTunnelHostHeader)),
				strings.TrimSpace(r.Header.Get(networkExtensionRuntimeCopyTunnelPortHeader)))
			writeError(w, status, err)
		}
		if runtimeTenantID == "" || strings.TrimSpace(r.Header.Get(networkExtensionRuntimeCopyTunnelTenantHeader)) != runtimeTenantID {
			refuse(http.StatusBadGateway, "tenant_scope_mismatch", fmt.Errorf("network extension runtime-copy tunnel tenant scope mismatch"))
			return
		}
		port, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(networkExtensionRuntimeCopyTunnelPortHeader)))
		if err != nil {
			refuse(http.StatusBadRequest, "port_invalid", fmt.Errorf("network extension runtime-copy tunnel port is invalid"))
			return
		}
		route, ok, routeFailure := networkExtensionRuntimeCopyRouteFromRequest(networkExtensionRuntimeCopyRoundTripRequest{
			DestinationHost: strings.TrimSpace(r.Header.Get(networkExtensionRuntimeCopyTunnelHostHeader)),
			DestinationPort: port,
		})
		if !ok {
			refuse(routeFailure.status, "route_rejected:"+routeFailure.category, fmt.Errorf("network extension runtime-copy tunnel route rejected: %s", routeFailure.category))
			return
		}
		// Carry the verified (T) transport device identity into the route so the decrypt-all egress + the
		// federated-auth gate bind/check a grant per-device. This tunnel handler is the Mac NE decrypt path;
		// without this the device is empty and a browser-minted grant would be tenant-wide.
		if identityVerified {
			route.DeviceIdentity = identity
		}
		route.TenantID = runtimeTenantID
		route.BuiltBy = "runtime-copy-tunnel"

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			refuse(http.StatusInternalServerError, "hijack_unsupported", fmt.Errorf("network extension runtime-copy tunnel response writer does not support hijack"))
			return
		}
		var clientConn net.Conn
		clientConn, _, err = hijacker.Hijack()
		if err != nil {
			log.Printf("network_extension_runtime_copy_tunnel hijack failed: %v", err)
			return
		}
		if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = clientConn.Close()
			log.Printf("network_extension_runtime_copy_tunnel established-response write failed: %v", err)
			return
		}

		// In SNI mode the ClientHello is peeked and route.SNI set. The dialer decides intercept or raw_forward
		// from it, so a raw forward passes straight through the dialer as a direct bridge and avoids the
		// net.Pipe in between, which is what stalls at high throughput. It also means a connect-by-IP flow
		// (Chrome, IPv6) is still matched by hostname.
		if sniDialer, ok := dialer.(NetworkExtensionRuntimeCopySNIPeekDialer); ok && sniDialer.SNIBasedDecisionEnabled() && route.Port == 443 {
			sni, buffered, _ := interception.PeekClientHelloSNI(clientConn)
			route.SNI = sni
			clientConn = &NetworkExtensionLabTLSPrefixedConn{Conn: clientConn, Prefix: buffered}
		}

		upstreamConn, err := dialer.OpenTCPConnection(r.Context(), route)
		if err != nil || upstreamConn == nil {
			_ = clientConn.Close()
			log.Printf("network_extension_runtime_copy_tunnel destination connect failed: %v", err)
			return
		}

		NetworkExtensionHotPathLog("network_extension_runtime_copy_tunnel progress=tunnel_started route_host_category=%s route_port_category=%s",
			NetworkExtensionLabTLSRouteHostCategory(route.Host), NetworkExtensionLabTLSRoutePortCategory(route.Port))
		BridgeNetworkExtensionRuntimeCopyTunnel(r.Context(), clientConn, upstreamConn)
		NetworkExtensionHotPathLog("network_extension_runtime_copy_tunnel progress=tunnel_completed")
	}
}

// BridgeNetworkExtensionRuntimeCopyTunnel copies bytes in both directions
// concurrently. When one direction reaches EOF it half-closes only the write
// side of the peer (CloseWrite), so the still-active reverse direction keeps
// flowing instead of being cut. This preserves long-lived/bidirectional flows
// (a finished request body while the response still streams, SSH, etc.). The
// flow is fully torn down only once BOTH directions have ended. Connections
// that do not support CloseWrite (e.g. the in-process decrypt pipe) fall back
// to a full close, matching the prior HTTP/1.1 Connection: close semantics.
func BridgeNetworkExtensionRuntimeCopyTunnel(ctx context.Context, clientConn io.ReadWriteCloser, upstreamConn io.ReadWriteCloser) {
	bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(ctx, clientConn, upstreamConn, networkExtensionRuntimeCopyTunnelIdleTimeout)
}

func bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(ctx context.Context, clientConn io.ReadWriteCloser, upstreamConn io.ReadWriteCloser, idleTimeout time.Duration) {
	BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(ctx, clientConn, upstreamConn, idleTimeout, networkExtensionRuntimeCopyTunnelHalfCloseLinger(idleTimeout))
}

// BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger bridges two conns with an EXPLICIT full-window idle and
// half-close linger, so the two can be set independently. An interactive East-West flow (ssh) passes idleTimeout=0
// (the full-duplex idle window is UNLIMITED — a live session at a prompt is never reaped) together with a finite
// halfCloseLinger (an ABANDONED half-closed flow is still reclaimed — the leak countermeasure is preserved). The
// default callers pass linger = idleTimeout/8, byte-identical to the prior behavior.
func BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(ctx context.Context, clientConn io.ReadWriteCloser, upstreamConn io.ReadWriteCloser, idleTimeout, halfCloseLinger time.Duration) {
	// ★★ COUNTED HERE BECAUSE HERE IS WHERE EVERY PATH MEETS (2026-08-18). The first version of these counters
	// sat in the runtime-copy HTTP handler, which is ONE of three entry points — steer.go bridges directly for
	// both the ordinary and the interactive (unlimited-idle) case. The declared-posture check caught it within
	// the hour: reaped_idle_total read 8 while started_total read 0, which is not a ratio, it is a counter that
	// is not wired. That is the exact failure the posture file exists to prevent — a zero passing as "nothing
	// happened" when it means "not measured".
	CountNetworkExtensionTunnelStarted()
	defer CountNetworkExtensionTunnelCompleted()
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}
	// An activity counter incremented by reads in both directions; the watchdog uses it to find an idle flow.
	var activity uint64
	// Whether one direction has finished (half-closed). For the log.
	var halfClosed atomic.Bool
	// ★ Was the half-close an ABANDONMENT: true only when the direction that finished closed without carrying
	// a single byte. Only then is the remaining direction reaped with a short linger — a connection pool's
	// miss, a Happy-Eyeballs loser, a closed tab.
	//
	// A flow that SENT a request and then half-closed is not abandoned, it is waiting for a reply, and it
	// keeps the full window. Otherwise a reply that takes a moment to generate, or whose first bytes are
	// delayed through egress — an AI chat, say — is reaped before its response begins. That regression is
	// exactly what introducing the linger caused.
	var abandonedHalfClose atomic.Bool
	done := make(chan struct{}, 2)
	copyHalf := func(dst io.ReadWriteCloser, src io.ReadWriteCloser, direction string) {
		n, err := copyNetworkExtensionRuntimeCopyTunnelTrackingActivity(dst, src, &activity)
		if err != nil && ctx.Err() == nil {
			// Per-flow copy end with a non-EOF category (often a benign peer reset). Diagnostic wire detail —
			// bring it under the same hot-path/DEBUG gate as the EOF sibling so it stops escaping to steady-state
			// stderr (docs/logging_what_to_log_design.md).
			NetworkExtensionHotPathLog("network_extension_runtime_copy_tunnel copy ended direction=%s bytes=%d category=%s", direction, n, NetworkExtensionLabTLSErrorCategory(err))
		} else {
			NetworkExtensionHotPathLog("network_extension_runtime_copy_tunnel copy ended direction=%s bytes=%d category=eof", direction, n)
		}
		// EOF one way: half-close only dst's write side, so the stream in the other direction stays alive.
		// Where CloseWrite is not available — an in-process pipe — this falls back to closing both.
		if halfCloseWriteSide(dst) {
			halfClosed.Store(true)
			if n == 0 {
				// This direction closed without carrying anything: an abandoned client, so the remaining
				// direction may be reaped with the short linger. Had it carried bytes — a half-close after
				// sending a request — a reply may still be coming the other way, and it keeps the full
				// window.
				abandonedHalfClose.Store(true)
			}
		} else {
			closeBoth()
		}
		done <- struct{}{}
	}
	stopWatchdog := make(chan struct{})
	// Run the watchdog when EITHER window is armed. idleTimeout=0 with a finite linger (interactive ssh) means:
	// never reap a live full-duplex idle flow, but still reclaim it once it half-closes WITHOUT having sent
	// anything (abandoned client).
	if idleTimeout > 0 || halfCloseLinger > 0 {
		go watchNetworkExtensionRuntimeCopyTunnelIdle(&activity, idleTimeout, halfCloseLinger, &halfClosed, &abandonedHalfClose, stopWatchdog, closeBoth)
	}
	// downstream_to_upstream is browser to upstream (the request); upstream_to_downstream is upstream to
	// browser (the response).
	go copyHalf(clientConn, upstreamConn, "upstream_to_downstream")
	go copyHalf(upstreamConn, clientConn, "downstream_to_upstream")
	<-done
	<-done
	close(stopWatchdog)
	closeBoth()
}

// steerRelayBufferPool reuses the 32 KiB relay buffers so each steer flow (2 directions) does not
// allocate fresh buffers per bridge, cutting GC pressure under many concurrent clients.
// Stores *[]byte (not []byte) so Put does not box/allocate a slice header.
var steerRelayBufferPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// copyNetworkExtensionRuntimeCopyTunnelTrackingActivity is io.Copy, except that every successful read
// increments the activity counter so the idle watchdog sees progress. EOF counts as success.
func copyNetworkExtensionRuntimeCopyTunnelTrackingActivity(dst io.Writer, src io.Reader, activity *uint64) (int64, error) {
	bufp := steerRelayBufferPool.Get().(*[]byte)
	defer steerRelayBufferPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			atomic.AddUint64(activity, 1)
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}

// networkExtensionRuntimeCopyTunnelHalfCloseLinger is the short idle window applied to the direction that
// remains after the other has half-closed. A flow whose remaining direction then makes no progress is not a
// legitimately idle interactive connection; it is a nearly-abandoned client — a Happy-Eyeballs loser, a closed
// tab. Reaping it at about idleTimeout/8 rather than the full window bounds the accumulation of half-dead
// bridges, which is a goroutine and heap leak and shows up as GC CPU. Any progress resets the idle clock, so a
// flow streaming a response after its request completed — a large download — is not cut.
func networkExtensionRuntimeCopyTunnelHalfCloseLinger(idleTimeout time.Duration) time.Duration {
	return idleTimeout / 8
}

// watchNetworkExtensionRuntimeCopyTunnelIdle samples the activity counter at a fine interval and tears the
// flow down when it passes the applicable window without progress. That window is idleTimeout normally, and
// the shorter halfCloseLinger once one direction has finished. Progress — bytes in either direction — resets
// it, so a streaming response or a keepalive is not cut. The previous implementation took effectively twice
// idleTimeout for a flow that went idle after making progress, because of how last was initialised; this one
// accumulates the idle time and reaps at one window.
func watchNetworkExtensionRuntimeCopyTunnelIdle(activity *uint64, idleTimeout, halfCloseLinger time.Duration, halfClosed, abandonedHalfClose *atomic.Bool, stop <-chan struct{}, onIdle func()) {
	// Poll finely enough for the smallest armed window. idleTimeout=0 means the full window is unlimited, so poll
	// off the linger instead (the only window that can fire).
	poll := idleTimeout / 4
	if halfCloseLinger > 0 && (poll <= 0 || halfCloseLinger/4 < poll) {
		poll = halfCloseLinger / 4
	}
	if poll <= 0 {
		poll = time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	last := atomic.LoadUint64(activity)
	var idle time.Duration
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			current := atomic.LoadUint64(activity)
			if current != last {
				last = current
				idle = 0
				continue
			}
			idle += poll
			// window=0 means the full-duplex idle window is UNLIMITED (interactive ssh): never reap while both
			// directions are open. The short linger applies ONLY to an ABANDONED half-close — a direction that
			// closed WITHOUT sending anything (a connection-pool miss, a Happy-Eyeballs loser, a closed tab). A
			// half-close that carried bytes is a request awaiting its reply, so it keeps the full window: the
			// reply may not begin within the linger (a slow model, or egress latency on an AI-chat stream). This
			// is the #28 regression fix — the 2026-07-10 linger reaped those reply-pending flows.
			window := idleTimeout
			if abandonedHalfClose != nil && abandonedHalfClose.Load() && halfCloseLinger > 0 && (window == 0 || halfCloseLinger < window) {
				window = halfCloseLinger
			}
			if window > 0 && idle >= window {
				neTunnelsReaped.Add(1)
				log.Printf("network_extension_runtime_copy_tunnel progress=tunnel_idle_timeout half_closed=%t abandoned=%t",
					halfClosed != nil && halfClosed.Load(), abandonedHalfClose != nil && abandonedHalfClose.Load())
				onIdle()
				return
			}
		}
	}
}

// halfCloseWriteSide half-closes the write side (sending EOF) when conn has CloseWrite, and returns true. It
// returns false when it does not, and the caller falls back to closing both directions.
func halfCloseWriteSide(conn io.ReadWriteCloser) bool {
	if writeCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = writeCloser.CloseWrite()
		return true
	}
	return false
}

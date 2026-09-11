package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

// edgeConfig holds everything the edge-steering layer needs. It is independent of the capture backend.
type edgeConfig struct {
	edgeURL          string
	applicationID    string
	connectorID      string
	sessionID        string
	connectAuthority string
	omitAuthority    bool
	maxFlows         int
	// genericSteer routes to the W3 generic path CONNECT /steer (no app registration, no authority ==
	// route Destination constraint): the recovered original destination is sent as-is in the authority
	// and the edge applies policy (port->family, east-west/default-deny) to it. When false the
	// flow uses the connector-app route CONNECT /apps/{app}.
	genericSteer bool
	// muxSteer carries every flow over a multiplexed transport connection (CONNECT /steer-mux) instead of a
	// dedicated CONNECT /steer tunnel per flow, collapsing the Edge's per-flow FD/handshake cost to per-device.
	// The Edge runs the SAME policy per OPEN; a denied flow is simply closed (no HTTP status, so no step-up
	// mediation over the mux — use per-flow for that). Falls back to per-flow when false. See steer_mux.go.
	muxSteer bool
	// muxFlowsPerConn / muxMaxConns size the adaptive mux connection pool: desired conns =
	// clamp(1 + activeFlows/muxFlowsPerConn, 1, muxMaxConns). A small pool spreads flows over independent TCP
	// connections (own congestion window / no cross-flow TCP head-of-line blocking / multi-core crypto) while
	// keeping the Edge FD/handshake win. muxMaxConns==1 == the single-connection behaviour. Only used when
	// muxSteer is set.
	muxFlowsPerConn int
	muxMaxConns     int
	// transport is the (T) secure transport (). When enabled, the CONNECT to the edge rides inside a
	// pinned mTLS tunnel to the transport listener instead of a plaintext TCP connection to edgeURL.
	transport transportConfig
	// stepUp mediates agent-driven step-up: on an "authenticate" 401 carrying X-Dsse-Stepup-Url, surface a
	// prompt + open the portal in the default browser (coalesced per resource). nil disables the prompt
	// (the flow is still denied -- fail-closed). Safe to leave nil in tests / non-stepup deployments.
	stepUp *stepUpCoordinator
	// warn surfaces the passive Warn-stage (S3) "monitored" notice on a steer-mux WARN frame. The flow is
	// already allowed + forwarded; nil disables the notice. Coalesced once per service|destination per session.
	warn *warnNotifier
	// failOpen (--fail-open) trades security for availability when the CONTROL PLANE is down: if the Edge is
	// UNREACHABLE (transport error, status==0), the flow is connected straight to its recovered original
	// destination (UNMEDIATED — no interception/policy) instead of being dropped, so the box keeps working
	// during an Edge/tunnel outage. A reachable Edge that returns a policy DENY is still fail-closed. health
	// is the shared circuit breaker so a sustained outage skips the per-flow Edge dial. nil health = fail-closed.
	failOpen bool
	health   *edgeHealth
	// dialTimeout bounds the Edge CONNECT/tunnel dial. Under --fail-open it is set short (a few seconds) so a
	// flow detects an Edge outage and falls through to the direct path quickly instead of hanging ~10s. Zero
	// means the 10s default.
	dialTimeout time.Duration
	// answerNCSI answers the Windows NCSI web probe (msftconnecttest/msftncsi GET on :80) locally instead of
	// steering it, so the OS reliably shows "Internet" under steer-all. See ncsi_answer.go.
	answerNCSI bool
	// interception, when non-nil, periodically verifies what interception is serving this device and journals
	// what the verifiers said. It NEVER changes what happens to a flow — see the posture note at the top of
	// interception_observation.go — and every call on it is nil-safe.
	interception *interceptionWatch
}

// edgeSteerer consumes SteeredFlows from any SteeringCapture and steers each to the edge via CONNECT
// /apps/{app}. It depends only on the SteeringCapture interface -- never on WinDivert -- which is the
// whole point of the W2 seam: swap WinDivert for Wintun/WFP with no change here.
type edgeSteerer struct {
	cfg edgeConfig
	// mux is the shared multiplexed transport, created in run() when cfg.muxSteer is set. run() is a value
	// receiver, but it assigns s.mux before spawning handleFlow goroutines off the SAME local copy s, so every
	// flow shares this one manager. nil when muxSteer is off (per-flow path).
	mux *muxManager
}

func (s edgeSteerer) run(capture SteeringCapture) {
	route := "/apps/" + s.cfg.applicationID
	switch {
	case s.cfg.muxSteer:
		route = "/steer-mux (multiplexed, authority=orig-dst)"
	case s.cfg.genericSteer:
		route = "/steer (generic, authority=orig-dst)"
	}
	fmt.Printf("steer redirect: edge=%s route=%s capture_backend=%s\n", s.cfg.edgeURL, route, capture.Backend())
	if s.cfg.muxSteer {
		s.mux = newMuxManager(s.cfg, s.cfg.dialTimeout, s.cfg.muxFlowsPerConn, s.cfg.muxMaxConns)
		fmt.Printf("steer mux pool: flows-per-conn=%d max-conns=%d\n", s.mux.flowsPerConn, s.mux.maxConns)
		// The interception probe has to reach a destination the way the APPLICATION reached it — through this
		// same mux, so the Edge intercepts it identically. Wired here rather than where the watch is built,
		// because that is where the mux first exists. The loop starts here for the same reason, and it stops
		// when the capture does: an agent that is no longer steering has nothing to probe.
		if s.cfg.interception != nil {
			mm := s.mux
			s.cfg.interception.probe = makeInterceptionProbe(func(authority string) (net.Conn, error) {
				mux, err := mm.acquire()
				if err != nil {
					return nil, err
				}
				return mux.openFlow(authority)
			})
			stop := make(chan struct{})
			defer close(stop)
			go s.cfg.interception.run(stop)
			fmt.Printf("steer: interception verification enabled (one probe every %s through the mux; refusals are "+
				"journaled and reported, and NOTHING is blocked on a refusal)\n", interceptionProbeInterval)
		}
	}
	count := 0
	for flow := range capture.Flows() {
		// Handle each flow concurrently: handleFlow blocks in pipe() until the flow tears down, and real
		// clients (browsers) open MANY long-lived connections at once (HTTP/2). Servicing flows serially
		// would wedge the loop on the first long-lived connection and stall every other flow -- the cause
		// of browser page loads timing out under steer-all even though the NAT path was clean.
		count++
		go s.handleFlow(flow)
		if s.cfg.maxFlows > 0 && count >= s.cfg.maxFlows {
			fmt.Printf("steer: reached max-flows=%d\n", s.cfg.maxFlows)
			return
		}
	}
}

func (s edgeSteerer) handleFlow(flow SteeredFlow) {
	defer flow.Conn.Close()
	origDst := flow.OrigDst

	// NCSI web probe (port 80 only — HTTP, client speaks first): answer Windows' connectivity probe locally so
	// the box reliably shows "Internet" under steer-all (the probe would otherwise be funneled through the
	// tunnel and time out -> "No Internet", confusing users/apps). A non-NCSI :80 flow is forwarded unchanged
	// with the peeked bytes replayed.
	if s.cfg.answerNCSI && origDst.Port() == 80 {
		if handled, consumed := answerNCSIWebProbe(flow.Conn); handled {
			fmt.Printf("ncsi_web_probe answered locally dst=%s\n", origDst)
			return
		} else if len(consumed) > 0 {
			flow.Conn = &prefixConn{Conn: flow.Conn, prefix: consumed}
		}
	}

	// fail-open: if the circuit is already open from a recent outage, skip the Edge dial and go direct now
	// (no per-flow timeout while the control plane is down).
	// ★★★ NOT INTO A FAMILY THIS DEPLOYMENT CANNOT CARRY (2026-08-25). See
	// deployment_carries_family.go: the flow is captured as always — not capturing it would let it leave
	// unmediated — and closed here rather than sent to an Edge that will close it with no bytes anyway. The
	// application falls back to the other family and that flow is steered normally.
	if !deploymentCarries(origDst) {
		fmt.Printf("steer_family_not_carried dst=%s — this deployment declared it cannot egress that address "+
			"family; closing here so the application falls back, instead of spending a round trip on an Edge "+
			"that would close it with no bytes\n", origDst)
		return
	}

	if s.cfg.failOpen && !s.cfg.health.shouldTryEdge() {
		s.failOpenDirect(flow, origDst, "edge_circuit_open")
		return
	}

	// Multiplexed carriage: hand the flow to the shared mux (one transport connection for all flows) instead of
	// dialing a dedicated CONNECT /steer tunnel. Same policy/interception on the Edge; only the carriage differs.
	if s.cfg.muxSteer {
		s.handleFlowMux(flow, origDst)
		return
	}

	edgeConn, status, body, stepUpURL, err := dialEdgeCONNECT(s.cfg, origDst)
	decision := decisionForStatus(status, body, err)
	if decision == "error" {
		// Surface WHY the Edge was unreachable (timeout / connection refused / no route) — the key signal when
		// diagnosing a network switch: it shows whether the tunnel failed to re-establish on the new link.
		fmt.Printf("steer_edge_decision decision=error dst=%s status=0 err=%v\n", origDst, err)
	} else {
		fmt.Printf("steer_edge_decision decision=%s dst_port=%d status=%d\n", decision, origDst.Port(), status)
	}
	if err != nil {
		// status==0 means the Edge was UNREACHABLE at the transport layer (dial/timeout), NOT a policy deny.
		// In fail-open mode that trips the breaker and the flow goes direct (unmediated) so the box keeps
		// working through a control-plane outage. Fail-closed mode (and a reachable-but-deny Edge) fall through.
		// ★★★ A REFUSED HANDSHAKE USED TO BE EXCLUDED FROM FAIL-OPEN HERE, AND IT IS NOT ANY MORE (removed
		// 2026-08-26, the operator's ruling — see muxUnreachable). A refusal arrives identically whatever
		// caused it, so excluding it turned an expired device certificate into a fleet that cannot work.
		// fail-open means the device keeps working unprotected when this deployment cannot mediate for it,
		// whatever the reason; an operator who wants a block to stop a device chooses fail-closed.
		if status == 0 && s.cfg.failOpen {
			if opened := s.cfg.health.recordFailure(); opened {
				fmt.Printf("steer_failopen: edge unreachable (%v) — circuit OPEN, flows go direct for the cooldown\n", err)
			}
			s.failOpenDirect(flow, origDst, "edge_unreachable")
			return
		}
		if status != 0 {
			s.cfg.health.recordSuccess() // edge answered (a deny/401) -> control plane is healthy, enforce.
		}
		// Agent-mediated step-up: an "authenticate" deny on a steered native (SMB/RDP/WinRM) flow carries a
		// portal URL the user opens out-of-band (a native client cannot follow a 302). Surface it; the flow
		// itself STAYS denied (fail-closed) -- once the user completes the step-up a device grant is minted and
		// the retried connection is allowed. Coalesced per resource so a burst opens the portal once.
		if decision == "authenticate_required" && stepUpURL != "" {
			s.cfg.stepUp.Trigger(origDst.String(), stepUpURL)
		}
		fmt.Printf("steer_blocked reason=%s dst_port=%d edge_body=%q\n", decision, origDst.Port(), body)
		return
	}
	s.cfg.health.recordSuccess()
	defer edgeConn.Close()
	fmt.Printf("steer_forwarded dst_port=%d\n", origDst.Port())

	toEdge, toApp := pipe(flow.Conn, edgeConn, fmt.Sprintf("dst=%s", origDst))
	fmt.Printf("steer_bytes dst_port=%d app_to_edge=%d edge_to_app=%d\n", origDst.Port(), toEdge, toApp)
}

// failOpenDirect connects straight to the recovered original destination and pipes the app's bytes through —
// used ONLY in --fail-open mode when the Edge is unreachable. The flow is UNMEDIATED (no interception, no
// policy) for the outage window; this is the explicit availability-over-security tradeoff selected at install
// time. Logged loudly so the unmediated window is visible in the agent log. The agent's own connections are
// excluded from WFP capture, so this direct dial is not re-redirected (no loop).
func (s edgeSteerer) failOpenDirect(flow SteeredFlow, origDst netip.AddrPort, reason string) {
	fmt.Printf("steer_failopen_direct dst=%s reason=%s (UNMEDIATED — edge bypassed)\n", origDst.String(), reason)
	d := net.Dialer{Timeout: 10 * time.Second}
	direct, err := d.Dial("tcp", origDst.String())
	if err != nil {
		fmt.Printf("steer_failopen_direct_failed dst=%s err=%v\n", origDst.String(), err)
		return
	}
	defer direct.Close()
	pipe(flow.Conn, direct, fmt.Sprintf("failopen dst=%s", origDst))
}

func decisionForStatus(status int, body string, err error) string {
	switch {
	case err != nil && status == 0:
		return "error"
	case status == 200:
		return "allow"
	case status == 401:
		return "authenticate_required"
	case status == 502 && strings.Contains(body, "connector tunnel is required"):
		// Edge passed policy (connector_route_allowed) but no connector tunnel was registered, so it
		// could not complete the CONNECT. The decision was ALLOW; the backend tunnel was unavailable.
		return "allow_no_tunnel"
	default:
		return "deny"
	}
}

// dialEdgeCONNECT opens a CONNECT tunnel to the edge for the recovered original destination. It returns
// the tunneled connection (on 200), the HTTP status, a bounded body snippet (on non-200), the step-up portal
// URL the edge advertised (X-Dsse-Stepup-Url, present on an "authenticate" 401; "" otherwise), and any error.
// Mirrors cmd/localproxy's edge CONNECT client; the connect-authority carries the destination so edge
// policy keys on it.
func dialEdgeCONNECT(cfg edgeConfig, origDst netip.AddrPort) (net.Conn, int, string, string, error) {
	dialTimeout := cfg.dialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	var conn net.Conn
	var host string
	if cfg.transport.enabled {
		// (T) secure transport: TLS+mTLS tunnel to the Edge; the CONNECT/steer rides INSIDE it so SNI and
		// destination metadata never appear in plaintext on the endpoint or local network.
		host = cfg.transport.host
		c, err := cfg.transport.dial(dialTimeout)
		if err != nil {
			return nil, 0, "", "", err
		}
		conn = c
	} else {
		h, err := edgeHostPort(cfg.edgeURL)
		if err != nil {
			return nil, 0, "", "", err
		}
		host = h
		dialer := net.Dialer{Timeout: dialTimeout}
		c, err := dialer.Dial("tcp", host)
		if err != nil {
			return nil, 0, "", "", err
		}
		conn = c
	}
	// W3 generic steer: send the recovered original destination as the authority to CONNECT /steer; the
	// edge derives port->family and applies policy. No app id, no authority override.
	authority := origDst.String()
	target := "/steer"
	sendAuthority := true
	if !cfg.genericSteer {
		// Connector-app route: authority must equal the app's route Destination (override allowed).
		if cfg.connectAuthority != "" {
			authority = cfg.connectAuthority
		}
		target = fmt.Sprintf("/apps/%s", cfg.applicationID)
		if cfg.connectorID != "" {
			target += "?connector_id=" + cfg.connectorID
		}
		sendAuthority = !cfg.omitAuthority
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	if sendAuthority {
		fmt.Fprintf(&b, "x-dsse-connect-authority: %s\r\n", authority)
	}
	if cfg.sessionID != "" {
		fmt.Fprintf(&b, "x-session-id: %s\r\n", cfg.sessionID)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		return nil, 0, "", "", err
	}
	reader := bufio.NewReader(conn)
	status, headers, err := readCONNECTStatus(reader)
	if err != nil {
		conn.Close()
		return nil, status, "", "", err
	}
	// The Edge advertises the step-up portal on an "authenticate" deny via X-Dsse-Stepup-Url (it is empty on
	// an allow/200). Surface it to the caller so the agent can open it out-of-band for native flows.
	stepUpURL := strings.TrimSpace(headers.Get(stepUpChallengeHeader))
	if status != 200 {
		// Read a bounded body snippet so the caller can distinguish an allow-but-no-tunnel/route-mismatch
		// 502 from a real policy deny. Bounded by a read deadline so a half-open connection cannot block.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		snippet, _ := io.ReadAll(io.LimitReader(reader, 512))
		conn.Close()
		return nil, status, strings.TrimSpace(string(snippet)), stepUpURL, fmt.Errorf("edge CONNECT status %d", status)
	}
	return &bufferedConn{Conn: conn, reader: reader}, status, "", stepUpURL, nil
}

// readCONNECTStatus reads the CONNECT response status line and the response headers up to the blank line,
// returning the status code and the parsed headers (so the caller can read X-Dsse-Stepup-Url on a 401). The
// underlying bufio.Reader is left positioned at the start of the tunnel body (the CONNECT payload on a 200).
func readCONNECTStatus(reader *bufio.Reader) (int, textproto.MIMEHeader, error) {
	tp := textproto.NewReader(reader)
	statusLine, err := tp.ReadLine()
	if err != nil {
		return 0, nil, err
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return 0, nil, fmt.Errorf("malformed CONNECT status line %q", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, nil, fmt.Errorf("bad CONNECT status %q", fields[1])
	}
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return code, headers, err
	}
	return code, headers, nil
}

func edgeHostPort(edgeURL string) (string, error) {
	u := edgeURL
	switch {
	case strings.HasPrefix(u, "http://"):
		u = strings.TrimPrefix(u, "http://")
	case strings.HasPrefix(u, "https://"):
		return "", errors.New("https edge not supported in W1/W2 (use http lab edge)")
	}
	u = strings.TrimRight(u, "/")
	if !strings.Contains(u, ":") {
		u += ":80"
	}
	if _, _, err := net.SplitHostPort(u); err != nil {
		return "", fmt.Errorf("invalid edge host %q: %w", u, err)
	}
	return u, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// CloseWrite forwards the half-close to the wrapped conn. Embedding net.Conn does NOT promote CloseWrite —
// it is not part of the interface — so without this the wrapper hides a real TCP half-close from pipe().
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// pipe copies bytes both ways between the app-side conn a and the edge-side conn b, returning the byte
// counts (a->b, b->a) once the connection tears down. Counts localize a broken data path.
// A one-way EOF ends one DIRECTION, not the connection. Closing both sides as soon as either io.Copy returned
// discarded replies the server had not finished sending: an app that half-closes after its request (the
// ChatGPT desktop app does) had its answer thrown away mid-stream. The request still reached the server — the
// same answer showed up on the user's phone — it just had nowhere to be delivered. Measured on win-dev-1:
// flows whose app->edge side ended while the edge->app side had NOT (#28), and browsers losing the tail of
// otherwise-complete responses the same way.
//
// So propagate each direction's end on its own and only tear the flow down once BOTH are finished.
func pipe(a, b net.Conn, label string) (int64, int64) {
	var aToB, bToA int64
	var wg sync.WaitGroup
	wg.Add(2)
	t0 := time.Now()
	go func() {
		defer wg.Done()
		var err error
		aToB, err = io.Copy(b, a)
		fmt.Printf("pipe_dir_end %s dir=app->edge bytes=%d at=%.1fs err=%v\n", label, aToB, time.Since(t0).Seconds(), err)
		halfCloseWrite(b) // app stopped sending; the response keeps flowing
	}()
	go func() {
		defer wg.Done()
		var err error
		// This error used to be discarded. A failure WRITING the reply into the application socket is exactly
		// the case #28 has to distinguish, and it was invisible.
		bToA, err = io.Copy(a, b)
		fmt.Printf("pipe_dir_end %s dir=edge->app bytes=%d at=%.1fs err=%v\n", label, bToA, time.Since(t0).Seconds(), err)
		halfCloseWrite(a) // response finished; let the app see EOF
	}()
	wg.Wait()
	a.Close()
	b.Close()
	return aToB, bToA
}

// halfCloseWrite ends the write side of conns that can express it, leaving the read side alive. Conns without
// CloseWrite simply stay fully open until pipe tears them down, which costs nothing but a later teardown.
func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

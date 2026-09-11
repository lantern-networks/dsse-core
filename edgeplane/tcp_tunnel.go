package edgeplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func ProxyConnectViaTunnel(w http.ResponseWriter, r *http.Request, session *tunnel.Session, conn model.ConnectorRegistration, dec model.AccessDecision, decisionReq model.DecisionRequest, appendAudit ConnectorAuditFunc, applicationID string, routeProfiles map[string]ApplicationRouteProfile) {
	openFrame, err := edgeTCPConnectOpenFrameForRequest(r, applicationID, routeProfiles)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	streamCh, cleanup, _, err := session.OpenTCP(r.Context(), openFrame)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer cleanup()

	if err := appendAudit(r.Context(), "private_app_tcp_session_started", conn, PrivateAppTCPSessionAuditDetails(dec, decisionReq, openFrame, ApplicationRouteProfileFor(applicationID, routeProfiles), session.TunnelID)); err != nil {
		_ = session.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: openFrame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError})
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = session.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: openFrame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError})
		writeError(w, http.StatusInternalServerError, fmt.Errorf("response writer does not support CONNECT hijack"))
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		_ = session.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: openFrame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError})
		log.Printf("hijack CONNECT response: %v", err)
		return
	}
	defer clientConn.Close()
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("write CONNECT established response: %v", err)
		return
	}
	if err := rw.Flush(); err != nil {
		log.Printf("flush CONNECT established response: %v", err)
		return
	}

	done := make(chan error, 2)
	go func() {
		done <- CopyEdgeTCPClientToTunnel(r.Context(), session, openFrame.RequestID, clientConn)
	}()
	go func() {
		done <- CopyEdgeTCPTunnelToClient(streamCh, clientConn)
	}()
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		Debugf("CONNECT tunnel copy ended: %v", err)
	}
}

func PrivateAppTCPSessionAuditDetails(dec model.AccessDecision, req model.DecisionRequest, openFrame tunnel.Frame, profile ApplicationRouteProfile, tunnelID string) map[string]any {
	details := map[string]any{
		"access_decision_id":                dec.ID,
		"application_id":                    req.ApplicationID,
		"application_sensitivity":           req.ApplicationSensitivity,
		"decision":                          dec.Decision,
		"destination_port":                  req.DestinationPort,
		"destination_role":                  req.DestinationRole,
		"network_extension_runtime_used":    false,
		"private_app_session_audit":         true,
		"private_app_session_audit_event":   "tcp_session_started",
		"private_app_session_audit_version": "m813.v1",
		"protocol":                          valueOrDefault(req.Protocol, "tcp"),
		"raw_payload_logged":                false,
		"credential_material_logged":        false,
		"service_family":                    req.ServiceFamily,
		"tcp_byte_cap":                      openFrame.ByteCap,
		"tcp_concurrent_connection_cap":     openFrame.ConcurrentConnectionCap,
		"tcp_connect_timeout_ms":            openFrame.ConnectTimeoutMillis,
		"tcp_idle_timeout_ms":               openFrame.IdleTimeoutMillis,
		"tcp_max_connection_lifetime_ms":    openFrame.MaxConnectionLifetimeMillis,
		"tcp_request_id":                    openFrame.RequestID,
		"transport_path":                    "edge_connector_tcp_tunnel",
	}
	if tunnelID != "" {
		details["tunnel_id"] = tunnelID
	}
	if isDatabaseServiceFamily(req.ServiceFamily) {
		details["database_protocol"] = databaseProtocolAuditCategory(profile)
		details["database_query_metadata_mode"] = "category_only"
		details["database_query_text_logged"] = false
		details["database_parameter_values_logged"] = false
	}
	return details
}

func isDatabaseServiceFamily(serviceFamily string) bool {
	switch strings.ToLower(strings.TrimSpace(serviceFamily)) {
	case "database", "db":
		return true
	default:
		return false
	}
}

func databaseProtocolAuditCategory(profile ApplicationRouteProfile) string {
	switch strings.ToLower(strings.TrimSpace(profile.DatabaseProtocol)) {
	case "postgres", "postgresql":
		return "postgresql"
	case "mysql":
		return "mysql"
	case "mariadb":
		return "mariadb"
	case "mssql", "sqlserver", "sql_server":
		return "mssql"
	default:
		return "database"
	}
}

func edgeTCPConnectOpenFrameForRequest(r *http.Request, applicationID string, routeProfiles map[string]ApplicationRouteProfile) (tunnel.Frame, error) {
	clientHost, clientPort, err := edgeConnectAuthority(r)
	if err != nil {
		return tunnel.Frame{}, err
	}
	target, err := EdgeTCPConnectTargetForApplication(applicationID, clientHost, clientPort, routeProfiles)
	if err != nil {
		return tunnel.Frame{}, err
	}
	return EdgeTCPOpenFrameForTarget(randomEdgeID("req_tcp_", time.Now().UTC()), target, defaultEdgeTCPConnectLimits())
}

func edgeConnectAuthority(r *http.Request) (string, int, error) {
	if header := strings.TrimSpace(r.Header.Get(ConnectAuthorityHeader)); header != "" {
		return parseEdgeConnectAuthorityCandidate(header)
	}
	for _, candidate := range []string{r.Host, r.URL.Opaque, r.RequestURI, r.URL.Path, r.URL.Host} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == "/" {
			continue
		}
		host, port, err := parseEdgeConnectAuthorityCandidate(candidate)
		if err != nil {
			continue
		}
		return host, port, nil
	}
	return "", 0, fmt.Errorf("CONNECT authority host:port is required")
}

func parseEdgeConnectAuthorityCandidate(candidate string) (string, int, error) {
	host, portText, err := net.SplitHostPort(candidate)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("CONNECT authority port %q is invalid", portText)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", 0, fmt.Errorf("CONNECT authority host is required")
	}
	return host, port, nil
}

func defaultEdgeTCPConnectLimits() EdgeTCPConnectLimits {
	return EdgeTCPConnectLimits{
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}

// InteractiveEastWestEdgeTCPConnectLimits is for a STEERED interactive East-West session (ssh/rdp) egressing over
// the connector tunnel. idle=0 and lifetime=0 mean UNLIMITED (0 = unlimited in ValidateTCPOpenFrame): an
// interactive session must never be torn down by a timer — a user can sit at a prompt, or wait on a long silent
// command, for an arbitrary time. The connector therefore never reaps the stream on idle/lifetime; teardown is
// driven by the natural EOF/RST relayed from the Edge bridge, which keeps a half-close linger so an ABANDONED
// (half-closed) flow is still reclaimed. The byte cap (1 GiB) + concurrency cap still bound resource use, so an
// unlimited-lifetime flow cannot leak unbounded bytes. (The 30s default connector-stream idle used to drop ssh
// after ~30s; a bounded 5m idle still cut a thinking session — hence unlimited for interactive.)
func InteractiveEastWestEdgeTCPConnectLimits() EdgeTCPConnectLimits {
	return EdgeTCPConnectLimits{
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: 0, // unlimited
		IdleTimeoutMillis:           0, // unlimited
		ByteCap:                     tunnel.MaxTCPByteCap,
		ConcurrentConnectionCap:     32,
	}
}

func CopyEdgeTCPClientToTunnel(ctx context.Context, session *tunnel.Session, RequestID string, client net.Conn) error {
	bufferPool := tunnel.DefaultTCPFrameBufferPool()
	for {
		frame, n, readErr := bufferPool.ReadTCPDataFrame(client, RequestID, tunnel.TCPDirectionUp)
		if n > 0 {
			if err := session.WriteTCPStreamFrame(frame); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.ErrNoProgress) {
				continue
			}
			reason := tunnel.TCPCloseReasonError
			if errors.Is(readErr, io.EOF) {
				reason = tunnel.TCPCloseReasonEOF
			}
			closeFrame := tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: reason}
			if reason == tunnel.TCPCloseReasonError {
				closeFrame.Error = readErr.Error()
			}
			if err := session.WriteTCPStreamFrame(closeFrame); err != nil {
				return err
			}
			return readErr
		}
		select {
		case <-ctx.Done():
			closeFrame := tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError, Error: ctx.Err().Error()}
			_ = session.WriteTCPStreamFrame(closeFrame)
			return ctx.Err()
		default:
		}
	}
}

// ProxyPublishedWebAppViaTunnel serves a PUBLISHED web private app (publish_protocol=web with a routable
// destination) over the connector tunnel's raw TCP (CONNECT) path: the edge opens a FrameTCPOpen to the
// published destination:port and runs a one-shot HTTP request/response over that stream, returning the real
// backend response to the data-plane client.
//
// This is the fix for the HTTP-GET data path: the legacy /apps/{id} GET forwarded a FrameHTTPRequest to the
// connector's privateBaseURL (its built-in server) and ignored the published destination. A connector-
// discovered web app has no privateBaseURL handler — only the published destination is reachable — so the GET
// is proxied over the same FrameTCPOpen-to-destination mechanism the CONNECT path uses. The connector
// authorizes the destination with its existing reachable_routes layer (no connector change required).
//
// Secret-safe: the connector's privateBaseURL / runtime secret is never read or forwarded here; only the
// non-secret destination:port (already authorized by policy in handleConnectorApplication) is dialed. The
// audit event carries no body, credential, or private_base_url.
func ProxyPublishedWebAppViaTunnel(w http.ResponseWriter, r *http.Request, session *tunnel.Session, conn model.ConnectorRegistration, dec model.AccessDecision, decisionReq model.DecisionRequest, appendAudit ConnectorAuditFunc, applicationID string, routeProfiles map[string]ApplicationRouteProfile) {
	profile := ApplicationRouteProfileFor(applicationID, routeProfiles)
	host := strings.TrimSpace(profile.Destination)
	if host == "" || profile.DestinationPort <= 0 {
		writeError(w, http.StatusBadGateway, fmt.Errorf("published web application %s has no routable destination", applicationID))
		return
	}
	target := EdgeTCPConnectTarget{ApplicationID: applicationID, Host: host, Port: profile.DestinationPort, ServiceFamily: profile.ServiceFamily}
	openFrame, err := EdgeTCPOpenFrameForTarget(randomEdgeID("req_web_", time.Now().UTC()), target, defaultEdgeTCPConnectLimits())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	streamCh, cleanup, _, err := session.OpenTCP(r.Context(), openFrame)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer cleanup()

	if err := appendAudit(r.Context(), "private_app_web_session_started", conn, PrivateAppWebSessionAuditDetails(dec, decisionReq, openFrame, profile, session.TunnelID)); err != nil {
		_ = session.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: openFrame.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonError})
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	streamConn := &tunnelTCPStreamConn{session: session, RequestID: openFrame.RequestID, streamCh: streamCh, ctx: r.Context()}
	defer streamConn.Close()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return streamConn, nil
		},
	}
	backendURL := "http://" + net.JoinHostPort(host, strconv.Itoa(profile.DestinationPort)) + publishedWebAppBackendPath(r)
	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, backendURL, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	outReq.Header.Set("connection", "close")
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("proxy published web app response: %v", err)
	}
}

// publishedWebAppBackendPath maps the data-plane request to a backend path. The /apps/{id} route has no path
// suffix, so the web app root ("/") is requested; an explicit ?path= override (leading slash enforced) lets a
// caller target a sub-path without exposing the connector's privateBaseURL.
func publishedWebAppBackendPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func isHopByHopHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func PrivateAppWebSessionAuditDetails(dec model.AccessDecision, req model.DecisionRequest, openFrame tunnel.Frame, profile ApplicationRouteProfile, tunnelID string) map[string]any {
	details := PrivateAppTCPSessionAuditDetails(dec, req, openFrame, profile, tunnelID)
	details["private_app_session_audit_event"] = "web_session_started"
	details["transport_path"] = "edge_connector_web_http_over_tcp_tunnel"
	return details
}

// tunnelTCPStreamConn adapts a connector tunnel TCP stream (FrameTCPOpen reply channel + FrameTCPData up
// writes) to a net.Conn so the edge can run an HTTP client over the CONNECT-over-tunnel path. Deadlines are
// no-ops: cancellation is driven by the request context the stream was opened with.
type tunnelTCPStreamConn struct {
	session   *tunnel.Session
	RequestID string
	streamCh  <-chan tunnel.Frame
	ctx       context.Context
	readBuf   []byte
	readErr   error
	closeOnce sync.Once
}

func (c *tunnelTCPStreamConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		select {
		case frame, ok := <-c.streamCh:
			if !ok {
				c.readErr = io.EOF
				return 0, io.EOF
			}
			switch frame.Type {
			case tunnel.FrameTCPData:
				payload, err := tunnel.TCPDataFramePayload(frame)
				if err != nil {
					c.readErr = err
					return 0, err
				}
				c.readBuf = payload
			case tunnel.FrameTCPClose:
				if frame.Error != "" {
					c.readErr = errors.New(frame.Error)
				} else {
					c.readErr = io.EOF
				}
				return 0, c.readErr
			default:
				c.readErr = fmt.Errorf("edge web proxy received unexpected frame type %s", frame.Type)
				return 0, c.readErr
			}
		case <-c.ctx.Done():
			c.readErr = c.ctx.Err()
			return 0, c.readErr
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *tunnelTCPStreamConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > tunnel.MaxTCPDataFramePayloadBytes {
			chunk = chunk[:tunnel.MaxTCPDataFramePayloadBytes]
		}
		frame, err := tunnel.NewTCPDataFrame(c.RequestID, tunnel.TCPDirectionUp, chunk)
		if err != nil {
			return written, err
		}
		if err := c.session.WriteTCPStreamFrame(frame); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *tunnelTCPStreamConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.session.WriteTCPStreamFrame(tunnel.Frame{Type: tunnel.FrameTCPClose, RequestID: c.RequestID, Direction: tunnel.TCPDirectionLocal, CloseReason: tunnel.TCPCloseReasonEOF})
	})
	return nil
}

func (c *tunnelTCPStreamConn) LocalAddr() net.Addr              { return tunnelStreamAddr(c.RequestID) }
func (c *tunnelTCPStreamConn) RemoteAddr() net.Addr             { return tunnelStreamAddr(c.RequestID) }
func (c *tunnelTCPStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelTCPStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelTCPStreamConn) SetWriteDeadline(time.Time) error { return nil }

type tunnelStreamAddr string

func (a tunnelStreamAddr) Network() string { return "dsse-tunnel" }
func (a tunnelStreamAddr) String() string  { return string(a) }

func CopyEdgeTCPTunnelToClient(streamCh <-chan tunnel.Frame, client net.Conn) error {
	for frame := range streamCh {
		switch frame.Type {
		case tunnel.FrameTCPData:
			if frame.Direction != tunnel.TCPDirectionDown {
				return fmt.Errorf("edge CONNECT expected down tcp_data, got %s", frame.Direction)
			}
			payload, err := tunnel.TCPDataFramePayload(frame)
			if err != nil {
				return err
			}
			if _, err := client.Write(payload); err != nil {
				return err
			}
		case tunnel.FrameTCPClose:
			if frame.Error != "" {
				return errors.New(frame.Error)
			}
			return io.EOF
		default:
			return fmt.Errorf("edge CONNECT received unexpected frame type %s", frame.Type)
		}
	}
	return io.EOF
}

// ConnectorAuditFunc is the injected connector-audit appender: the composition root
// (cmd/edge) binds it to its log writer + domain-event outbox; edgeplane only states
// WHAT happened. Adapters stay in the composition root (advisory caution 6).
type ConnectorAuditFunc func(ctx context.Context, eventType string, conn model.ConnectorRegistration, details map[string]any) error

// ConnectAuthorityHeader carries the client-requested CONNECT authority through the
// steer mux to the tunnel open. Shared with cmd/edge's runtime auth checks.
const ConnectAuthorityHeader = "x-dsse-connect-authority"

// Private copies of trivial cmd/edge helpers (duplicated rather than a util seam).
var edgeplaneIDFallbackCounter atomic.Uint64

func randomEdgeID(prefix string, fallback time.Time) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return prefix + hex.EncodeToString(random[:])
	} else {
		log.Printf("WARN: crypto/rand failed for %s id, falling back to process-local entropy: %v", strings.TrimSuffix(prefix, "_"), err)
	}
	return fmt.Sprintf("%s%d_%d_%d", prefix, fallback.UTC().UnixNano(), os.Getpid(), edgeplaneIDFallbackCounter.Add(1))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

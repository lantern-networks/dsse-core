package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	FrameHTTPRequest   = "http_request"
	FrameHTTPResponse  = "http_response"
	FrameTCPOpen       = "tcp_open"
	FrameTCPOpenResult = "tcp_open_result"
	FrameTCPData       = "tcp_data"
	FrameTCPClose      = "tcp_close"
	// FrameProbeRequest / FrameProbeResult are the additive reachability-diagnostics frames (Connector UX
	// Slice 3): the edge asks the connector to probe ONE destination (DNS/TCP/TLS/HTTP) and the connector
	// returns a secret-safe, layer-by-layer ProbeResult. They are request/response (like HTTP frames), not a
	// byte stream, and do not move payload bytes — they carry diagnostics only.
	FrameProbeRequest = "probe_request"
	FrameProbeResult  = "probe_result"
	// FrameDNSQuery / FrameDNSResult carry a RAW DNS query to be resolved INSIDE the private network by the
	// connector (the Edge cannot reach internal DNS directly). The connector forwards the raw query to the
	// internal DNS server (UDP, TCP on truncation) and returns the raw response, so every record type — SRV
	// especially, for AD DC-locator — is preserved. See docs/dns_conditional_forwarding_design.md. Request/
	// response like the probe frames; DNS bytes travel base64 in DNSQuery/DNSResponse.
	FrameDNSQuery  = "dns_query"
	FrameDNSResult = "dns_result"
)

const DefaultRequestTimeout = 10 * time.Second

// ErrTCPOpenTimeout means the shared tunnel did not answer an open request.
// A backend refusal or a caller cancellation does not imply this failure.
var ErrTCPOpenTimeout = errors.New("tcp open timed out")

const (
	TCPDirectionUp     = "up"
	TCPDirectionDown   = "down"
	TCPDirectionLocal  = "local"
	TCPDirectionRemote = "remote"
)

const (
	TCPCloseReasonEOF                   = "eof"
	TCPCloseReasonError                 = "error"
	TCPCloseReasonTimeout               = "timeout"
	TCPCloseReasonDenied                = "denied"
	TCPCloseReasonByteCapExceeded       = "byte_cap_exceeded"
	TCPCloseReasonLifetimeExceeded      = "lifetime_exceeded"
	TCPCloseReasonIdleTimeoutExceeded   = "idle_timeout_exceeded"
	TCPCloseReasonConcurrentCapExceeded = "concurrent_cap_exceeded"
)

const (
	MaxTCPDataFramePayloadBytes    = 64 << 10
	MaxTCPConnectTimeoutMillis     = int((30 * time.Second) / time.Millisecond)
	MaxTCPConnectionLifetimeMillis = int((1 * time.Hour) / time.Millisecond)
	MaxTCPIdleTimeoutMillis        = int((5 * time.Minute) / time.Millisecond)
	MaxTCPByteCap                  = int64(1 << 30)
	MaxTCPConcurrentConnections    = 1024
)

type Frame struct {
	Type                        string `json:"type"`
	RequestID                   string `json:"request_id,omitempty"`
	TunnelID                    string `json:"tunnel_id,omitempty"`
	ApplicationID               string `json:"application_id,omitempty"`
	Method                      string `json:"method,omitempty"`
	Path                        string `json:"path,omitempty"`
	StatusCode                  int    `json:"status_code,omitempty"`
	ContentType                 string `json:"content_type,omitempty"`
	Body                        string `json:"body,omitempty"`
	Error                       string `json:"error,omitempty"`
	Host                        string `json:"host,omitempty"`
	Port                        int    `json:"port,omitempty"`
	ConnectTimeoutMillis        int    `json:"connect_timeout_ms,omitempty"`
	MaxConnectionLifetimeMillis int    `json:"max_connection_lifetime_ms,omitempty"`
	IdleTimeoutMillis           int    `json:"idle_timeout_ms,omitempty"`
	ByteCap                     int64  `json:"byte_cap,omitempty"`
	ConcurrentConnectionCap     int    `json:"concurrent_connection_cap,omitempty"`
	Direction                   string `json:"direction,omitempty"`
	Data                        string `json:"data,omitempty"`
	CloseReason                 string `json:"close_reason,omitempty"`
	// TenantID is the organization the relayed flow belongs to.
	//
	// ★★★ A RELAY LOST WHOSE FLOW IT WAS (2026-09-01, measured on a customer's connector pair). An Edge that
	// cannot serve a connector itself relays the open to the Edge that can — across regions over the mesh, and
	// within a region to a sibling. The receiving side dialled every relayed open under ITS OWN default
	// organization, which its own comment said out loud, so a connector belonging to a customer was never
	// found at the far end: the flow was dialled directly and refused by the egress guard.
	//
	// A connector is matched WITHIN an organization, so the organization has to cross the hop with the flow.
	// Both ends of this link are this deployment's own Edges, authenticated to each other by the management
	// CA, so the value is as trustworthy on arrival as it was on departure — and the receiver still applies
	// its own residency rules to it.
	TenantID       string `json:"tenant_id,omitempty"`
	BytesUp        int64  `json:"bytes_up,omitempty"`
	BytesDown      int64  `json:"bytes_down,omitempty"`
	DurationMillis int64  `json:"duration_ms,omitempty"`
	// Probe fields (Slice 3 reachability diagnostics). ProbeProtocol selects how deep the connector probes
	// ("web" => DNS+TCP+TLS+HTTP; "tcp" => DNS+TCP only). Probe carries the secret-safe result on the
	// response frame. Both are omitempty so non-probe frames are byte-identical to before.
	ProbeProtocol string `json:"probe_protocol,omitempty"`
	// ProbeConnectorID preserves the selected connector across an authenticated peer-edge relay.
	ProbeConnectorID string       `json:"probe_connector_id,omitempty"`
	Probe            *ProbeResult `json:"probe,omitempty"`
	// DNS conditional-forward fields (FrameDNSQuery/FrameDNSResult). DNSUpstream is the internal DNS server to
	// query (e.g. "10.10.0.10:53"); DNSQuery/DNSResponse are the RAW DNS message bytes, base64-encoded. All
	// omitempty so non-DNS frames are byte-identical to before.
	DNSUpstream string `json:"dns_upstream,omitempty"`
	DNSQuery    string `json:"dns_query,omitempty"`
	DNSResponse string `json:"dns_response,omitempty"`
}

func ValidateTCPOpenFrame(frame Frame) error {
	if frame.Type != FrameTCPOpen {
		return fmt.Errorf("tcp_open frame type is required")
	}
	if frame.RequestID == "" {
		return fmt.Errorf("tcp_open request_id is required")
	}
	if frame.ApplicationID == "" {
		return fmt.Errorf("tcp_open application_id is required")
	}
	if frame.Host == "" {
		return fmt.Errorf("tcp_open host is required")
	}
	if frame.Port < 1 || frame.Port > 65535 {
		return fmt.Errorf("tcp_open port must be between 1 and 65535")
	}
	if err := validatePositiveBounded("connect_timeout_ms", frame.ConnectTimeoutMillis, MaxTCPConnectTimeoutMillis); err != nil {
		return err
	}
	// 0 = unlimited (no lifetime / no idle reap). Used by interactive East-West flows (ssh/rdp): a session at a
	// prompt must not be torn down by a timer. A positive value is still bounded by the cap. The idle<=lifetime
	// invariant only applies when BOTH are bounded (a bounded idle under an unlimited lifetime is fine).
	if err := validateNonNegativeBounded("max_connection_lifetime_ms", frame.MaxConnectionLifetimeMillis, MaxTCPConnectionLifetimeMillis); err != nil {
		return err
	}
	if err := validateNonNegativeBounded("idle_timeout_ms", frame.IdleTimeoutMillis, MaxTCPIdleTimeoutMillis); err != nil {
		return err
	}
	if frame.MaxConnectionLifetimeMillis > 0 && frame.IdleTimeoutMillis > frame.MaxConnectionLifetimeMillis {
		return fmt.Errorf("idle_timeout_ms cannot exceed max_connection_lifetime_ms")
	}
	if frame.ByteCap <= 0 || frame.ByteCap > MaxTCPByteCap {
		return fmt.Errorf("byte_cap must be between 1 and %d", MaxTCPByteCap)
	}
	if frame.ConcurrentConnectionCap <= 0 || frame.ConcurrentConnectionCap > MaxTCPConcurrentConnections {
		return fmt.Errorf("concurrent_connection_cap must be between 1 and %d", MaxTCPConcurrentConnections)
	}
	return nil
}

func ValidateTCPDataFrame(frame Frame) error {
	if frame.Type != FrameTCPData {
		return fmt.Errorf("tcp_data frame type is required")
	}
	if frame.RequestID == "" {
		return fmt.Errorf("tcp_data request_id is required")
	}
	if frame.Direction != TCPDirectionUp && frame.Direction != TCPDirectionDown {
		return fmt.Errorf("tcp_data direction must be up or down")
	}
	payload, err := base64.StdEncoding.DecodeString(frame.Data)
	if err != nil {
		return fmt.Errorf("tcp_data payload must be base64: %w", err)
	}
	if len(payload) > MaxTCPDataFramePayloadBytes {
		return fmt.Errorf("tcp_data payload length %d exceeds limit %d", len(payload), MaxTCPDataFramePayloadBytes)
	}
	return nil
}

func ValidateTCPCloseFrame(frame Frame) error {
	if frame.Type != FrameTCPClose {
		return fmt.Errorf("tcp_close frame type is required")
	}
	if frame.RequestID == "" {
		return fmt.Errorf("tcp_close request_id is required")
	}
	if frame.Direction != TCPDirectionLocal && frame.Direction != TCPDirectionRemote {
		return fmt.Errorf("tcp_close direction must be local or remote")
	}
	switch frame.CloseReason {
	case TCPCloseReasonEOF, TCPCloseReasonError, TCPCloseReasonTimeout, TCPCloseReasonDenied,
		TCPCloseReasonByteCapExceeded, TCPCloseReasonLifetimeExceeded,
		TCPCloseReasonIdleTimeoutExceeded, TCPCloseReasonConcurrentCapExceeded:
	default:
		return fmt.Errorf("tcp_close reason %q is not allowed", frame.CloseReason)
	}
	if frame.BytesUp < 0 || frame.BytesDown < 0 || frame.DurationMillis < 0 {
		return fmt.Errorf("tcp_close metrics cannot be negative")
	}
	return nil
}

func validatePositiveBounded(name string, value, max int) error {
	if value <= 0 || value > max {
		return fmt.Errorf("%s must be between 1 and %d", name, max)
	}
	return nil
}

// validateNonNegativeBounded is validatePositiveBounded except 0 is allowed and means "unlimited" (no cap on that
// dimension). A positive value is still bounded by max; only 0 opts out. Used for idle/lifetime on interactive
// East-West streams that must never be reaped by a timer.
func validateNonNegativeBounded(name string, value, max int) error {
	if value < 0 || value > max {
		return fmt.Errorf("%s must be between 0 and %d (0 = unlimited)", name, max)
	}
	return nil
}

type TCPConnectionRegistry struct {
	mu          sync.Mutex
	connections map[string]*tcpConnectionRecord
}

type tcpConnectionRecord struct {
	requestID      string
	byteCap        int64
	maxLifetime    time.Duration
	idleTimeout    time.Duration
	openedAt       time.Time
	lastActivityAt time.Time
	bytesUp        int64
	bytesDown      int64
}

func NewTCPConnectionRegistry() *TCPConnectionRegistry {
	return &TCPConnectionRegistry{connections: map[string]*tcpConnectionRecord{}}
}

func (r *TCPConnectionRegistry) Open(frame Frame, now time.Time) error {
	if r == nil {
		return fmt.Errorf("tcp connection registry is required")
	}
	if err := ValidateTCPOpenFrame(frame); err != nil {
		return err
	}
	now = normalizeTCPRegistryTime(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.connections[frame.RequestID]; exists {
		return fmt.Errorf("tcp connection %s is already open", frame.RequestID)
	}
	if len(r.connections) >= frame.ConcurrentConnectionCap {
		return fmt.Errorf("tcp concurrent connection cap exceeded: %d/%d", len(r.connections), frame.ConcurrentConnectionCap)
	}
	r.connections[frame.RequestID] = &tcpConnectionRecord{
		requestID:      frame.RequestID,
		byteCap:        frame.ByteCap,
		maxLifetime:    time.Duration(frame.MaxConnectionLifetimeMillis) * time.Millisecond,
		idleTimeout:    time.Duration(frame.IdleTimeoutMillis) * time.Millisecond,
		openedAt:       now,
		lastActivityAt: now,
	}
	return nil
}

func (r *TCPConnectionRegistry) RecordData(frame Frame, now time.Time) (Frame, bool, error) {
	if r == nil {
		return Frame{}, false, fmt.Errorf("tcp connection registry is required")
	}
	if err := ValidateTCPDataFrame(frame); err != nil {
		return Frame{}, false, err
	}
	payload, err := base64.StdEncoding.DecodeString(frame.Data)
	if err != nil {
		return Frame{}, false, fmt.Errorf("tcp_data payload must be base64: %w", err)
	}
	now = normalizeTCPRegistryTime(now)
	r.mu.Lock()
	record, ok := r.connections[frame.RequestID]
	if !ok {
		r.mu.Unlock()
		return Frame{}, false, fmt.Errorf("tcp connection %s is not open", frame.RequestID)
	}
	if frame.Direction == TCPDirectionUp {
		record.bytesUp += int64(len(payload))
	} else {
		record.bytesDown += int64(len(payload))
	}
	record.lastActivityAt = now
	if record.bytesUp+record.bytesDown <= record.byteCap {
		r.mu.Unlock()
		return Frame{}, false, nil
	}
	closeFrame := record.closeFrame(TCPDirectionLocal, TCPCloseReasonByteCapExceeded, now)
	delete(r.connections, frame.RequestID)
	r.mu.Unlock()
	return closeFrame, true, nil
}

func (r *TCPConnectionRegistry) Close(requestID, direction, reason string, now time.Time) (Frame, error) {
	if r == nil {
		return Frame{}, fmt.Errorf("tcp connection registry is required")
	}
	now = normalizeTCPRegistryTime(now)
	r.mu.Lock()
	record, ok := r.connections[requestID]
	if !ok {
		r.mu.Unlock()
		return Frame{}, fmt.Errorf("tcp connection %s is not open", requestID)
	}
	closeFrame := record.closeFrame(direction, reason, now)
	if err := ValidateTCPCloseFrame(closeFrame); err != nil {
		r.mu.Unlock()
		return Frame{}, err
	}
	delete(r.connections, requestID)
	r.mu.Unlock()
	return closeFrame, nil
}

func (r *TCPConnectionRegistry) CloseExpired(now time.Time) []Frame {
	if r == nil {
		return nil
	}
	now = normalizeTCPRegistryTime(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	closed := make([]Frame, 0)
	for requestID, record := range r.connections {
		reason := ""
		// A zero maxLifetime / idleTimeout means "unlimited" — skip that reap dimension. An interactive East-West
		// stream (ssh/rdp) opens with both at 0 so the connector never times it out; teardown is driven by the
		// natural EOF/RST relayed from the Edge bridge (which keeps a half-close linger to reclaim abandoned flows).
		if record.maxLifetime > 0 && now.Sub(record.openedAt) >= record.maxLifetime {
			reason = TCPCloseReasonLifetimeExceeded
		} else if record.idleTimeout > 0 && now.Sub(record.lastActivityAt) >= record.idleTimeout {
			reason = TCPCloseReasonIdleTimeoutExceeded
		}
		if reason == "" {
			continue
		}
		closed = append(closed, record.closeFrame(TCPDirectionLocal, reason, now))
		delete(r.connections, requestID)
	}
	return closed
}

func (r *TCPConnectionRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.connections)
}

func (record *tcpConnectionRecord) closeFrame(direction, reason string, now time.Time) Frame {
	return Frame{
		Type:           FrameTCPClose,
		RequestID:      record.requestID,
		Direction:      direction,
		CloseReason:    reason,
		BytesUp:        record.bytesUp,
		BytesDown:      record.bytesDown,
		DurationMillis: millisSince(record.openedAt, now),
	}
}

func normalizeTCPRegistryTime(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now
}

func millisSince(start, end time.Time) int64 {
	if end.Before(start) {
		return 0
	}
	return int64(end.Sub(start) / time.Millisecond)
}

type Manager struct {
	mu             sync.RWMutex
	sessions       map[string]*Session
	seenConnectors map[string]bool
	requestTimeout time.Duration
}

type Session struct {
	ConnectorID       string
	TunnelID          string
	TransportProtocol string

	conn    FrameTransport
	pending map[string]chan Frame
	streams map[string]chan Frame
	mu      sync.Mutex

	requestTimeout time.Duration
}

func NewManager() *Manager {
	return NewManagerWithRequestTimeout(DefaultRequestTimeout)
}

func NewManagerWithRequestTimeout(timeout time.Duration) *Manager {
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &Manager{
		sessions:       map[string]*Session{},
		seenConnectors: map[string]bool{},
		requestTimeout: timeout,
	}
}

func (m *Manager) Register(connectorID, tunnelID string, conn FrameTransport) (*Session, bool) {
	return m.RegisterWithTransportProtocol(connectorID, tunnelID, conn, WebSocketTextJSONTransportProtocol)
}

func (m *Manager) RegisterWithTransportProtocol(connectorID, tunnelID string, conn FrameTransport, transportProtocol string) (*Session, bool) {
	if transportProtocol == "" {
		transportProtocol = WebSocketTextJSONTransportProtocol
	}
	session := &Session{
		ConnectorID:       connectorID,
		TunnelID:          tunnelID,
		TransportProtocol: transportProtocol,
		conn:              conn,
		pending:           map[string]chan Frame{},
		streams:           map[string]chan Frame{},
		requestTimeout:    m.requestTimeout,
	}
	m.mu.Lock()
	previous, replacing := m.sessions[connectorID]
	reconnect := m.seenConnectors[connectorID] || replacing
	m.seenConnectors[connectorID] = true
	m.sessions[connectorID] = session
	m.mu.Unlock()
	if replacing && previous != nil {
		_ = previous.Close()
	}
	return session, reconnect
}

func (m *Manager) Unregister(connectorID, tunnelID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[connectorID]
	if ok && session.TunnelID == tunnelID {
		delete(m.sessions, connectorID)
	}
}

func (m *Manager) Get(connectorID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.sessions[connectorID]
	return session, ok
}

func (s *Session) Run() error {
	for {
		var frame Frame
		if err := s.conn.ReadJSON(&frame); err != nil {
			s.failPending(err)
			if err == io.EOF {
				return nil
			}
			return err
		}
		if frame.Type == FrameHTTPResponse || frame.Type == FrameProbeResult || frame.Type == FrameDNSResult {
			s.deliver(frame)
			continue
		}
		if isTCPStreamFrame(frame.Type) {
			s.deliverTCPStream(frame)
		}
	}
}

func (s *Session) RoundTrip(ctx context.Context, frame Frame) (Frame, error) {
	if frame.RequestID == "" {
		return Frame{}, fmt.Errorf("request_id is required")
	}
	responseCh := make(chan Frame, 1)
	s.mu.Lock()
	s.pending[frame.RequestID] = responseCh
	s.mu.Unlock()
	defer s.deletePending(frame.RequestID)

	frame.TunnelID = s.TunnelID
	if err := s.conn.WriteJSON(frame); err != nil {
		return Frame{}, err
	}
	select {
	case response := <-responseCh:
		if response.Error != "" {
			return response, errors.New(response.Error)
		}
		return response, nil
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-time.After(s.requestTimeout):
		return Frame{}, fmt.Errorf("tunnel request timed out")
	}
}

func (s *Session) OpenTCP(ctx context.Context, frame Frame) (<-chan Frame, func(), Frame, error) {
	if err := ValidateTCPOpenFrame(frame); err != nil {
		return nil, nil, Frame{}, err
	}
	streamCh, cleanup, err := s.RegisterTCPStream(frame.RequestID)
	if err != nil {
		return nil, nil, Frame{}, err
	}
	frame.TunnelID = s.TunnelID
	if err := s.conn.WriteJSON(frame); err != nil {
		cleanup()
		return nil, nil, Frame{}, err
	}
	select {
	case response := <-streamCh:
		if response.Type != FrameTCPOpenResult {
			cleanup()
			return nil, nil, response, fmt.Errorf("tcp_open_result is required")
		}
		if response.Error != "" {
			cleanup()
			return nil, nil, response, errors.New(response.Error)
		}
		return streamCh, cleanup, response, nil
	case <-ctx.Done():
		cleanup()
		return nil, nil, Frame{}, ctx.Err()
	case <-time.After(s.requestTimeout):
		cleanup()
		return nil, nil, Frame{}, ErrTCPOpenTimeout
	}
}

func (s *Session) WriteTCPStreamFrame(frame Frame) error {
	if frame.Type != FrameTCPData && frame.Type != FrameTCPClose {
		return fmt.Errorf("tcp_data or tcp_close frame is required")
	}
	if frame.Type == FrameTCPData {
		if err := ValidateTCPDataFrame(frame); err != nil {
			return err
		}
	} else if err := ValidateTCPCloseFrame(frame); err != nil {
		return err
	}
	frame.TunnelID = s.TunnelID
	return s.conn.WriteJSON(frame)
}

func (s *Session) Close() error {
	return s.conn.Close()
}

func (s *Session) RegisterTCPStream(requestID string) (<-chan Frame, func(), error) {
	if requestID == "" {
		return nil, nil, fmt.Errorf("request_id is required")
	}
	ch := make(chan Frame, DefaultTCPStreamChannelBufferFrames)
	s.mu.Lock()
	if _, exists := s.streams[requestID]; exists {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("tcp stream %s is already registered", requestID)
	}
	s.streams[requestID] = ch
	s.mu.Unlock()
	// cleanup CLOSES the channel as well as deregistering it, so a consumer still blocked in a channel receive
	// is released. Without the close, an edge-initiated stream close leaked the tunnel->client copy goroutine
	// forever: the connector's dispatcher replies NOTHING to an edge-sent tcp_close, so nothing else ever wakes
	// that receive. The map is the closed-guard — every closer (cleanup, deliverTCPStream's backpressure path,
	// failPending) deletes and closes under s.mu and only when the entry is still present, so cleanup is
	// idempotent and a send-on-closed / double-close race cannot occur (deliverTCPStream sends while HOLDING
	// s.mu; "in the map" therefore implies "not closed").
	cleanup := func() {
		s.mu.Lock()
		if registered, ok := s.streams[requestID]; ok {
			delete(s.streams, requestID)
			close(registered)
		}
		s.mu.Unlock()
	}
	return ch, cleanup, nil
}

// deliver hands a response frame to the waiting RoundTrip. The send is NON-BLOCKING (mirroring
// deliverTCPStream's fail-closed backpressure): responseCh is buffer-1 and a RoundTrip consumes exactly one
// frame, so a DUPLICATE response for the same request_id would find the buffer full. A blocking send there
// wedged Session.Run — the single reader goroutine — forever whenever the RoundTrip had already exited via
// timeout/ctx without draining the channel, stalling every other request on the session. A full buffer means
// the request already has its response (or has given up), so the extra frame is dropped and the pending
// entry cleared.
func (s *Session) deliver(frame Frame) {
	s.mu.Lock()
	responseCh, ok := s.pending[frame.RequestID]
	if !ok {
		s.mu.Unlock()
		return
	}
	select {
	case responseCh <- frame:
		s.mu.Unlock()
	default:
		delete(s.pending, frame.RequestID)
		s.mu.Unlock()
	}
}

// failPending fans a terminal error to every waiting RoundTrip and stream on a session teardown. Sends are
// NON-BLOCKING for the same reason as deliver: a pending buffer already holding a frame (or a stream whose
// consumer stopped reading) must not block the teardown — dropping the error frame there is safe because the
// channel already carries a response, or the reader is gone.
//
// Streams are additionally DELETED and CLOSED, under s.mu like every other stream closer: a consumer whose
// buffer was full (so the error frame was dropped) must still be woken, and a stream that survived here as a
// registered-but-never-closed entry kept its copy goroutine blocked for the life of the process. The error
// frame is sent first so a consumer that drains the buffer still sees the reason before EOF.
func (s *Session) failPending(err error) {
	s.mu.Lock()
	pendingSnapshot := make(map[string]chan Frame, len(s.pending))
	for k, v := range s.pending {
		pendingSnapshot[k] = v
	}
	for requestID, streamCh := range s.streams {
		select {
		case streamCh <- Frame{Type: FrameTCPClose, RequestID: requestID, Error: err.Error(), CloseReason: TCPCloseReasonError}:
		default:
		}
		delete(s.streams, requestID)
		close(streamCh)
	}
	s.mu.Unlock()
	for requestID, responseCh := range pendingSnapshot {
		select {
		case responseCh <- Frame{Type: FrameHTTPResponse, RequestID: requestID, Error: err.Error()}:
		default:
		}
	}
}

func (s *Session) deletePending(requestID string) {
	s.mu.Lock()
	delete(s.pending, requestID)
	s.mu.Unlock()
}

// deliverTCPStream delivers a TCP stream frame to the registered stream consumer.
// The bounded stream channel is a fail-closed backpressure boundary. If the
// consumer is full, the stream is removed and closed instead of blocking
// Session.Run and starving unrelated responses.
func (s *Session) deliverTCPStream(frame Frame) {
	s.mu.Lock()
	streamCh, ok := s.streams[frame.RequestID]
	if !ok {
		s.mu.Unlock()
		return
	}
	select {
	case streamCh <- frame:
		s.mu.Unlock()
	default:
		delete(s.streams, frame.RequestID)
		close(streamCh)
		s.mu.Unlock()
	}
}

func isTCPStreamFrame(frameType string) bool {
	return frameType == FrameTCPOpenResult || frameType == FrameTCPData || frameType == FrameTCPClose
}

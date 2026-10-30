package edgeplane

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// SteerMuxWarnNoticePayload extracts the JSON WARN payload from a Warn-stage decision (a warn_notice action, see
// decision.eastWestWarnActions). Returns (payload, true) only when the decision carries one — an allow that came
// from the learning-lifecycle Warn stage. The payload is the compact {message, destination, service} the agent
// renders as a passive notice.
func SteerMuxWarnNoticePayload(dec model.AccessDecision) ([]byte, bool) {
	for _, a := range dec.Actions {
		if a.Type != "warn_notice" {
			continue
		}
		notice := map[string]string{}
		if v, ok := a.Metadata["message"].(string); ok && strings.TrimSpace(v) != "" {
			notice["message"] = v
		}
		if v, ok := a.Metadata["destination"].(string); ok && strings.TrimSpace(v) != "" {
			notice["destination"] = v
		}
		if v, ok := a.Metadata["service_family"].(string); ok && strings.TrimSpace(v) != "" {
			notice["service"] = v
		}
		payload, err := json.Marshal(notice)
		if err != nil {
			return nil, false
		}
		return payload, true
	}
	return nil, false
}

// Tunnel multiplexing for the steer path: MANY browser TLS flows carried inside ONE mTLS transport
// connection, instead of one CONNECT /steer tunnel (one NWConnection) per flow. A heavy page opens ~80
// flows at once; on macOS ~80 concurrent NWConnections overwhelm Network.framework's callback delivery and
// some interception handshakes stall mid-ServerHello. Multiplexing collapses that to a single connection
// (or a small pool) whose bytes the Edge demuxes to per-flow virtual conns and runs through the SAME
// interception engine (steerEgressForward) — the flows are unchanged; only their carriage changes.
//
// Wire frame (both directions, identical): [flowID uint32 BE][type uint8][length uint32 BE][payload...]
//   OPEN   (NE->Edge): payload = destination authority ("host:port", IPv6 bracketed). Starts a flow.
//   DATA   (both):     payload = opaque flow bytes (the browser's raw TLS in one direction).
//   CLOSE  (both):     payload empty. Half/full close of the flow.
//   STEPUP (Edge->NE):  payload = a step-up portal URL. The flow's decision is authenticate/reauth and the
//                       device has no live grant; a native TCP client can't follow a 302, so the Edge asks the
//                       agent to open the URL out-of-band in a browser. The native flow is held for a bounded
//                       wait; if authorization and upstream connection succeed it resumes, otherwise it closes
//                       and the original application must reconnect.
//                       (Mirrors the single-flow /steer path's X-Dsse-Stepup-Url header.)
//   WARN   (Edge->NE):  payload = a small JSON notice {message, destination, service}. NON-HOLDING: the flow is
//                       ALLOWED and forwarded normally; this frame only asks the agent to surface a PASSIVE
//                       "this connection is monitored; authentication will soon be required" message (the agent
//                       coalesces it once per session). It is the learning-lifecycle Warn stage (S3) — a dry-run
//                       notice before a rule flips to Enforce. Unlike STEPUP it never closes or holds the flow.
//   AUTH_RESULT (Edge->NE): payload = {request_id,result}, with result "resumed" only after the held
//                       flow passes current authorization, leaves the hold, and establishes its upstream TCP
//                       connection, or "not_resumed" before it is dropped.
//                       It reports this flow's outcome over the authenticated mux, never an IdP identity.
//   AUTH_QUERY (NE->Edge): flowID=0, payload = {request_id,os_principal,os_session}. The Edge answers
//                       with AUTH_RESULT on flowID=0 only for an exact match in the shared final-result ledger.

const (
	muxFrameOpen       uint8 = 0
	muxFrameData       uint8 = 1
	muxFrameClose      uint8 = 2
	muxFrameStepUp     uint8 = 3
	muxFrameWarn       uint8 = 4
	muxFrameAuthResult uint8 = 5
	muxFrameAuthQuery  uint8 = 6

	muxHeaderLen      = 9
	muxMaxFrameLen    = 1 << 20 // 1 MiB per frame — a defensive bound on a single DATA payload.
	muxVirtualConnCap = 1 << 20 // per-flow inbound buffer before the demux loop backpressures that flow.
)

// MuxVirtualConn is a net.Conn for one multiplexed flow: Read drains inbound DATA (fed by the demux loop),
// Write emits DATA frames back over the shared mux. The interception engine treats it like any client conn.
type MuxVirtualConn struct {
	flowID    uint32
	mux       *steerMux
	inbound   *BufferedPipeHalf
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *MuxVirtualConn) Read(p []byte) (int, error) { return c.inbound.Read(p) }

// BeginAuthWait bounds pre-authentication data without blocking the mux reader.
// A false result requires the caller to close the flow without forwarding.
func (c *MuxVirtualConn) BeginAuthWait() bool { return c.inbound.setAuthLimit(16*1024, true) }
func (c *MuxVirtualConn) EndAuthWait() bool   { return c.inbound.setAuthLimit(muxVirtualConnCap, false) }

func (c *MuxVirtualConn) Write(p []byte) (int, error) {
	if err := c.mux.writeFrame(c.flowID, muxFrameData, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a CLOSE frame to the peer and tears down the local half. Idempotent.
func (c *MuxVirtualConn) Close() error {
	if c.closeLocalOnly() {
		return c.mux.writeFrame(c.flowID, muxFrameClose, nil)
	}
	return nil
}

// sendStepUp asks the peer (NE agent) to open a step-up portal URL out-of-band in a browser for this flow.
func (c *MuxVirtualConn) SendStepUp(url string) error {
	return c.mux.writeFrame(c.flowID, muxFrameStepUp, []byte(url))
}

// SendAuthResult reports the fate of the same held flow. A result is advisory
// for the UI; authorization still depends on the server's current policy check.
func (c *MuxVirtualConn) SendAuthResult(requestID, result string) error {
	if len(requestID) != 32 || (result != "resumed" && result != "not_resumed") {
		return errors.New("invalid authentication result")
	}
	for _, ch := range requestID {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return errors.New("invalid authentication result")
		}
	}
	payload, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		Result    string `json:"result"`
	}{requestID, result})
	if err != nil {
		return err
	}
	return c.mux.writeFrame(c.flowID, muxFrameAuthResult, payload)
}

// sendWarnNotice asks the peer (NE agent) to surface a PASSIVE "monitored; auth soon required" notice for this
// flow. Non-holding — the flow is already allowed and will be forwarded; this only informs the user. payload is
// the JSON notice ({message, destination, service}). The agent coalesces display once per session.
func (c *MuxVirtualConn) SendWarnNotice(payload []byte) error {
	return c.mux.writeFrame(c.flowID, muxFrameWarn, payload)
}

// closeLocalOnly tears down the local half WITHOUT sending a CLOSE frame (used when the peer already sent one).
func (c *MuxVirtualConn) closeLocalOnly() bool {
	closed := false
	c.closeOnce.Do(func() {
		c.inbound.Close()
		c.mux.removeFlow(c.flowID)
		close(c.closed)
		closed = true
	})
	return closed
}

type muxAddr struct{}

func (muxAddr) Network() string { return "steer-mux" }
func (muxAddr) String() string  { return "steer-mux" }

func (c *MuxVirtualConn) LocalAddr() net.Addr                { return muxAddr{} }
func (c *MuxVirtualConn) RemoteAddr() net.Addr               { return muxAddr{} }
func (c *MuxVirtualConn) SetDeadline(t time.Time) error      { return nil }
func (c *MuxVirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *MuxVirtualConn) SetWriteDeadline(t time.Time) error { return nil }

// steerMux demultiplexes one mux transport connection into per-flow virtual conns.
type steerMux struct {
	conn    net.Conn
	writeMu sync.Mutex
	flowsMu sync.Mutex
	flows   map[uint32]*MuxVirtualConn
	// warnedResources coalesces Warn-stage notices: a mux connection is roughly one device session, so a WARN
	// frame is sent only on the FIRST flow to a given (destination:service) — a chatty warn-staged protocol does
	// not spam frames. The agent additionally coalesces display. Keyed by resource string.
	warnMu          sync.Mutex
	warnedResources map[string]struct{}
}

func NewSteerMux(conn net.Conn) *steerMux {
	return &steerMux{conn: conn, flows: make(map[uint32]*MuxVirtualConn), warnedResources: make(map[string]struct{})}
}

// warnOnce reports whether a Warn notice for this resource should be SENT on this mux connection (true only the
// first time per resource), so a chatty warn-staged flow emits one frame, not one per OPEN.
func (m *steerMux) warnOnce(resourceKey string) bool {
	m.warnMu.Lock()
	defer m.warnMu.Unlock()
	if _, seen := m.warnedResources[resourceKey]; seen {
		return false
	}
	m.warnedResources[resourceKey] = struct{}{}
	return true
}

func (m *steerMux) writeFrame(flowID uint32, typ uint8, payload []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	var hdr [muxHeaderLen]byte
	binary.BigEndian.PutUint32(hdr[0:4], flowID)
	hdr[4] = typ
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := m.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := m.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func (m *steerMux) removeFlow(flowID uint32) {
	m.flowsMu.Lock()
	delete(m.flows, flowID)
	m.flowsMu.Unlock()
}

func (m *steerMux) lookup(flowID uint32) *MuxVirtualConn {
	m.flowsMu.Lock()
	defer m.flowsMu.Unlock()
	return m.flows[flowID]
}

// run reads frames until the mux connection ends, dispatching OPEN to handleOpen (in its own goroutine so
// slow interception setup on one flow never blocks the demux of others) and routing DATA/CLOSE to flows.
func (m *steerMux) Run(handleOpen func(flowID uint32, authority string, vc *MuxVirtualConn), handleAuthQuery ...func([]byte) []byte) {
	r := bufio.NewReaderSize(m.conn, 64*1024)
	defer m.closeAll()
	// One bounded worker reports local rejections without blocking DATA dispatch
	// for unrelated flows. A peer that will not read cannot accumulate goroutines.
	closeNotices := make(chan uint32, 64)
	querySlots := make(chan struct{}, 8)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case id := <-closeNotices:
				if err := m.writeFrame(id, muxFrameClose, nil); err != nil {
					_ = m.conn.Close()
					return
				}
			}
		}
	}()
	var hdr [muxHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		flowID := binary.BigEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		length := binary.BigEndian.Uint32(hdr[5:9])
		if length > muxMaxFrameLen {
			log.Printf("steer_mux_frame_too_large flow=%d len=%d", flowID, length)
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				return
			}
		}
		switch typ {
		case muxFrameAuthQuery:
			if flowID != 0 || length > 256 || len(handleAuthQuery) != 1 || handleAuthQuery[0] == nil {
				continue
			}
			select {
			case querySlots <- struct{}{}:
				go func(payload []byte) {
					defer func() { <-querySlots }()
					if response := handleAuthQuery[0](payload); len(response) > 0 && len(response) <= 256 {
						_ = m.writeFrame(0, muxFrameAuthResult, response)
					}
				}(payload)
			default:
				// Bounded control work. The next periodic query can retry.
			}
		case muxFrameOpen:
			if flowID == 0 {
				continue
			} // control flow is reserved for result requery
			vc := &MuxVirtualConn{flowID: flowID, mux: m, inbound: NewBufferedPipeHalf(muxVirtualConnCap), closed: make(chan struct{})}
			m.flowsMu.Lock()
			if m.flows[flowID] != nil {
				m.flowsMu.Unlock()
				// Replacing a live flow loses the original virtual connection, so
				// tear down this malformed transport and close every active flow.
				log.Printf("steer_mux_duplicate_open flow=%d", flowID)
				return
			}
			m.flows[flowID] = vc
			m.flowsMu.Unlock()
			go handleOpen(flowID, string(payload), vc)
		case muxFrameData:
			if vc := m.lookup(flowID); vc != nil {
				// Writes block only when THIS flow's inbound buffer is full (its interception reader is slow);
				// the interception drains it continuously, so handshake-sized bursts never block.
				if _, err := vc.inbound.Write(payload); err != nil {
					if !vc.closeLocalOnly() {
						continue
					}
					select {
					case closeNotices <- flowID:
					default:
						return // transport teardown bounds an unresponsive peer
					}
				}
			}
		case muxFrameClose:
			if vc := m.lookup(flowID); vc != nil {
				vc.closeLocalOnly()
			}
		}
	}
}

func (m *steerMux) closeAll() {
	m.flowsMu.Lock()
	flows := make([]*MuxVirtualConn, 0, len(m.flows))
	for _, vc := range m.flows {
		flows = append(flows, vc)
	}
	m.flowsMu.Unlock()
	for _, vc := range flows {
		vc.closeLocalOnly()
	}
	_ = m.conn.Close()
}

// Closed reports mux/peer teardown: the channel is closed when the virtual conn is
// closed by either side. Exported for the composition root's select loops.
func (c *MuxVirtualConn) Closed() <-chan struct{} { return c.closed }

// WarnOnce returns true the first time the given key warns on this mux session.
func (c *MuxVirtualConn) WarnOnce(key string) bool { return c.mux.warnOnce(key) }

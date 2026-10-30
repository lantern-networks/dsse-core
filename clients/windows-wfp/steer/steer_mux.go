package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel multiplexing (client side). Instead of one CONNECT /steer tunnel per browser flow, ALL of a device's
// flows ride ONE mTLS transport connection to the Edge, framed with a small header. This collapses the Edge's
// per-flow FD + TLS-handshake cost from per-FLOW to per-DEVICE, which is what lets a single Edge scale to many
// devices; the flows themselves are unchanged, only their carriage is. Wire protocol is identical to the Edge
// demux and the macOS client (steerEgressForward runs on the far end exactly as for CONNECT /steer):
//
//	[flowID uint32 BE][type uint8][length uint32 BE][payload...]
//	OPEN(0):   client->Edge, payload = destination authority "host:port" (IPv6 bracketed) — starts a flow.
//	DATA(1):   both ways, payload = opaque flow bytes (one direction of the browser's raw TLS).
//	CLOSE(2):  both ways, payload empty — half/full close of the flow.
//	STEPUP(3): Edge->client, payload = a step-up portal URL to open OOB in a browser for that held flow (the
//	           East-West "authenticate" mediation over the mux — mirrors the macOS NE muxFrameStepUp). The
//	           flow stays held until a grant is minted; the browser open lets the user complete the step-up.
const (
	muxFrameOpen   uint8 = 0
	muxFrameData   uint8 = 1
	muxFrameClose  uint8 = 2
	muxFrameStepUp uint8 = 3
	// WARN(4): Edge->client, payload = JSON {"message","destination","service"} — a passive "this internal
	// connection is monitored; authentication will soon be required" notice for a Warn-staged East-West rule
	// (S3, dry-run). The flow is ALREADY allowed + forwarded; the frame is fire-and-forget and NEVER holds it.
	muxFrameWarn       uint8 = 4
	muxFrameAuthResult uint8 = 5
	muxFrameAuthQuery  uint8 = 6

	muxHeaderLen   = 9       // flowID(4) + type(1) + length(4)
	muxMaxFrameLen = 1 << 20 // 1 MiB — defensive bound on a single DATA payload; a larger frame ends the mux.
	muxFlowBufCap  = 1 << 20 // per-flow inbound buffer; a stalled reader must not block the shared demux.
)

var errMuxClosed = errors.New("steer mux connection closed")
var errMuxEndpointChanged = errors.New("steer mux endpoint changed")
var errMuxFlowBackpressure = errors.New("steer mux flow inbound buffer full")
var muxConnectionCounter atomic.Uint64
var authResultQueryLeader atomic.Pointer[steerMuxClient]

// muxPipe is a bounded byte pipe feeding one flow's inbound side. The demux loop uses TryWrite: a slow reader
// closes only its own flow rather than blocking every other flow on the shared mux. A read offset + amortized compaction keeps
// the drain O(n), never O(n^2): a large download must not stall the shared demux loop copying its whole buffer
// on every frame (the failure that skeletoned heavy pages on the macOS side).
type muxPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	off    int
	cap    int
	closed bool
}

func newMuxPipe(capacity int) *muxPipe {
	p := &muxPipe{cap: capacity}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *muxPipe) size() int { return len(p.buf) - p.off }

func (p *muxPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Wait for room. A single DATA payload is <= muxMaxFrameLen == cap, so waiting for any space is enough to
	// admit one frame; the buffer may transiently reach ~2x cap, still bounded.
	for p.size() >= p.cap && !p.closed {
		p.cond.Wait()
	}
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	return p.appendLocked(b), nil
}

// TryWrite is the demux path. A full pipe is a per-flow failure, not a reason
// to stop reading other flows' frames from the same transport connection.
func (p *muxPipe) TryWrite(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	if p.size() >= p.cap {
		return 0, errMuxFlowBackpressure
	}
	return p.appendLocked(b), nil
}

func (p *muxPipe) appendLocked(b []byte) int {
	// Reclaim the consumed prefix before appending only when it is worth it (consumed >= remaining), so the
	// backing array cannot grow unboundedly yet we don't memmove on every write.
	if p.off > 0 && p.off >= p.size() {
		p.buf = append(p.buf[:0], p.buf[p.off:]...)
		p.off = 0
	}
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
	return len(b)
}

func (p *muxPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.size() == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.size() == 0 && p.closed {
		return 0, io.EOF
	}
	n := copy(b, p.buf[p.off:])
	p.off += n
	if p.off >= len(p.buf) { // fully drained: reset to reuse the array
		p.buf = p.buf[:0]
		p.off = 0
	}
	p.cond.Broadcast()
	return n, nil
}

func (p *muxPipe) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
	return nil
}

// muxFlowConn is a net.Conn for one multiplexed flow: Read drains inbound DATA (fed by the demux loop), Write
// emits DATA frames over the shared mux. pipe() drives it exactly like a real per-flow edge conn.
type muxFlowConn struct {
	flowID    uint32
	mux       *steerMuxClient
	inbound   *muxPipe
	closeOnce sync.Once
	owner     stepUpOwner
	authority string // the destination "host:port" this flow OPENed — used as the step-up "resource" label.
	openedAt  time.Time
	// These are elapsed monotonic times, not payloads. They distinguish a stalled
	// Edge reply from a reply that reached the agent before the application timed out.
	firstAppDataNS  atomic.Int64
	firstEdgeDataNS atomic.Int64
	// #28 measurement: what the demux actually received FOR THIS FLOW, so a missing reply can be attributed.
	// Without it, "the app never saw the answer" cannot be told apart from "the Edge never sent one".
	inFrames   atomic.Int64
	inBytes    atomic.Int64
	edgeClosed atomic.Bool
}

func (c *muxFlowConn) Read(p []byte) (int, error) { return c.inbound.Read(p) }

func (c *muxFlowConn) Write(p []byte) (int, error) {
	if err := c.mux.writeFrame(c.flowID, muxFrameData, p); err != nil {
		return 0, err
	}
	if len(p) > 0 {
		c.firstAppDataNS.CompareAndSwap(0, max(1, time.Since(c.openedAt).Nanoseconds()))
	}
	return len(p), nil
}

func firstFlowDataMS(elapsedNS int64) int64 {
	if elapsedNS == 0 {
		return -1 // No data observed in this direction.
	}
	return elapsedNS / int64(time.Millisecond)
}

// CloseWrite accepts the app->edge half-close WITHOUT tearing the flow down. The mux protocol has only
// OPEN/DATA/CLOSE — no half-close frame — and the Edge does not need one: the macOS NE talks to the SAME Edge
// and keeps receiving a reply after its app stops sending. So this is deliberately a no-op on the wire. What
// matters is what it does NOT do: send CLOSE. Doing that discarded the flow while the answer was still being
// generated, which is #28.
func (c *muxFlowConn) CloseWrite() error { return nil }

// Close sends CLOSE to the Edge and tears down the local half. Idempotent; pipe() calls it once BOTH
// directions have ended.
func (c *muxFlowConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.mux.writeFrame(c.flowID, muxFrameClose, nil)
		c.inbound.Close()
		c.mux.removeFlow(c.flowID)
	})
	return nil
}

// closeLocalOnly tears down the local half WITHOUT sending CLOSE (the Edge already sent one, or the mux died).
func (c *muxFlowConn) closeLocalOnly() {
	c.closeOnce.Do(func() {
		c.inbound.Close()
		c.mux.removeFlow(c.flowID)
	})
}

type muxAddr struct{}

func (muxAddr) Network() string { return "steer-mux" }
func (muxAddr) String() string  { return "steer-mux" }

func (c *muxFlowConn) LocalAddr() net.Addr                { return muxAddr{} }
func (c *muxFlowConn) RemoteAddr() net.Addr               { return muxAddr{} }
func (c *muxFlowConn) SetDeadline(t time.Time) error      { return nil }
func (c *muxFlowConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *muxFlowConn) SetWriteDeadline(t time.Time) error { return nil }

// steerMuxClient owns ONE transport connection and multiplexes many flows over it. flowID is client-assigned
// and monotonic — the Edge only ever creates flows from client OPENs, never the reverse.
type steerMuxClient struct {
	conn net.Conn
	id   uint64 // local connection ID; flow IDs alone are only unique within one mux
	peer string // actual TCP peer, for distinguishing old/new entrance in failover diagnostics
	// endpoint is the immutable failover target captured before this connection was dialled. A live endpoint
	// switch must not put new flows on a still-open mux to the previous entrance.
	endpoint         *activeEndpoint
	active           *atomic.Pointer[activeEndpoint]
	transportFailure chan<- struct{}
	writeMu          sync.Mutex
	flowsMu          sync.Mutex
	flows            map[uint32]*muxFlowConn
	nextID           uint32
	dead             chan struct{}
	deadOnce         sync.Once
	// stepUp opens the Edge-issued step-up portal in a browser when a held East-West "authenticate" flow
	// receives a STEPUP frame. Same coordinator the per-flow /steer path uses (coalesced per resource); nil
	// when step-up mediation is disabled (--stepup-portal=false) -> a STEPUP frame is then a no-op.
	stepUp *stepUpCoordinator
	// warn surfaces the passive Warn-stage "monitored" notice on a WARN frame (the flow is already forwarded;
	// nothing is held). nil disables the notice. Coalesced once per service|destination per session.
	warn *warnNotifier
}

// writeFrame emits one whole frame (header + payload) under writeMu so concurrent flows' frames never
// interleave. The lock is held ONLY for this one frame's Write — never across anything else — so a slow flow's
// send does not serialize the others beyond one in-flight frame.
func (m *steerMuxClient) writeFrame(flowID uint32, typ uint8, payload []byte) error {
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

func (m *steerMuxClient) removeFlow(flowID uint32) {
	m.flowsMu.Lock()
	delete(m.flows, flowID)
	m.flowsMu.Unlock()
}

func (m *steerMuxClient) lookup(flowID uint32) *muxFlowConn {
	m.flowsMu.Lock()
	defer m.flowsMu.Unlock()
	return m.flows[flowID]
}

func (m *steerMuxClient) healthy() bool {
	select {
	case <-m.dead:
		return false
	default:
		return true
	}
}

// openFlow registers a new flow, sends OPEN(authority), and returns its net.Conn.
func (m *steerMuxClient) openFlow(authority string, owners ...stepUpOwner) (*muxFlowConn, error) {
	m.flowsMu.Lock()
	if m.active != nil && m.active.Load() != m.endpoint {
		m.flowsMu.Unlock()
		return nil, errMuxEndpointChanged
	}
	if !m.healthy() {
		m.flowsMu.Unlock()
		return nil, errMuxClosed
	}
	m.nextID++
	id := m.nextID
	fc := &muxFlowConn{flowID: id, mux: m, inbound: newMuxPipe(muxFlowBufCap), authority: authority, openedAt: time.Now()}
	if len(owners) == 1 {
		fc.owner = owners[0]
		authority = authorityWithAuthOwner(authority, fc.owner)
	}
	m.flows[id] = fc
	m.flowsMu.Unlock()
	if err := m.writeFrame(id, muxFrameOpen, []byte(authority)); err != nil {
		fc.closeLocalOnly()
		return nil, err
	}
	if m.active != nil && m.active.Load() != m.endpoint {
		// A switch may race with the frame write. Do not hand that flow to the application as a success;
		// the manager closes this old mux and retries against the current entrance.
		fc.closeLocalOnly()
		return nil, errMuxEndpointChanged
	}
	return fc, nil
}

// readLoop demultiplexes frames until the connection ends, routing DATA/CLOSE to flows. A too-large frame or
// any read error ends the loop and tears the whole mux down (muxManager reconnects on the next flow).
func (m *steerMuxClient) readLoop(r *bufio.Reader) {
	defer m.teardown()
	var hdr [muxHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			m.signalUnexpectedTransportLoss()
			return
		}
		flowID := binary.BigEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		length := binary.BigEndian.Uint32(hdr[5:9])
		if length > muxMaxFrameLen {
			m.signalUnexpectedTransportLoss()
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				m.signalUnexpectedTransportLoss()
				return
			}
		}
		switch typ {
		case muxFrameData:
			if fc := m.lookup(flowID); fc != nil {
				if len(payload) > 0 {
					fc.firstEdgeDataNS.CompareAndSwap(0, max(1, time.Since(fc.openedAt).Nanoseconds()))
				}
				fc.inFrames.Add(1)
				fc.inBytes.Add(int64(len(payload)))
				if _, err := fc.inbound.TryWrite(payload); err != nil {
					// A stalled application cannot hold the demultiplexer or grow the
					// shared connection's memory indefinitely. Tell the Edge that this
					// flow ended; unrelated flows keep their own buffered data.
					if errors.Is(err, errMuxFlowBackpressure) {
						_ = fc.Close()
					} else {
						fc.closeLocalOnly()
					}
				}
			}
		case muxFrameClose:
			if fc := m.lookup(flowID); fc != nil {
				fc.edgeClosed.Store(true)
				fc.closeLocalOnly()
			}
		case muxFrameStepUp:
			// East-West "authenticate" mediation over the mux: the Edge held this flow and sent the step-up
			// portal URL. Open it OOB in the logged-in user's browser (coalesced per resource) — mirrors the
			// macOS NE. The flow stays held (no DATA) until current authorization and upstream connection succeed,
			// or the wait fails and the originating app must reconnect.
			if m.stepUp != nil {
				if fc := m.lookup(flowID); fc != nil {
					m.stepUp.TriggerForOwner(fc.authority, string(payload), fc.owner)
				}
			}
		case muxFrameWarn:
			// Warn stage (S3): the flow is already allowed + forwarded; show a passive "monitored; auth soon
			// required" notice only to the originating user. Never held, never opened.
			if fc := m.lookup(flowID); fc != nil {
				m.warn.NotifyForOwner(payload, fc.owner)
			}
		case muxFrameAuthResult:
			if m.stepUp == nil || len(payload) > 256 {
				break
			}
			var result map[string]string
			if err := json.Unmarshal(payload, &result); err != nil || len(result) != 2 {
				break
			}
			if flowID == 0 {
				m.stepUp.HandleQueriedResult(result["request_id"], result["result"])
			} else if fc := m.lookup(flowID); fc != nil {
				m.stepUp.HandleResultForOwner(fc.authority, result["request_id"], result["result"], fc.owner)
			}
		case muxFrameOpen:
			// The Edge never initiates OPEN; ignore.
		}
	}
}

func (m *steerMuxClient) signalUnexpectedTransportLoss() {
	if m.transportFailure == nil || !m.healthy() || (m.active != nil && m.active.Load() != m.endpoint) {
		return // intentional close, already-switched entrance, or no region selector
	}
	select {
	case m.transportFailure <- struct{}{}:
	default: // coalesce simultaneous mux closures during the same fault
	}
}

func (m *steerMuxClient) teardown() {
	m.deadOnce.Do(func() {
		fmt.Printf("steer_mux_closed mux=%d peer=%s\n", m.id, m.peer)
		close(m.dead)
		_ = m.conn.Close()
		m.flowsMu.Lock()
		flows := make([]*muxFlowConn, 0, len(m.flows))
		for _, fc := range m.flows {
			flows = append(flows, fc)
		}
		m.flowsMu.Unlock()
		for _, fc := range flows {
			fc.closeLocalOnly()
		}
	})
}

// openSteerMux dials ONE transport connection ((T) mTLS when enabled, else plaintext TCP to the edge host),
// performs the CONNECT /steer-mux handshake, and starts the demux loop.
func openSteerMux(cfg edgeConfig, dialTimeout time.Duration) (*steerMuxClient, error) {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	var conn net.Conn
	var host string
	var endpoint *activeEndpoint
	active := cfg.transport.active
	if cfg.transport.enabled {
		if active != nil {
			// Freeze both dial target and TLS name for this handshake. Otherwise a switch between dialTarget()
			// and tlsConfig() can combine the old address with the new region's certificate name.
			endpoint = active.Load()
			frozen := &atomic.Pointer[activeEndpoint]{}
			frozen.Store(endpoint)
			cfg.transport.active = frozen
		}
		host = cfg.transport.host
		c, err := cfg.transport.dial(dialTimeout)
		if err != nil {
			return nil, err
		}
		conn = c
	} else {
		h, err := edgeHostPort(cfg.edgeURL)
		if err != nil {
			return nil, err
		}
		host = h
		dialer := net.Dialer{Timeout: dialTimeout}
		c, err := dialer.Dial("tcp", host)
		if err != nil {
			return nil, err
		}
		conn = c
	}
	// The per-device signal headers (OS + posture) ride on this CONNECT — per-connection ≈ per-device, the right
	// granularity (the per-flow who/what goes on the OPEN frames instead).
	// TCP/TLS dial timeouts do not cover the Edge's CONNECT exchange.
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	req := fmt.Sprintf("CONNECT /steer-mux HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, deviceConnectHeaders())
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 64*1024)
	// A half-open entrance must not pin a flow here indefinitely after a switch.
	status, _, err := readCONNECTStatus(reader)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if status != 200 {
		conn.Close()
		return nil, fmt.Errorf("steer-mux CONNECT status %d", status)
	}
	_ = conn.SetDeadline(time.Time{})
	m := &steerMuxClient{conn: conn, id: muxConnectionCounter.Add(1), peer: conn.RemoteAddr().String(), endpoint: endpoint, active: active, transportFailure: cfg.transportFailure, flows: make(map[uint32]*muxFlowConn), dead: make(chan struct{}), stepUp: cfg.stepUp, warn: cfg.warn}
	fmt.Printf("steer_mux_connected mux=%d peer=%s\n", m.id, m.peer)
	// Any bytes the Edge already sent past the CONNECT header are the first mux frames; readCONNECTStatus left
	// them buffered in `reader`, and the demux loop reads from that same reader, so they are not lost.
	go m.readLoop(reader)
	if m.stepUp != nil {
		go m.requeryAuthResults()
	}
	return m, nil
}

func (m *steerMuxClient) requeryAuthResults() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer authResultQueryLeader.CompareAndSwap(m, nil)
	for {
		leader := authResultQueryLeader.Load()
		if leader == nil || !leader.healthy() {
			if authResultQueryLeader.CompareAndSwap(leader, m) {
				leader = m
			}
		}
		if leader == m {
			for _, query := range m.stepUp.pendingResultQueries() {
				payload, err := json.Marshal(query)
				if err != nil || len(payload) > 256 {
					continue
				}
				if err := m.writeFrame(0, muxFrameAuthQuery, payload); err != nil {
					return
				}
			}
		}
		select {
		case <-m.dead:
			return
		case <-ticker.C:
		}
	}
}

// load reports this connection's current active flow count (used by the pool to pick the least-loaded conn and
// to size the pool).
func (m *steerMuxClient) load() int {
	m.flowsMu.Lock()
	defer m.flowsMu.Unlock()
	return len(m.flows)
}

// muxManager owns an ADAPTIVE POOL of mux connections for a steer run and grows/shrinks it with load. A single
// TCP-multiplexed connection has transport-layer limits that framing cannot fix — TCP head-of-line blocking (one
// lost packet stalls every flow on that connection until retransmit), a shared congestion window, and single-core
// crypto/demux — so spreading flows over a few connections restores per-connection independence while keeping the
// Edge's FD/handshake win (a handful of conns vs thousands of flows). Sizing mirrors the macOS reference:
//
//	desired = clamp(1 + active/flowsPerConn, 1, maxConns)
//
// A flow is pinned to the connection it is assigned for life (byte-order preserved). Growth happens in the
// background; idle (zero-flow) surplus connections are closed on the next acquire. maxConns==1 is exactly the
// old single-connection behaviour (backward compatible).
type muxManager struct {
	cfg           edgeConfig
	dialTimeout   time.Duration
	flowsPerConn  int
	maxConns      int
	mu            sync.Mutex
	cond          *sync.Cond
	pool          []*steerMuxClient
	opening       int // dials in flight for endpointEpoch; old-entrance dials must not delay a new entrance
	endpointEpoch *activeEndpoint
}

func newMuxManager(cfg edgeConfig, dialTimeout time.Duration, flowsPerConn, maxConns int) *muxManager {
	if flowsPerConn < 1 {
		flowsPerConn = 12
	}
	if maxConns < 1 {
		maxConns = 1
	}
	mm := &muxManager{cfg: cfg, dialTimeout: dialTimeout, flowsPerConn: flowsPerConn, maxConns: maxConns}
	mm.cond = sync.NewCond(&mm.mu)
	return mm
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// acquire returns the least-loaded healthy mux connection for a new flow, growing the pool toward `desired` in
// the background and shrinking idle surplus. When the pool is empty it opens the first connection synchronously,
// coalescing a cold-start burst of flows onto ONE dial (concurrent callers wait on cond rather than each dialing).
func (mm *muxManager) acquire() (*steerMuxClient, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	for {
		mm.refreshEndpointLocked()
		mm.pruneLocked()
		active := mm.activeLocked()
		desired := clampInt(1+active/mm.flowsPerConn, 1, mm.maxConns)
		mm.shrinkIdleLocked(desired)
		if len(mm.pool) > 0 {
			best := mm.leastLoadedLocked()
			if len(mm.pool)+mm.opening < desired {
				mm.opening++
				go mm.growOne(mm.endpointEpoch)
			}
			return best, nil
		}
		// Pool empty. If someone is already opening the first connection, wait for it instead of piling on more
		// dials (cold-start coalescing); otherwise open it ourselves.
		if mm.opening > 0 {
			if mm.cfg.transport.active == nil {
				mm.cond.Wait()
			} else {
				// A region switch cannot signal this condition variable. Recheck the atomic endpoint soon
				// instead of waiting for an old-entrance TCP timeout before the first new-entrance dial.
				mm.mu.Unlock()
				time.Sleep(25 * time.Millisecond)
				mm.mu.Lock()
			}
			continue
		}
		mm.opening++
		epoch := mm.endpointEpoch
		mm.mu.Unlock()
		m, err, abandoned := mm.openFirstForEpoch(epoch, openSteerMux)
		mm.mu.Lock()
		mm.refreshEndpointLocked()
		if abandoned {
			// The old entrance's dial is still finishing in the background. It will
			// close its own result; retry this caller against the new entrance now.
			continue
		}
		if epoch != mm.endpointEpoch {
			if m != nil {
				fmt.Printf("steer_mux_discarded_after_switch mux=%d peer=%s\n", m.id, m.peer)
				go m.teardown()
			}
			mm.cond.Broadcast()
			continue
		}
		mm.opening--
		if err != nil {
			mm.cond.Broadcast()
			return nil, err
		}
		if !mm.currentEndpoint(m) {
			// The dial began before failover and completed afterwards. Never publish that old connection.
			fmt.Printf("steer_mux_discarded_after_switch mux=%d peer=%s\n", m.id, m.peer)
			go m.teardown()
			mm.cond.Broadcast()
			continue
		}
		mm.pool = append(mm.pool, m)
		mm.cond.Broadcast()
		// Loop: select the least-loaded connection (now the one just opened).
	}
}

// openFirstForEpoch lets an in-flight cold-pool dial be abandoned when the signed
// selector moves to another entrance. The old dial remains bounded by its TCP/TLS
// and CONNECT deadlines, and closes its result; the waiting application flow starts
// a new dial immediately instead of inheriting the old entrance's timeout.
func (mm *muxManager) openFirstForEpoch(epoch *activeEndpoint, open func(edgeConfig, time.Duration) (*steerMuxClient, error)) (*steerMuxClient, error, bool) {
	if mm.cfg.transport.active == nil {
		m, err := open(mm.cfg, mm.dialTimeout)
		return m, err, false
	}
	type result struct {
		m   *steerMuxClient
		err error
	}
	resultCh := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		m, err := open(mm.cfg, mm.dialTimeout)
		select {
		case resultCh <- result{m: m, err: err}:
		case <-abandoned:
			if m != nil {
				m.teardown()
			}
		}
	}()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case r := <-resultCh:
			return r.m, r.err, false
		case <-tick.C:
			if mm.cfg.transport.active.Load() != epoch {
				close(abandoned)
				return nil, nil, true
			}
		}
	}
}

func (mm *muxManager) refreshEndpointLocked() {
	var current *activeEndpoint
	if mm.cfg.transport.active != nil {
		current = mm.cfg.transport.active.Load()
	}
	if current != mm.endpointEpoch {
		mm.endpointEpoch = current
		// Dials started for the prior endpoint may still be blocked in TCP/TLS. They will discard their
		// results when they return; do not count them against this endpoint's cold-start/growth slots.
		mm.opening = 0
	}
}

func (mm *muxManager) currentEndpoint(m *steerMuxClient) bool {
	return m.active == nil || m.active.Load() == m.endpoint
}

// openFlow retries only the harmless acquire/open race in which failover changes the endpoint between the
// pool selection and the OPEN frame. Ordinary transport and policy errors still reach the caller unchanged.
func (mm *muxManager) openFlow(authority string, owners ...stepUpOwner) (*muxFlowConn, error) {
	for attempt := 0; attempt < 3; attempt++ {
		m, err := mm.acquire()
		if err != nil {
			return nil, err
		}
		fc, err := m.openFlow(authority, owners...)
		if errors.Is(err, errMuxEndpointChanged) {
			mm.invalidate(m)
			continue
		}
		if err != nil {
			mm.invalidate(m)
		}
		return fc, err
	}
	return nil, errMuxEndpointChanged
}

func (mm *muxManager) pruneLocked() {
	kept := mm.pool[:0]
	for _, m := range mm.pool {
		if !mm.currentEndpoint(m) {
			// Existing flows cannot migrate between mux sockets. Close them promptly so applications retry;
			// keeping the old socket in the pool would also send every new flow to the failed entrance.
			fmt.Printf("steer_mux_retired_after_switch mux=%d peer=%s\n", m.id, m.peer)
			go m.teardown()
		} else if m.healthy() {
			kept = append(kept, m)
		}
	}
	mm.pool = kept
}

func (mm *muxManager) activeLocked() int {
	n := 0
	for _, m := range mm.pool {
		n += m.load()
	}
	return n
}

func (mm *muxManager) leastLoadedLocked() *steerMuxClient {
	best := mm.pool[0]
	bestLoad := best.load()
	for _, m := range mm.pool[1:] {
		if l := m.load(); l < bestLoad {
			best, bestLoad = m, l
		}
	}
	return best
}

// shrinkIdleLocked closes zero-flow surplus connections until the pool is at `desired`. It only ever removes idle
// connections, so a connection carrying flows is never torn out from under them.
func (mm *muxManager) shrinkIdleLocked(desired int) {
	for len(mm.pool) > desired {
		idx := -1
		for i, m := range mm.pool {
			if m.load() == 0 {
				idx = i
				break
			}
		}
		if idx < 0 {
			return
		}
		m := mm.pool[idx]
		mm.pool = append(mm.pool[:idx], mm.pool[idx+1:]...)
		go m.teardown()
		fmt.Printf("steer_mux_pool shrank to %d conns (idle surplus)\n", len(mm.pool))
	}
}

// growOne opens one more connection in the background and adds it to the pool (best-effort; a failed dial just
// leaves the pool as-is and the next acquire retries).
func (mm *muxManager) growOne(epoch *activeEndpoint) {
	m, err := openSteerMux(mm.cfg, mm.dialTimeout)
	mm.mu.Lock()
	mm.refreshEndpointLocked()
	if epoch == mm.endpointEpoch {
		mm.opening--
	}
	if err == nil && epoch == mm.endpointEpoch && mm.currentEndpoint(m) {
		mm.pool = append(mm.pool, m)
		fmt.Printf("steer_mux_pool grew to %d conns (load)\n", len(mm.pool))
	} else if m != nil {
		go m.teardown()
	}
	mm.cond.Broadcast()
	mm.mu.Unlock()
}

// size reports the current pool size (test/diagnostic helper).
func (mm *muxManager) size() int {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	return len(mm.pool)
}

// invalidate removes a dead connection from the pool and tears it down. Called when a flow's OPEN fails because
// the connection died between acquire() and openFlow; the next acquire re-grows toward desired.
func (mm *muxManager) invalidate(m *steerMuxClient) {
	mm.mu.Lock()
	for i, c := range mm.pool {
		if c == m {
			mm.pool = append(mm.pool[:i], mm.pool[i+1:]...)
			break
		}
	}
	mm.cond.Broadcast()
	mm.mu.Unlock()
	m.teardown()
}

// muxAuthority builds the OPEN-frame payload: the destination authority ("host:port", already IPv6-bracketed by
// origDst.String()), optionally followed by a NUL byte and SPACE-separated "key=value" metadata — "u=<os-user>"
// (who) and "a=<app>" (what tool). The Edge splits on the first NUL and reads the space-separated keys (sanitized
// + length-bounded on its side). Absent fields are omitted, so a flow with no metadata sends exactly the legacy
// "host:port" payload (backward compatible). Values never contain spaces (an account/image name does not).
func muxAuthority(dst, osUser, app string) string {
	var parts []string
	// A value containing a space would break the space-separated key=value framing, so omit it defensively
	// (the source resolvers already avoid spaces; this guards against any unexpected one — fail-safe over corrupt).
	if osUser != "" && !strings.ContainsRune(osUser, ' ') {
		parts = append(parts, "u="+osUser)
	}
	if app != "" && !strings.ContainsRune(app, ' ') {
		parts = append(parts, "a="+app)
	}
	if len(parts) == 0 {
		return dst
	}
	return dst + "\x00" + strings.Join(parts, " ")
}

// handleFlowMux carries one flow over the shared mux instead of a dedicated CONNECT /steer tunnel. The Edge
// applies the SAME policy per OPEN: an allowed flow exchanges DATA, a denied one closes with no bytes. For an
// East-West "authenticate" verdict the Edge does NOT just close — it sends a STEPUP(3) frame carrying the
// portal URL, which the demux loop opens in the user's browser (same coordinator as the per-flow path, mirrors
// the macOS NE muxFrameStepUp). So agent-mediated step-up now works over the mux too; the flow stays held until
// a grant is minted and the connection is retried (a still-denied retry closes with no bytes as before).
func (s edgeSteerer) handleFlowMux(flow SteeredFlow, origDst netip.AddrPort) {
	osUser := osUserForPID(flow.PID)
	app := osAppForPID(flow.PID)
	clientPort := 0
	if addr, ok := flow.Conn.RemoteAddr().(*net.TCPAddr); ok {
		clientPort = addr.Port
	}
	fc, err := s.mux.openFlow(muxAuthority(origDst.String(), osUser, app), captureStepUpOwner(flow.PID))
	if err != nil {
		s.muxUnreachable(flow, origDst, err)
		return
	}
	s.cfg.health.recordSuccess()
	// Learn signature-form exclusions from the flows they failed to prevent: if this app matches a
	// signed:/publisher:/subject:/thumbprint: rule, its exact image path belongs in the kernel's verified table
	// and is evidently not there yet. Non-blocking and no-op when no such rule is active.
	noteSteeredPID(flow.PID)
	fmt.Printf("steer_mux_forwarded mux=%d peer=%s dst_port=%d flow=%d client_port=%d user=%q app=%q\n", fc.mux.id, fc.mux.peer, origDst.Port(), fc.flowID, clientPort, osUser, app)
	toEdge, toApp := pipe(flow.Conn, fc, fmt.Sprintf("flow=%d app=%q dst=%s", fc.flowID, app, origDst))
	// #28: mux_in_* is what the Edge actually delivered to this client for this flow; edge_to_app is what
	// reached the application socket. Comparing them splits "the Edge never sent the reply" from "we received
	// it and could not hand it over".
	fmt.Printf("steer_flow_end mux=%d peer=%s flow=%d client_port=%d app=%q dst=%s app_to_edge=%d edge_to_app=%d mux_in_frames=%d mux_in_bytes=%d first_app_data_ms=%d first_edge_data_ms=%d edge_sent_close=%t\n",
		fc.mux.id, fc.mux.peer, fc.flowID, clientPort, app, origDst, toEdge, toApp, fc.inFrames.Load(), fc.inBytes.Load(),
		firstFlowDataMS(fc.firstAppDataNS.Load()), firstFlowDataMS(fc.firstEdgeDataNS.Load()), fc.edgeClosed.Load())
	// One pointer store, and deliberately nothing more. The interception watch needs somewhere this device
	// actually talks to in order to probe it; judging the flow itself was tried and the box's own log refuted it
	// (see the note at the top of interception_observation.go).
	s.cfg.interception.noteDestination(origDst.String())
}

// muxUnreachable handles a dead transport for the mux path with the SAME fail-open/fail-closed semantics as the
// per-flow error branch: a transport-layer failure trips the breaker and, under --fail-open, sends the flow
// direct/unmediated; fail-closed drops it.
func (s edgeSteerer) muxUnreachable(flow SteeredFlow, origDst netip.AddrPort, err error) {
	fmt.Printf("steer_edge_decision decision=error dst=%s status=0 err=%v\n", origDst, err)
	// ★★★ REMOVED, BY THE OPERATOR'S RULING (2026-08-26). A refused handshake used to be treated as "the Edge
	// is alive and enforcing", which kept a blocked device off the internet under --fail-open. It also kept
	// EVERY device off the internet the moment their certificates expired, because a refusal for any reason —
	// blocked, revoked, expired, a misconfigured anchor — arrives here identically and the code said so in its
	// own comment. The operator's definition settles it:
	//
	//	fail-open exists so a device is not cut off from the internet BECAUSE it is being steered.
	//	Whether the cause is unreachable or refused does not matter. If DSSE cannot protect this device,
	//	the device keeps working unprotected. An operator who does not want that sets fail-closed —
	//	which is the default, and what --fail-open's own help warns about.
	//
	// So "blocking stops a device" is a property of fail-CLOSED, not something to special-case here.
	if s.cfg.failOpen {
		if opened := s.cfg.health.recordFailure(); opened {
			fmt.Printf("steer_failopen: edge unreachable (%v) — circuit OPEN, flows go direct for the cooldown\n", err)
		}
		s.failOpenDirect(flow, origDst, "edge_unreachable")
		return
	}
	fmt.Printf("steer_blocked reason=mux_unreachable dst_port=%d\n", origDst.Port())
}

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMuxUnexpectedTransportLossSignalsOnlyCurrentLiveSocket(t *testing.T) {
	signals := make(chan struct{}, 1)
	current := &activeEndpoint{}
	active := &atomic.Pointer[activeEndpoint]{}
	active.Store(current)
	newMux := func() *steerMuxClient {
		return &steerMuxClient{endpoint: current, active: active, transportFailure: signals, dead: make(chan struct{})}
	}
	m := newMux()
	m.signalUnexpectedTransportLoss()
	select {
	case <-signals:
	default:
		t.Fatal("live current mux loss did not wake the selector")
	}
	close(m.dead) // mirrors the intentional-teardown marker without a test socket
	m.signalUnexpectedTransportLoss()
	select {
	case <-signals:
		t.Fatal("intentional teardown signaled a failure")
	default:
	}
	m = newMux()
	active.Store(&activeEndpoint{})
	m.signalUnexpectedTransportLoss()
	select {
	case <-signals:
		t.Fatal("old entrance signaled after endpoint switch")
	default:
	}
}

func TestMuxWarnIsDeliveredOnlyForTheFrameFlowOwner(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	a := testWarnOwner(42, 1, "user-a", 10)
	b := testWarnOwner(43, 2, "user-b", 11)
	got := make(chan stepUpOwner, 3)
	m := &steerMuxClient{
		conn: client, dead: make(chan struct{}), flows: map[uint32]*muxFlowConn{},
		warn: newWarnNotifier(func(_, _ string, owner stepUpOwner) { got <- owner }, nil),
	}
	m.flows[1] = &muxFlowConn{flowID: 1, mux: m, inbound: newMuxPipe(muxFlowBufCap), owner: a}
	m.flows[2] = &muxFlowConn{flowID: 2, mux: m, inbound: newMuxPipe(muxFlowBufCap), owner: b}
	done := make(chan struct{})
	go func() { m.readLoop(bufio.NewReader(client)); close(done) }()
	payload := []byte(`{"destination":"10.20.0.10","service":"ssh"}`)
	for _, id := range []uint32{1, 2, 0, 3} {
		var hdr [muxHeaderLen]byte
		binary.BigEndian.PutUint32(hdr[:4], id)
		hdr[4] = muxFrameWarn
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
		if _, err := server.Write(append(hdr[:], payload...)); err != nil {
			t.Fatal(err)
		}
	}
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mux read loop did not close")
	}
	seen := map[stepUpOwner]bool{}
	for len(seen) < 2 {
		select {
		case owner := <-got:
			seen[owner] = true
		case <-time.After(time.Second):
			t.Fatalf("missing owner-bound WARN: %+v", seen)
		}
	}
	if !seen[a] || !seen[b] {
		t.Fatalf("WARN escaped its flow owner: %+v", seen)
	}
	select {
	case owner := <-got:
		t.Fatalf("unknown flow emitted WARN: %+v", owner)
	default:
	}
}

func TestSlowMuxFlowCannotHoldAnotherFlowBehindItsInboundBuffer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	m := &steerMuxClient{conn: client, dead: make(chan struct{}), flows: make(map[uint32]*muxFlowConn)}
	slow := &muxFlowConn{flowID: 1, mux: m, inbound: newMuxPipe(4), openedAt: time.Now()}
	fast := &muxFlowConn{flowID: 2, mux: m, inbound: newMuxPipe(4), openedAt: time.Now()}
	m.flows[1], m.flows[2] = slow, fast
	done := make(chan struct{})
	go func() { m.readLoop(bufio.NewReader(client)); close(done) }()
	defer func() { m.teardown(); <-done }()
	write := func(id uint32, payload string) {
		t.Helper()
		var hdr [muxHeaderLen]byte
		binary.BigEndian.PutUint32(hdr[:4], id)
		hdr[4] = muxFrameData
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
		if _, err := server.Write(append(hdr[:], payload...)); err != nil {
			t.Fatal(err)
		}
	}
	write(1, "aaaa") // fill the slow flow's bounded inbound buffer
	write(1, "bbbb") // this flow may be closed, but must not stall the demux
	write(2, "ok")
	got := make(chan string, 1)
	go func() { b := make([]byte, 2); n, _ := fast.Read(b); got <- string(b[:n]) }()
	select {
	case s := <-got:
		if s != "ok" {
			t.Fatalf("fast flow received %q", s)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow flow blocked an unrelated flow behind the demux loop")
	}
}

func TestColdMuxDialAbandonsOldEntranceAfterSelectorSwitch(t *testing.T) {
	current := &activeEndpoint{}
	active := &atomic.Pointer[activeEndpoint]{}
	active.Store(current)
	mm := newMuxManager(edgeConfig{transport: transportConfig{active: active}}, 2*time.Second, 12, 1)
	oldStarted := make(chan struct{})
	releaseOld := make(chan struct{})
	oldClient, oldServer := net.Pipe()
	defer oldServer.Close()
	oldMux := &steerMuxClient{conn: oldClient, dead: make(chan struct{}), flows: make(map[uint32]*muxFlowConn)}
	result := make(chan bool, 1)
	go func() {
		_, _, abandoned := mm.openFirstForEpoch(current, func(edgeConfig, time.Duration) (*steerMuxClient, error) {
			close(oldStarted)
			<-releaseOld // emulate a blocked dial to the failed entrance
			return oldMux, nil
		})
		result <- abandoned
	}()
	<-oldStarted
	active.Store(&activeEndpoint{})
	select {
	case abandoned := <-result:
		if !abandoned {
			t.Fatal("old entrance dial completed instead of being abandoned")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("flow remained behind the old entrance dial after switch")
	}
	close(releaseOld)
	select {
	case <-oldMux.dead:
	case <-time.After(time.Second):
		t.Fatal("abandoned dial did not close its eventual mux")
	}
}

func TestMuxConnectResponseIsBoundedAfterTCPDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Leave CONNECT unanswered until the client deadline closes the socket.
		_, _ = io.Copy(io.Discard, conn)
	}()
	start := time.Now()
	m, err := openSteerMux(edgeConfig{edgeURL: "http://" + ln.Addr().String()}, 100*time.Millisecond)
	if m != nil || err == nil {
		t.Fatalf("unanswered CONNECT must fail, mux=%v err=%v", m, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CONNECT deadline was not enforced: %s", elapsed)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("test server did not see the timed-out socket close")
	}
}

// fakeMuxEdge is a minimal server speaking the mux wire protocol: it accepts CONNECT /steer-mux, replies 200,
// then demultiplexes frames. For each OPEN it records the authority; DATA is echoed back on the same flowID
// (loopback), so a client write should read its own bytes back — exercising the full frame round-trip. It also
// records OPEN authorities so the test can assert flowID assignment and authority delivery.
type fakeMuxEdge struct {
	mu          sync.Mutex
	openedAuth  map[uint32]string
	sawMuxPath  bool
	firstReqRaw string
}

func (f *fakeMuxEdge) serve(t *testing.T, ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	f.serveConn(conn)
}

func (f *fakeMuxEdge) serveConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReaderSize(conn, 64*1024)
	// Read the CONNECT request head up to the blank line.
	var head strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	f.mu.Lock()
	f.firstReqRaw = head.String()
	f.sawMuxPath = strings.Contains(f.firstReqRaw, "CONNECT /steer-mux ")
	f.mu.Unlock()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Demux loop: echo DATA back on the same flowID.
	var writeMu sync.Mutex
	writeFrame := func(flowID uint32, typ uint8, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		var hdr [muxHeaderLen]byte
		binary.BigEndian.PutUint32(hdr[0:4], flowID)
		hdr[4] = typ
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return err
		}
		if len(payload) > 0 {
			_, err := conn.Write(payload)
			return err
		}
		return nil
	}
	var hdr [muxHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		flowID := binary.BigEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		length := binary.BigEndian.Uint32(hdr[5:9])
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				return
			}
		}
		switch typ {
		case muxFrameOpen:
			f.mu.Lock()
			f.openedAuth[flowID] = string(payload)
			f.mu.Unlock()
		case muxFrameData:
			if err := writeFrame(flowID, muxFrameData, payload); err != nil {
				return
			}
		case muxFrameClose:
			// no-op for the echo server
		}
	}
}

func newFakeMuxEdge(t *testing.T) (*fakeMuxEdge, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeMuxEdge{openedAuth: make(map[uint32]string)}
	go f.serve(t, ln)
	return f, ln.Addr().String(), func() { ln.Close() }
}

// newFakeMuxEdgeMulti accepts MANY mux connections (each served by its own goroutine) and counts them, so pool
// growth/shrink can be observed. accepted() returns the number of transport connections the pool has opened.
func newFakeMuxEdgeMulti(t *testing.T) (accepted func() int, addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	n := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			n++
			mu.Unlock()
			f := &fakeMuxEdge{openedAuth: make(map[uint32]string)}
			go f.serveConn(conn)
		}
	}()
	accepted = func() int { mu.Lock(); defer mu.Unlock(); return n }
	return accepted, ln.Addr().String(), func() { ln.Close() }
}

func newFakeMuxTLSEdge(t *testing.T, cert tls.Certificate, accepted chan<- struct{}, release <-chan struct{}) (*fakeMuxEdge, string, func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMuxEdge{openedAuth: make(map[uint32]string)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if accepted != nil {
				accepted <- struct{}{}
			}
			go func() {
				if release != nil {
					<-release
				}
				f.serveConn(conn)
			}()
		}
	}()
	return f, ln.Addr().String(), func() { _ = ln.Close() }
}

func muxTestTransport(certPEM []byte, addr string) (transportConfig, *atomic.Pointer[activeEndpoint]) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	active := &atomic.Pointer[activeEndpoint]{}
	active.Store(&activeEndpoint{host: addr, serverName: "127.0.0.1", dialAddrs: []string{addr}})
	return transportConfig{enabled: true, host: addr, serverName: "127.0.0.1", rootCAs: pool, active: active}, active
}

func TestMuxManagerSwitchesNewFlowsToNewEndpoint(t *testing.T) {
	certPEM, _, cert := mkSelfSigned(t, "mux-edge", []net.IP{net.ParseIP("127.0.0.1")})
	a, addrA, stopA := newFakeMuxTLSEdge(t, cert, nil, nil)
	defer stopA()
	b, addrB, stopB := newFakeMuxTLSEdge(t, cert, nil, nil)
	defer stopB()
	tc, active := muxTestTransport(certPEM, addrA)
	mm := newMuxManager(edgeConfig{transport: tc}, 2*time.Second, 12, 1)
	first, err := mm.openFlow("first.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	oldMux := first.mux
	if !waitFor(time.Second, func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.openedAuth[1] == "first.example:443" }) {
		t.Fatal("initial flow did not reach A")
	}
	active.Store(&activeEndpoint{host: addrB, serverName: "127.0.0.1", dialAddrs: []string{addrB}})
	if _, err := oldMux.openFlow("stale.example:443"); !errors.Is(err, errMuxEndpointChanged) {
		t.Fatalf("old mux OPEN after switch: %v", err)
	}
	second, err := mm.openFlow("second.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if !waitFor(time.Second, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.openedAuth[1] == "second.example:443" }) {
		t.Fatal("new flow did not reach B")
	}
	if !waitFor(time.Second, func() bool { return !oldMux.healthy() }) {
		t.Fatal("old mux was not closed after switch")
	}
	a.mu.Lock()
	_, staleOpened := a.openedAuth[2]
	a.mu.Unlock()
	if staleOpened {
		t.Fatal("A received a flow after the endpoint changed")
	}
}

func TestMuxManagerDiscardsDialCompletedAfterSwitch(t *testing.T) {
	certPEM, _, cert := mkSelfSigned(t, "mux-edge", []net.IP{net.ParseIP("127.0.0.1")})
	accepted := make(chan struct{}, 1)
	release := make(chan struct{})
	a, addrA, stopA := newFakeMuxTLSEdge(t, cert, accepted, release)
	defer stopA()
	b, addrB, stopB := newFakeMuxTLSEdge(t, cert, nil, nil)
	defer stopB()
	tc, active := muxTestTransport(certPEM, addrA)
	mm := newMuxManager(edgeConfig{transport: tc}, 2*time.Second, 12, 1)
	type result struct {
		flow *muxFlowConn
		err  error
	}
	done := make(chan result, 1)
	go func() { fc, err := mm.openFlow("after-switch.example:443"); done <- result{fc, err} }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("dial to A did not start")
	}
	active.Store(&activeEndpoint{host: addrB, serverName: "127.0.0.1", dialAddrs: []string{addrB}})
	close(release)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.flow.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not move to B")
	}
	if !waitFor(time.Second, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.openedAuth[1] == "after-switch.example:443" }) {
		t.Fatal("new flow did not reach B")
	}
	a.mu.Lock()
	openedOnA := len(a.openedAuth)
	a.mu.Unlock()
	if openedOnA != 0 {
		t.Fatalf("in-flight old dial received %d OPEN frames", openedOnA)
	}
}

func TestMuxManagerDoesNotWaitForOldDialTimeoutAfterSwitch(t *testing.T) {
	certPEM, _, cert := mkSelfSigned(t, "mux-edge", []net.IP{net.ParseIP("127.0.0.1")})
	accepted := make(chan struct{}, 1)
	release := make(chan struct{})
	_, addrA, stopA := newFakeMuxTLSEdge(t, cert, accepted, release)
	defer stopA()
	_, addrB, stopB := newFakeMuxTLSEdge(t, cert, nil, nil)
	defer stopB()
	tc, active := muxTestTransport(certPEM, addrA)
	mm := newMuxManager(edgeConfig{transport: tc}, 2*time.Second, 12, 1)
	firstDone := make(chan error, 1)
	go func() {
		fc, err := mm.openFlow("first.example:443")
		if fc != nil {
			defer fc.Close()
		}
		firstDone <- err
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("dial to A did not start")
	}
	active.Store(&activeEndpoint{host: addrB, serverName: "127.0.0.1", dialAddrs: []string{addrB}})
	secondDone := make(chan error, 1)
	go func() {
		fc, err := mm.openFlow("second.example:443")
		if fc != nil {
			defer fc.Close()
		}
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new endpoint waited for the old endpoint's stalled TLS handshake")
	}
	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old dial caller did not retry on B")
	}
}

func TestSteerMuxHandshakeAndEcho(t *testing.T) {
	f, addr, stop := newFakeMuxEdge(t)
	defer stop()

	cfg := edgeConfig{edgeURL: "http://" + addr}
	m, err := openSteerMux(cfg, 2*time.Second)
	if err != nil {
		t.Fatalf("openSteerMux: %v", err)
	}
	defer m.teardown()

	fc, err := m.openFlow("example.com:443")
	if err != nil {
		t.Fatalf("openFlow: %v", err)
	}
	if fc.flowID != 1 {
		t.Fatalf("first flowID = %d, want 1", fc.flowID)
	}
	if got := firstFlowDataMS(fc.firstEdgeDataNS.Load()); got != -1 {
		t.Fatalf("edge data before sending request = %dms, want absent", got)
	}

	// Write two chunks; expect the same bytes echoed back (possibly re-chunked, so accumulate).
	want := []byte("hello-mux-round-trip")
	if _, err := fc.Write(want[:5]); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if _, err := fc.Write(want[5:]); err != nil {
		t.Fatalf("write2: %v", err)
	}
	got := make([]byte, 0, len(want))
	buf := make([]byte, 64)
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < len(want) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out; got %q want %q", got, want)
		}
		_ = fc.inbound // read via the net.Conn surface
		n, err := fc.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got)
		}
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
	if firstFlowDataMS(fc.firstAppDataNS.Load()) < 0 || firstFlowDataMS(fc.firstEdgeDataNS.Load()) < 0 {
		t.Fatal("round trip omitted a first-data timestamp")
	}

	// A second flow must get a distinct monotonic id and its own authority.
	fc2, err := m.openFlow("[2606:4700::1]:443")
	if err != nil {
		t.Fatalf("openFlow2: %v", err)
	}
	if fc2.flowID != 2 {
		t.Fatalf("second flowID = %d, want 2", fc2.flowID)
	}
	// Give the server a moment to record the OPEN authorities.
	time.Sleep(100 * time.Millisecond)

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sawMuxPath {
		t.Fatalf("server did not see CONNECT /steer-mux; got head:\n%s", f.firstReqRaw)
	}
	if f.openedAuth[1] != "example.com:443" {
		t.Fatalf("flow1 authority = %q, want example.com:443", f.openedAuth[1])
	}
	if f.openedAuth[2] != "[2606:4700::1]:443" {
		t.Fatalf("flow2 authority = %q, want [2606:4700::1]:443", f.openedAuth[2])
	}
}

// TestMuxPipeBackpressureAndEOF checks the bounded pipe: Read blocks until data, delivers it, and returns EOF
// after Close once drained.
func TestMuxPipeBackpressureAndEOF(t *testing.T) {
	p := newMuxPipe(8)
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := p.Read(buf) // blocks until Write below
		done <- buf[:n]
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := p.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-done:
		if string(got) != "abc" {
			t.Fatalf("read got %q, want abc", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not wake on Write")
	}
	p.Close()
	if _, err := p.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("after Close, Read err = %v, want EOF", err)
	}
}

// TestMuxManagerAdaptivePool checks the pool grows toward desired under load and shrinks back to 1 when idle.
func TestMuxManagerAdaptivePool(t *testing.T) {
	accepted, addr, stop := newFakeMuxEdgeMulti(t)
	defer stop()

	// flowsPerConn=2, maxConns=3 → desired = clamp(1 + active/2, 1, 3).
	mm := newMuxManager(edgeConfig{edgeURL: "http://" + addr}, 2*time.Second, 2, 3)

	// Cold start: first acquire opens exactly one connection (coalesced).
	c1, err := mm.acquire()
	if err != nil {
		t.Fatalf("acquire#1: %v", err)
	}
	if mm.size() != 1 {
		t.Fatalf("pool after first acquire = %d, want 1", mm.size())
	}

	// Put load on the pool: open 4 flows (active=4 → desired = clamp(1+4/2,1,3) = 3). Repeated acquires grow the
	// pool one background conn at a time; poll until it reaches 3.
	held := []*muxFlowConn{}
	for i := 0; i < 4; i++ {
		fc, err := c1.openFlow("load.example:443")
		if err != nil {
			t.Fatalf("openFlow load#%d: %v", i, err)
		}
		held = append(held, fc)
	}
	if !waitFor(2*time.Second, func() bool { _, _ = mm.acquire(); return mm.size() >= 3 }) {
		t.Fatalf("pool did not grow to 3 under load; size=%d accepted=%d", mm.size(), accepted())
	}
	if mm.size() != 3 { // clamped at maxConns even though 1+4/2 would allow no more anyway
		t.Fatalf("pool grew past max: size=%d", mm.size())
	}

	// Drop the load: close all flows (active=0 → desired=1). Next acquires shrink idle surplus back to 1.
	for _, fc := range held {
		fc.Close()
	}
	if !waitFor(2*time.Second, func() bool { _, _ = mm.acquire(); return mm.size() == 1 }) {
		t.Fatalf("pool did not shrink to 1 when idle; size=%d", mm.size())
	}
}

func TestMuxAuthority(t *testing.T) {
	cases := []struct{ dst, user, app, want string }{
		{"example.com:443", "", "", "example.com:443"},                                                   // nothing -> legacy
		{"[2606:4700::1]:443", "", "", "[2606:4700::1]:443"},                                             // IPv6 stays bracketed
		{"example.com:443", `CORP\alice`, "", "example.com:443\x00u=CORP\\alice"},                        // user only
		{"example.com:443", "", "chrome.exe", "example.com:443\x00a=chrome.exe"},                         // app only
		{"example.com:443", `CORP\alice`, "chrome.exe", "example.com:443\x00u=CORP\\alice a=chrome.exe"}, // both, space-joined
		{"[2606:4700::1]:443", "bob", "curl.exe", "[2606:4700::1]:443\x00u=bob a=curl.exe"},              // IPv6 + both
	}
	for _, c := range cases {
		if got := muxAuthority(c.dst, c.user, c.app); got != c.want {
			t.Errorf("muxAuthority(%q,%q,%q) = %q, want %q", c.dst, c.user, c.app, got, c.want)
		}
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestSteerMuxStepUpOpensPortal verifies the East-West "authenticate" mediation over the mux: when the Edge
// sends a STEPUP(3) frame for a held flow, the demux loop opens the portal via the injected coordinator
// (resource = the flow's authority, url = the frame payload). This is the fix for the Windows-mux gap where a
// held Authenticate flow was silently closed with no browser.
func TestSteerMuxStepUpOpensPortal(t *testing.T) {
	const portal = "https://203.0.113.10:8443/clientless/auth/start?device=win-dev-1&return_to=10.20.0.10:22"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReaderSize(conn, 64*1024)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		var hdr [muxHeaderLen]byte
		for {
			if _, err := io.ReadFull(r, hdr[:]); err != nil {
				return
			}
			flowID := binary.BigEndian.Uint32(hdr[0:4])
			typ := hdr[4]
			length := binary.BigEndian.Uint32(hdr[5:9])
			if length > 0 {
				if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
					return
				}
			}
			if typ == muxFrameOpen { // reply with a STEPUP frame for this held flow
				var out [muxHeaderLen]byte
				binary.BigEndian.PutUint32(out[0:4], flowID)
				out[4] = muxFrameStepUp
				binary.BigEndian.PutUint32(out[5:9], uint32(len(portal)))
				conn.Write(out[:])
				conn.Write([]byte(portal))
			}
		}
	}()
	var mu sync.Mutex
	var gotRes, gotURL string
	done := make(chan struct{})
	spy := func(resource, url string) { mu.Lock(); gotRes, gotURL = resource, url; mu.Unlock(); close(done) }
	cfg := edgeConfig{edgeURL: "http://" + ln.Addr().String(), stepUp: newStepUpCoordinator(time.Second, spy, func(string, ...any) {})}
	m, err := openSteerMux(cfg, 2*time.Second)
	if err != nil {
		t.Fatalf("openSteerMux: %v", err)
	}
	defer m.teardown()
	if _, err := m.openFlow("10.20.0.10:22"); err != nil {
		t.Fatalf("openFlow: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("step-up launcher was not called on a STEPUP frame (mux step-up not wired)")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotURL != portal {
		t.Errorf("portal url = %q, want %q", gotURL, portal)
	}
	if gotRes != "10.20.0.10:22" {
		t.Errorf("resource = %q, want the flow authority 10.20.0.10:22", gotRes)
	}
}

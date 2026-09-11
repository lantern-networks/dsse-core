package edgeplane

import (
	"io"
	"net"
	"sync"
	"time"
)

// bufferedPipeTimeoutError is returned by Read when the read deadline is exceeded. It is a net.Error with
// Timeout()==true so callers (the runtime-copy session pump, tls.Conn) treat it as a retryable timeout — the
// same contract net.Pipe honors. Without this, a deadline set on the pipe is silently ignored.
type bufferedPipeTimeoutError struct{}

func (bufferedPipeTimeoutError) Error() string {
	return "buffered interception pipe: read deadline exceeded"
}
func (bufferedPipeTimeoutError) Timeout() bool   { return true }
func (bufferedPipeTimeoutError) Temporary() bool { return true }

// BufferedPipeHalf is a bounded in-memory byte buffer with blocking Read/Write for ONE direction.
type BufferedPipeHalf struct {
	mu           sync.Mutex
	cond         *sync.Cond
	buf          []byte
	closed       bool
	cap          int
	totalWritten int64
	// readDeadline, when non-zero, bounds a blocking Read: a timer broadcasts the cond at the deadline so a Read
	// waiting on an empty buffer wakes and returns bufferedPipeTimeoutError instead of blocking forever. The
	// runtime-copy session pump relies on this to time-slice a TLS handshake's flights (drain what the server
	// produced, return it so the client can send the next flight); a raw net.Pipe honors deadlines, this must too.
	readDeadline  time.Time
	deadlineTimer *time.Timer
}

func NewBufferedPipeHalf(capBytes int) *BufferedPipeHalf {
	h := &BufferedPipeHalf{cap: capBytes}
	h.cond = sync.NewCond(&h.mu)
	return h
}

// setReadDeadline arms (or clears, when t is zero) the read deadline. A timer broadcasts the cond at the
// deadline so a blocked Read wakes and observes it.
func (h *BufferedPipeHalf) setReadDeadline(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.readDeadline = t
	if h.deadlineTimer != nil {
		h.deadlineTimer.Stop()
		h.deadlineTimer = nil
	}
	if t.IsZero() {
		return
	}
	d := time.Until(t)
	if d <= 0 {
		h.cond.Broadcast()
		return
	}
	h.deadlineTimer = time.AfterFunc(d, func() {
		h.mu.Lock()
		h.cond.Broadcast()
		h.mu.Unlock()
	})
}

func (h *BufferedPipeHalf) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for len(h.buf) >= h.cap && !h.closed {
			h.cond.Wait()
		}
		if h.closed {
			return written, io.ErrClosedPipe
		}
		space := h.cap - len(h.buf)
		n := len(p)
		if n > space {
			n = space
		}
		h.buf = append(h.buf, p[:n]...)
		h.totalWritten += int64(n)
		p = p[n:]
		written += n
		h.cond.Broadcast()
	}
	return written, nil
}

func (h *BufferedPipeHalf) Read(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for len(h.buf) == 0 && !h.closed {
		if !h.readDeadline.IsZero() && !time.Now().Before(h.readDeadline) {
			return 0, bufferedPipeTimeoutError{}
		}
		h.cond.Wait()
	}
	if len(h.buf) == 0 && h.closed {
		return 0, io.EOF
	}
	n := copy(p, h.buf)
	h.buf = h.buf[n:]
	h.cond.Broadcast()
	return n, nil
}

func (h *BufferedPipeHalf) Close() {
	h.mu.Lock()
	h.closed = true
	h.cond.Broadcast()
	h.mu.Unlock()
}

type bufferedPipeAddr struct{}

func (bufferedPipeAddr) Network() string { return "buffered-pipe" }
func (bufferedPipeAddr) String() string  { return "buffered-pipe" }

// bufferedPipeConn is one end of a buffered duplex pipe: it Reads its half and Writes the peer's half.
type bufferedPipeConn struct {
	readHalf  *BufferedPipeHalf
	writeHalf *BufferedPipeHalf
	onClose   func()
}

func (c *bufferedPipeConn) Read(p []byte) (int, error)  { return c.readHalf.Read(p) }
func (c *bufferedPipeConn) Write(p []byte) (int, error) { return c.writeHalf.Write(p) }
func (c *bufferedPipeConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	c.readHalf.Close()
	c.writeHalf.Close()
	return nil
}

// CloseWrite half-closes ONLY the write half: it delivers EOF to the peer that reads this side's writeHalf,
// while leaving the read half (the opposite direction) fully open. The tunnel bridge relies on this: when the
// browser→upstream (request) copy direction reaches EOF, it half-closes the write side of the interception
// pipe so serve()'s request reader sees EOF — WITHOUT tearing down the upstream→browser (response) direction.
//
// Without CloseWrite here, halfCloseWriteSide() falls back to Close-both, which killed the response before a
// single byte was written whenever the client flow's request direction EOF'd first — the exact Mac-NE decrypt-
// all failure where a POST with a streaming (chunked) response (e.g. amazon.co.jp/haul infinite-scroll
// getAsins) aborted with downstream_write=closed streamed_bytes=0 and the page skeletoned. A real TCP conn on
// the /steer path already has CloseWrite (TCPConn); this makes the in-process interception pipe behave the same.
func (c *bufferedPipeConn) CloseWrite() error {
	c.writeHalf.Close()
	return nil
}
func (c *bufferedPipeConn) LocalAddr() net.Addr  { return bufferedPipeAddr{} }
func (c *bufferedPipeConn) RemoteAddr() net.Addr { return bufferedPipeAddr{} }

// SetReadDeadline / SetDeadline bound this end's blocking Read (which reads readHalf). The write half is
// buffered (a Write only blocks when the buffer is full), so a write deadline is a no-op today.
func (c *bufferedPipeConn) SetDeadline(t time.Time) error { c.readHalf.setReadDeadline(t); return nil }
func (c *bufferedPipeConn) SetReadDeadline(t time.Time) error {
	c.readHalf.setReadDeadline(t)
	return nil
}
func (c *bufferedPipeConn) SetWriteDeadline(t time.Time) error { return nil }

// NewBufferedInterceptionPipe is a drop-in for net.Pipe() with an internal per-direction buffer: a Write
// returns as soon as the bytes are buffered (up to capBytes) instead of blocking until the peer Reads.
//
// Why: the Edge's decrypt-all interception runs the browser-facing tls.Server on the SERVER side of this pipe,
// while the endpoint's flow bytes are relayed onto the CLIENT side by a bridge that drains to the endpoint
// (Mac NE) over its tunnel. With a raw net.Pipe (synchronous, unbuffered), serve() writing the TLS ServerHello
// BLOCKS until the NE's ASYNC receive pump happens to read it. Under a browser's concurrent-flow burst on the
// steer (CONNECT /steer) path, that pump can lag just long enough that the handshake deadlocks (observed:
// handshake_completed=0/handshake_failed=0 after a successful SNI peek; pages hang / images drop). Buffering
// the handshake-sized writes decouples serve() from the pump's read cadence so the handshake completes.
func NewBufferedInterceptionPipe(capBytes int) (net.Conn, net.Conn) {
	clientToServer := NewBufferedPipeHalf(capBytes)
	serverToClient := NewBufferedPipeHalf(capBytes)
	clientSide := &bufferedPipeConn{readHalf: serverToClient, writeHalf: clientToServer}
	// TEMP diag: the SERVER side is the interception tls.Server; log byte flow each way when it closes to see
	// where a hung decrypt-all handshake stalls (c2s = ClientHello+Finished from the endpoint; s2c = ServerHello).
	serverSide := &bufferedPipeConn{readHalf: clientToServer, writeHalf: serverToClient, onClose: func() {
		clientToServer.mu.Lock()
		c2s := clientToServer.totalWritten
		clientToServer.mu.Unlock()
		serverToClient.mu.Lock()
		s2c := serverToClient.totalWritten
		serverToClient.mu.Unlock()
		Debugf("intercept_pipe_closed c2s=%d s2c=%d", c2s, s2c)
	}}
	return clientSide, serverSide
}

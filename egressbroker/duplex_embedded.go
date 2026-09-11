//go:build embedbroker

package egressbroker

import (
	"io"
	"sync"
)

// halfPipeCap is how many bytes one direction buffers before a writer blocks. It mirrors the engine's own
// client-read channel (64 chunks of 32 KiB), which is the sizing that has carried live AI chat streams.
const halfPipeCap = 64 * 32 * 1024

// halfPipe is one direction of an in-memory duplex: a bounded buffer with a condition variable.
//
// It is deliberately NOT io.Pipe or net.Pipe. Both are synchronous — a write blocks until a reader takes the
// bytes — and the WS relay is a SINGLE loop that must keep calling curl_ws_recv to answer the origin's
// keep-alive PING. A synchronous pipe lets one slow read stall that loop, the PONG goes unanswered, and the
// origin drops the WebSocket. Buffering breaks that coupling: the relay hands off and keeps looping. (The same
// trap, via net.Pipe used as a bridge, produced the connector-tunnel goroutine leak fixed earlier.)
//
// A writer still blocks once the buffer is genuinely full, which is correct: at that point the reader has
// stopped consuming and the flow is dead either way. Dropping bytes instead would corrupt a frame stream.
type halfPipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newHalfPipe() *halfPipe {
	h := &halfPipe{}
	h.cond = sync.NewCond(&h.mu)
	return h
}

func (h *halfPipe) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for len(h.buf) >= halfPipeCap && !h.closed {
			h.cond.Wait()
		}
		if h.closed {
			return written, io.ErrClosedPipe
		}
		n := halfPipeCap - len(h.buf)
		if n > len(p) {
			n = len(p)
		}
		h.buf = append(h.buf, p[:n]...)
		p = p[n:]
		written += n
		h.cond.Broadcast()
	}
	return written, nil
}

func (h *halfPipe) Read(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for len(h.buf) == 0 && !h.closed {
		h.cond.Wait()
	}
	if len(h.buf) == 0 {
		return 0, io.EOF // closed and drained: readers see the buffered bytes first, then EOF
	}
	n := copy(p, h.buf)
	h.buf = append(h.buf[:0], h.buf[n:]...) // compact, so the backing array does not creep forward
	h.cond.Broadcast()
	return n, nil
}

func (h *halfPipe) Close() error {
	h.mu.Lock()
	h.closed = true
	h.cond.Broadcast()
	h.mu.Unlock()
	return nil
}

// duplex is one end of the pair: it reads what the other end wrote, and writes what the other end reads.
type duplex struct {
	r *halfPipe
	w *halfPipe
}

func (d duplex) Read(p []byte) (int, error)  { return d.r.Read(p) }
func (d duplex) Write(p []byte) (int, error) { return d.w.Write(p) }

// Close ends BOTH directions. Either side hanging up tears the tunnel down — a WS half-close is not something
// the relay loop models, and leaving one direction open would strand the other end's blocked reader.
func (d duplex) Close() error {
	d.r.Close()
	d.w.Close()
	return nil
}

// newBufferedDuplex returns the two ends of an in-memory full-duplex pipe: what one end writes, the other
// reads. edgeSide becomes the Response.Body handed back to the edge; engineSide is what the relay loop sees.
func newBufferedDuplex() (edgeSide io.ReadWriteCloser, engineSide io.ReadWriter) {
	edgeToEngine, engineToEdge := newHalfPipe(), newHalfPipe()
	return duplex{r: engineToEdge, w: edgeToEngine}, duplex{r: edgeToEngine, w: engineToEdge}
}

package main

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// flushCountingWriter is an http.ResponseWriter that counts Flush calls, to prove the egress relay flushes
// streamed chunks to the client instead of buffering them.
type flushCountingWriter struct {
	buf     bytes.Buffer
	flushes int
	hdr     http.Header
}

func (f *flushCountingWriter) Header() http.Header {
	if f.hdr == nil {
		f.hdr = http.Header{}
	}
	return f.hdr
}
func (f *flushCountingWriter) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *flushCountingWriter) WriteHeader(int)             {}
func (f *flushCountingWriter) Flush()                      { f.flushes++ }

// chunkReader yields its chunks one Read at a time, simulating a slow token/SSE stream where each event arrives
// in its own read well under the response buffer size.
type chunkReader struct {
	chunks [][]byte
	i      int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.i >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.i])
	c.i++
	return n, nil
}

// TestStreamSWGEgressResponseBodyFlushesPerChunk is the regression for the Google AI Mode "something went wrong"
// fix: a slow streaming response must be flushed to the client as each chunk arrives, not buffered until the
// ~4KB response buffer fills (which stalls the stream and makes the page error out).
func TestStreamSWGEgressResponseBodyFlushesPerChunk(t *testing.T) {
	w := &flushCountingWriter{}
	body := &chunkReader{chunks: [][]byte{[]byte("data: a\n\n"), []byte("data: b\n\n"), []byte("data: c\n\n")}}

	if err := streamSWGEgressResponseBody(w, body); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := w.buf.String(); got != "data: a\n\ndata: b\n\ndata: c\n\n" {
		t.Fatalf("relayed body wrong: %q", got)
	}
	if w.flushes < 3 {
		t.Fatalf("expected a flush per streamed chunk (>=3) so a slow stream is not buffered, got %d", w.flushes)
	}
}

// TestSWGEgressResponseShouldStreamIncrementally: unknown-length / SSE responses stream; a fixed Content-Length
// response stays on the buffered (keep-alive) path so we don't force Connection: close on every response.
func TestSWGEgressResponseShouldStreamIncrementally(t *testing.T) {
	cases := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"chunked/unknown-length streams", &http.Response{ContentLength: -1, Header: http.Header{}}, true},
		{"event-stream streams", &http.Response{ContentLength: 100, Header: http.Header{"Content-Type": {"text/event-stream"}}}, true},
		{"fixed-length buffers", &http.Response{ContentLength: 2048, Header: http.Header{"Content-Type": {"text/html"}}}, false},
		{"nil is false", nil, false},
	}
	for _, c := range cases {
		if got := swgEgressResponseShouldStreamIncrementally(c.resp); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

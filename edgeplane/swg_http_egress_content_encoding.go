package edgeplane

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// ReconcileSWGEgressContentEncoding fixes the browser-mimic impedance mismatch documented in
// docs/handoff_edge_browser_mimic_content_encoding_mismatch.md. The egress mimics Chrome UPSTREAM (utls ClientHello
// + Chrome header order) to defeat bot mitigation, so Cloudflare may apply Content-Encoding: br as a "browser"
// optimization keyed on the fingerprint — even when the ACTUAL downstream client never advertised br. The egress
// otherwise passes Content-Encoding through un-decoded (browseregress DisableCompression: true, on the assumption
// the downstream is a browser). A NON-browser client (a Rust reqwest-based client, CLIs, SDKs) then feeds raw brotli to its JSON
// parser and fails ("error decoding response body").
//
// This reconciles the two: when the upstream response carries a Content-Encoding the downstream client did NOT
// accept (per its original Accept-Encoding), decompress the body to identity and strip Content-Encoding +
// Content-Length so the client receives bytes it can read. A client that DID advertise the encoding (every browser
// accepts br) is passed through unchanged — native decode and the current pass-through performance are preserved.
// A single, known encoding is handled; an unknown or stacked encoding is left untouched (never corrupt the body).
func ReconcileSWGEgressContentEncoding(clientReq *http.Request, resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if ce == "" || ce == "identity" {
		return
	}
	if clientAcceptsEncoding(clientReq, ce) {
		return // the client asked for this encoding (e.g. a browser accepting br) — pass through; it decodes natively.
	}
	// The client can't decode what the origin returned. Decompress to identity if we recognize the (single) coding.
	decoded, ok := decodeContentEncoding(ce, resp.Body)
	if !ok {
		// A decoder may consume a header before deciding that it cannot
		// decode. In that case decoded replays the consumed bytes.
		if decoded != nil {
			resp.Body = decoded
		}
		return // unknown/stacked coding we can't safely decode — leave untouched rather than risk corrupting it.
	}
	resp.Body = decoded
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length") // the identity length differs from the compressed length…
	resp.ContentLength = -1           // …and is unknown post-decode → relay as unknown-length (streamed/chunked).
}

// decodedEgressBody closes both the decoder's buffers and the original upstream
// response. A decoder's Close does not in general close its source.
type decodedEgressBody struct {
	io.Reader
	decoder  io.Closer
	upstream io.Closer
	once     sync.Once
	err      error
}

func (b *decodedEgressBody) Close() error {
	b.once.Do(func() {
		if b.decoder != nil {
			b.err = b.decoder.Close()
		}
		if b.upstream != nil {
			b.err = errors.Join(b.err, b.upstream.Close())
		}
	})
	return b.err
}

// headerCaptureReader records only the bytes used to initialize a decoder.
// Recording must stop after successful initialization: the decoder retains
// this reader for the full response stream.
type headerCaptureReader struct {
	source    io.Reader
	consumed  bytes.Buffer
	recording bool
}

func (r *headerCaptureReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if r.recording && n > 0 {
		_, _ = r.consumed.Write(p[:n])
	}
	return n, err
}

func (r *headerCaptureReader) stop() {
	r.recording = false
	r.consumed.Reset()
}

// decoderInit records bytes consumed while checking a coding's header. If
// initialization fails, the returned body replays those bytes unchanged.
func decoderInit(body io.ReadCloser, open func(io.Reader) (io.ReadCloser, error)) (io.ReadCloser, bool) {
	recorder := &headerCaptureReader{source: body, recording: true}
	decoder, err := open(recorder)
	if err != nil {
		return &decodedEgressBody{Reader: io.MultiReader(bytes.NewReader(recorder.consumed.Bytes()), body), upstream: body}, false
	}
	recorder.stop()
	return &decodedEgressBody{Reader: decoder, decoder: decoder, upstream: body}, true
}

// decodeContentEncoding wraps body in a decompressor for one known coding.
// Unknown codings are unchanged; a failed decoder header check is replayable.
func decodeContentEncoding(ce string, body io.ReadCloser) (io.ReadCloser, bool) {
	switch ce {
	case "br":
		return &decodedEgressBody{Reader: brotli.NewReader(body), upstream: body}, true
	case "gzip", "x-gzip":
		return decoderInit(body, func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) })
	case "zstd":
		return decoderInit(body, func(r io.Reader) (io.ReadCloser, error) {
			zr, err := zstd.NewReader(r)
			if err != nil {
				return nil, err
			}
			return zr.IOReadCloser(), nil
		})
	case "deflate":
		// RFC 7230 specifies zlib wrapping, but deployed servers also send
		// raw DEFLATE. Replay every byte consumed by the failed zlib header
		// check before trying raw DEFLATE.
		recorder := &headerCaptureReader{source: body, recording: true}
		zr, err := zlib.NewReader(recorder)
		if err == nil {
			recorder.stop()
			return &decodedEgressBody{Reader: zr, decoder: zr, upstream: body}, true
		}
		fr := flate.NewReader(io.MultiReader(bytes.NewReader(recorder.consumed.Bytes()), body))
		return &decodedEgressBody{Reader: fr, decoder: fr, upstream: body}, true
	}
	return body, false
}

// clientAcceptsEncoding reports whether the intercepted client's original Accept-Encoding permits the coding ce
// (identity is always acceptable). Absent/empty Accept-Encoding means only identity is acceptable (RFC 7231).
// Honors "*" and q=0 ("br;q=0" = not acceptable).
func clientAcceptsEncoding(r *http.Request, ce string) bool {
	ce = strings.ToLower(strings.TrimSpace(ce))
	if ce == "" || ce == "identity" {
		return true
	}
	if r == nil {
		return false
	}
	ae := strings.TrimSpace(r.Header.Get("Accept-Encoding"))
	if ae == "" {
		return false
	}
	starSeen, starOK := false, false
	for _, part := range strings.Split(ae, ",") {
		fields := strings.Split(part, ";")
		token := strings.ToLower(strings.TrimSpace(fields[0]))
		if token == "" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			f = strings.ToLower(strings.TrimSpace(f))
			if strings.HasPrefix(f, "q=") {
				if v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(f, "q=")), 64); err == nil {
					q = v
				}
			}
		}
		if token == ce {
			return q > 0
		}
		if token == "*" {
			starSeen, starOK = true, q > 0
		}
	}
	if starSeen {
		return starOK
	}
	return false
}

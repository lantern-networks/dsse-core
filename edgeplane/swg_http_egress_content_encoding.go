package edgeplane

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"

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
		return // unknown/stacked coding we can't safely decode — leave untouched rather than risk corrupting it.
	}
	resp.Body = decoded
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length") // the identity length differs from the compressed length…
	resp.ContentLength = -1           // …and is unknown post-decode → relay as unknown-length (streamed/chunked).
}

// decodeContentEncoding wraps body in a decompressing reader for a single known Content-Encoding. The returned
// reader reads from body lazily; the caller's existing `defer resp.Body.Close()` still closes the underlying body
// (defer captured the original body value), so no extra Close plumbing is needed. Returns ok=false for an unknown
// or comma-stacked coding.
func decodeContentEncoding(ce string, body io.Reader) (io.ReadCloser, bool) {
	switch ce {
	case "br":
		return io.NopCloser(brotli.NewReader(body)), true
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(body)
		if err != nil {
			return nil, false
		}
		return gr, true
	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, false
		}
		return zr.IOReadCloser(), true
	case "deflate":
		// RFC 7230 says Content-Encoding: deflate is zlib-wrapped; some servers send raw DEFLATE. zlib validates a
		// 2-byte header up front, so try it first and fall back to raw flate only if the header is not zlib.
		if zr, err := zlib.NewReader(body); err == nil {
			return zr, true
		}
		return flate.NewReader(body), true
	}
	return nil, false
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

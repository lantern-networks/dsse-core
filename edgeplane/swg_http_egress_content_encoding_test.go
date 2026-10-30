package edgeplane

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/andybalholm/brotli"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error { b.closed = true; return nil }

func TestReconcileRawAndWrappedDeflate(t *testing.T) {
	const payload = `{"raw":"deflate body"}`
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "zlib", true: "raw"}[raw], func(t *testing.T) {
			var buf bytes.Buffer
			var writer io.WriteCloser
			if raw {
				writer, _ = flate.NewWriter(&buf, flate.DefaultCompression)
			} else {
				writer = zlib.NewWriter(&buf)
			}
			if _, err := writer.Write([]byte(payload)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			resp := makeResp("deflate", buf.Bytes())
			original := &closeTrackingBody{Reader: resp.Body}
			resp.Body = original
			ReconcileSWGEgressContentEncoding(reqWithAE("identity"), resp)
			decoded, err := io.ReadAll(resp.Body)
			if err != nil || string(decoded) != payload {
				t.Fatalf("decoded=%q err=%v", decoded, err)
			}
			if resp.Header.Get("Content-Encoding") != "" {
				t.Fatal("encoding was not stripped")
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !original.closed {
				t.Fatal("decoded body Close did not close upstream response")
			}
		})
	}
}

func TestReconcileFailedDecoderHeaderPreservesAndClosesUpstream(t *testing.T) {
	compressed := []byte("not a gzip stream")
	resp := makeResp("gzip", compressed)
	original := &closeTrackingBody{Reader: resp.Body}
	resp.Body = original
	ReconcileSWGEgressContentEncoding(reqWithAE("identity"), resp)
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("invalid gzip header must not be stripped")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, compressed) {
		t.Fatalf("failed header consumed upstream body: %q %v", got, err)
	}
	if err := resp.Body.Close(); err != nil || !original.closed {
		t.Fatalf("upstream not closed after header failure: %v", err)
	}
}

func TestDecoderHeaderCaptureStopsBeforeStreamingResponse(t *testing.T) {
	// A compressed response much larger than the decoder header must not be
	// copied into the temporary replay buffer after the header is accepted.
	payload := make([]byte, 512*1024)
	var state uint32 = 0x12345678
	for i := range payload {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		payload[i] = byte(state)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var recorder *headerCaptureReader
	decoded, ok := decoderInit(io.NopCloser(bytes.NewReader(compressed.Bytes())), func(r io.Reader) (io.ReadCloser, error) {
		var valid bool
		recorder, valid = r.(*headerCaptureReader)
		if !valid {
			t.Fatalf("decoder source %T does not support stopping header capture", r)
		}
		return gzip.NewReader(r)
	})
	if !ok || recorder == nil {
		t.Fatal("gzip decoder did not initialize")
	}
	if recorder.recording || recorder.consumed.Len() != 0 {
		t.Fatal("header capture was not discarded after initialization")
	}
	got, err := io.ReadAll(decoded)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("streamed response mismatch: bytes=%d err=%v", len(got), err)
	}
	if recorder.consumed.Len() != 0 {
		t.Fatalf("header capture grew during streaming: %d bytes", recorder.consumed.Len())
	}
	if err := decoded.Close(); err != nil {
		t.Fatal(err)
	}
}

func brotliBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write([]byte(s)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func makeResp(ce string, body []byte) *http.Response {
	h := http.Header{}
	if ce != "" {
		h.Set("Content-Encoding", ce)
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func reqWithAE(ae string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://origin.example/", nil)
	r.Header.Del("Accept-Encoding")
	if ae != "" {
		r.Header.Set("Accept-Encoding", ae)
	}
	return r
}

// The core bug: a non-browser client (Accept-Encoding: gzip, no br) gets a br body — reconcile must decompress it
// to identity and strip Content-Encoding / Content-Length.
func TestReconcileDecompressesUnacceptedBrotli(t *testing.T) {
	const payload = `{"issuer":"https://auth.openai.com","token_endpoint":"https://auth.openai.com/oauth/token"}`
	resp := makeResp("br", brotliBytes(t, payload))
	ReconcileSWGEgressContentEncoding(reqWithAE("gzip"), resp)

	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding should be stripped, got %q", got)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length should be stripped, got %q", got)
	}
	if resp.ContentLength != -1 {
		t.Fatalf("ContentLength should be -1 (unknown), got %d", resp.ContentLength)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Fatalf("body not decoded to identity JSON: %q", string(body))
	}
}

// An empty Accept-Encoding means only identity is acceptable → br must be decompressed.
func TestReconcileDecompressesBrotliForEmptyAcceptEncoding(t *testing.T) {
	const payload = `{"ok":true}`
	resp := makeResp("br", brotliBytes(t, payload))
	ReconcileSWGEgressContentEncoding(reqWithAE(""), resp)
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("br must be decompressed when the client sent no Accept-Encoding")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Fatalf("body mismatch: %q", string(body))
	}
}

// A client that DID advertise br (every browser) is passed through unchanged — native decode + perf preserved.
func TestReconcilePassesThroughAcceptedBrotli(t *testing.T) {
	compressed := brotliBytes(t, `{"x":1}`)
	resp := makeResp("br", compressed)
	ReconcileSWGEgressContentEncoding(reqWithAE("gzip, deflate, br, zstd"), resp)
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("br must be passed through when the client accepts it")
	}
	if resp.ContentLength == -1 {
		t.Fatalf("passed-through response must keep its Content-Length framing")
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, compressed) {
		t.Fatalf("passed-through body must be the untouched compressed bytes")
	}
}

// gzip is decompressed for a client that only accepts identity.
func TestReconcileDecompressesUnacceptedGzip(t *testing.T) {
	const payload = `{"g":"z"}`
	resp := makeResp("gzip", gzipBytes(t, payload))
	ReconcileSWGEgressContentEncoding(reqWithAE("identity"), resp)
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("gzip must be decompressed for an identity-only client")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Fatalf("gzip body mismatch: %q", string(body))
	}
}

// An identity / absent Content-Encoding is never touched.
func TestReconcileLeavesIdentityUntouched(t *testing.T) {
	resp := makeResp("", []byte(`{"plain":1}`))
	ReconcileSWGEgressContentEncoding(reqWithAE("gzip"), resp)
	if resp.ContentLength == -1 {
		t.Fatalf("identity response must be left untouched")
	}
}

func TestClientAcceptsEncoding(t *testing.T) {
	cases := []struct {
		ae, ce string
		want   bool
	}{
		{"gzip, deflate, br, zstd", "br", true},
		{"gzip", "br", false},
		{"", "br", false},
		{"", "identity", true},
		{"identity", "br", false},
		{"*", "br", true},
		{"br;q=0", "br", false},
		{"gzip, br;q=0.0", "br", false},
		{"*;q=0", "br", false},
		{"gzip;q=1.0, br;q=0.5", "br", true},
		{"BR", "br", true}, // case-insensitive token
	}
	for _, c := range cases {
		if got := clientAcceptsEncoding(reqWithAE(c.ae), c.ce); got != c.want {
			t.Errorf("clientAcceptsEncoding(AE=%q, ce=%q) = %v, want %v", c.ae, c.ce, got, c.want)
		}
	}
}

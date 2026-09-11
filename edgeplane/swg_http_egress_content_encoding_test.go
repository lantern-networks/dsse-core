package edgeplane

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/andybalholm/brotli"
)

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

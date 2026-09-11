//go:build embedbroker

// These drive the REAL engine in-process. They need libcurl-impersonate and network egress, so they run in the
// cgo build container, not on a dev host — the same place the standalone broker's tests run.
//
// What they are for: the embedded and sidecar builds must be indistinguishable to an origin. A test that only
// proved "a response came back" would pass with any HTTP client, which is exactly the failure the broker
// exists to prevent. So the HTTP test asserts the FINGERPRINT, and the WS test asserts a byte round-trip
// through the buffered duplex rather than merely a successful handshake.

package egressbroker

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// chromeJA4 is the fingerprint the sidecar build produces, recorded from live probes of the running broker.
// The embedded build re-originates through the same engine, so it must produce the same one — if it does not,
// the two hosts are not equivalent and the unification is a lie.
const chromeJA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"

func embeddedTransport(t *testing.T) http.RoundTripper {
	t.Helper()
	rt, err := NewRoundTripperForURL("embedded")
	if err != nil {
		t.Fatalf("NewRoundTripperForURL: %v", err)
	}
	return rt
}

func TestEmbeddedHTTPReOriginatesWithTheChromeFingerprint(t *testing.T) {
	rt := embeddedTransport(t)
	req, err := http.NewRequest(http.MethodGet, "https://tls.browserleaks.com/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "identity") // so the body is readable without decompressing

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var got struct {
		JA4    string `json:"ja4"`
		Akamai string `json:"akamai_hash"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode %q: %v", truncate(string(body), 200), err)
	}
	if got.JA4 != chromeJA4 {
		t.Fatalf("ja4 = %q, want %q — the embedded host does not present the same TLS fingerprint as the sidecar", got.JA4, chromeJA4)
	}
	if got.Akamai == "" {
		t.Fatal("no akamai h2 fingerprint reported — the h2 layer did not negotiate as expected")
	}
	t.Logf("embedded egress: ja4=%s akamai=%s", got.JA4, got.Akamai)
}

// The WS path is where the in-memory duplex earns its keep: the relay is a single loop, so a synchronous pipe
// would stall it. Writing a frame and reading the echo back proves both directions move and nothing deadlocks.
func TestEmbeddedWebSocketRoundTripsThroughTheBufferedDuplex(t *testing.T) {
	rt := embeddedTransport(t)
	req, err := http.NewRequest(http.MethodGet, "https://echo.websocket.org/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("ws RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	tunnel, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("Response.Body is not a duplex — the WS tunnel cannot carry client->origin bytes")
	}

	marker := "embedded-duplex-probe"
	if _, err := tunnel.Write(maskedTextFrame([]byte(marker))); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	buf := make([]byte, 32*1024)
	for time.Now().Before(deadline) {
		n, rerr := tunnel.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), marker) {
			t.Logf("embedded ws: echo received (%d bytes)", n)
			return
		}
		if rerr != nil {
			t.Fatalf("read: %v", rerr)
		}
	}
	t.Fatal("no echo within 20s — the duplex or the relay loop stalled")
}

// maskedTextFrame builds a client->server WS text frame (clients must mask).
func maskedTextFrame(payload []byte) []byte {
	var key [4]byte
	_, _ = rand.Read(key[:])
	frame := []byte{0x81}
	n := len(payload)
	if n < 126 {
		frame = append(frame, byte(n)|0x80)
	} else {
		frame = append(frame, 126|0x80)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		frame = append(frame, ext[:]...)
	}
	frame = append(frame, key[:]...)
	for i, b := range payload {
		frame = append(frame, b^key[i%4])
	}
	return frame
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

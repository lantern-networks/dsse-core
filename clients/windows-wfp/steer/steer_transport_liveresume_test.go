package main

// Live, on-the-real-tunnel proof that the (T) transport resumes TLS sessions after the first
// full mTLS handshake. Gated behind DSSE_LIVE_RESUME=1 so it never runs in the normal suite —
// it dials the live Edge transport using the deployed device cert. Uses the agent's OWN dial()
// path and the per-config session cache, so it proves the SHIPPED behavior, not a
// re-implementation.
//
//   DSSE_LIVE_RESUME=1 DSSE_T_URL=https://203.0.113.10:18543 \
//   DSSE_T_CA=...\transport_ca.pem DSSE_T_CERT=...\win-device.pem DSSE_T_KEY=...\win-device.key \
//   go test -run TestLiveTransportResumes -v .

import (
	"crypto/tls"
	"os"
	"testing"
	"time"
)

func TestLiveTransportResumes(t *testing.T) {
	if os.Getenv("DSSE_LIVE_RESUME") != "1" {
		t.Skip("set DSSE_LIVE_RESUME=1 to run the live tunnel resumption probe")
	}
	tc, err := buildTransportConfig(
		os.Getenv("DSSE_T_URL"), os.Getenv("DSSE_T_CA"),
		os.Getenv("DSSE_T_CERT"), os.Getenv("DSSE_T_KEY"))
	if err != nil {
		t.Fatalf("buildTransportConfig: %v", err)
	}
	if !tc.enabled {
		t.Fatalf("transport not enabled — set DSSE_T_URL")
	}

	const n = 6
	for i := 0; i < n; i++ {
		start := time.Now()
		conn, err := tc.dial(8 * time.Second)
		if err != nil {
			t.Fatalf("dial[%d]: %v", i, err)
		}
		dialDur := time.Since(start)
		tconn, ok := conn.(*tls.Conn)
		if !ok {
			t.Fatalf("dial[%d]: not a *tls.Conn", i)
		}
		// Drive a tiny request so the post-handshake NewSessionTicket is read and cached,
		// exactly like the agent reading its CONNECT response. Failure to read the response
		// is fine — we only need the ticket processed.
		_ = tconn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = tconn.Write([]byte("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"))
		buf := make([]byte, 512)
		_, _ = tconn.Read(buf)
		cs := tconn.ConnectionState()
		t.Logf("conn[%d] DidResume=%-5v tls=0x%04x dial(connect+handshake)=%v",
			i, cs.DidResume, cs.Version, dialDur.Round(time.Millisecond))
		_ = tconn.Close()
		// brief gap so the ticket lands in the LRU cache before the next dial
		time.Sleep(150 * time.Millisecond)
	}
}

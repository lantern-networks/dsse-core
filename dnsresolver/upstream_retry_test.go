package dnsresolver

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// lossyUpstream is a local UDP DNS server that DROPS the first dropFirst datagrams and answers the rest, so a
// lost query can be simulated without any external network.
type lossyUpstream struct {
	conn      *net.UDPConn
	received  atomic.Int64
	dropFirst int64
}

func newLossyUpstream(t *testing.T, dropFirst int64) *lossyUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	u := &lossyUpstream{conn: conn, dropFirst: dropFirst}
	go u.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return u
}

func (u *lossyUpstream) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if u.received.Add(1) <= u.dropFirst {
			continue // simulate a lost datagram: read it and never answer
		}
		reply := append([]byte(nil), buf[:n]...)
		reply[2] |= 0x80 // set QR: this is a response
		_, _ = u.conn.WriteToUDP(reply, addr)
	}
}

func (u *lossyUpstream) addr() string { return u.conn.LocalAddr().String() }

func rawQuery() []byte {
	return []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0x00, 0x01, 0x00, 0x01,
	}
}

// A single lost datagram must NOT become a resolution failure. On this path a failure becomes a 502 to the
// endpoint agent, whose circuit breaker fails OPEN — so one dropped UDP packet would disable enforcement on the
// whole device. Measured in the lab: ~70% of single-shot queries were lost at concurrency 8.
func TestUDPUpstreamRetriesLostDatagram(t *testing.T) {
	upstream := newLossyUpstream(t, 1) // drop exactly the first send
	u := udpUpstreamDNS{addr: upstream.addr(), timeout: 3 * time.Second, attempts: defaultUpstreamAttempts}

	resp, err := u.Resolve(rawQuery())
	if err != nil {
		t.Fatalf("a single lost datagram became a hard failure (would fail-open the device): %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if got := upstream.received.Load(); got != 2 {
		t.Fatalf("upstream saw %d sends, want 2 (the lost one + one retry)", got)
	}
}

// Retries must stay inside the caller's total budget: the endpoint agent has its own client timeout, and
// overrunning it turns a slow answer into the very fail-open the retry exists to prevent.
func TestUDPUpstreamRetriesStayWithinTotalBudget(t *testing.T) {
	upstream := newLossyUpstream(t, 1000) // never answers
	// Wide enough for every attempt: two fast probes (upstreamFastProbeTimeout each) plus a final attempt on
	// the remainder. A budget too small for that would legitimately yield fewer attempts.
	budget := 2*upstreamFastProbeTimeout + 500*time.Millisecond
	u := udpUpstreamDNS{addr: upstream.addr(), timeout: budget, attempts: defaultUpstreamAttempts}

	start := time.Now()
	if _, err := u.Resolve(rawQuery()); err == nil {
		t.Fatal("expected a failure from an upstream that never answers")
	}
	elapsed := time.Since(start)
	if elapsed > budget+300*time.Millisecond {
		t.Fatalf("Resolve took %s, want <= the %s budget — retries must not extend it", elapsed, budget)
	}
	if got := upstream.received.Load(); got != int64(defaultUpstreamAttempts) {
		t.Fatalf("upstream saw %d sends, want %d attempts", got, defaultUpstreamAttempts)
	}
}

// A non-timeout error (nothing listening) will fail identically on every retry, so it must fail fast rather
// than burn the whole budget re-sending.
func TestUDPUpstreamDoesNotRetryHardErrors(t *testing.T) {
	// Bind then close, so the port is almost certainly refused rather than silently dropped.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	u := udpUpstreamDNS{addr: addr, timeout: 3 * time.Second, attempts: defaultUpstreamAttempts}
	start := time.Now()
	_, err = u.Resolve(rawQuery())
	if err == nil {
		t.Skip("the closed port answered; this platform does not send ICMP unreachable")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Skip("the closed port silently dropped the datagram; no hard error to assert on")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a hard error took %s to surface — it was retried instead of failing fast", elapsed)
	}
}

// slowUpstream answers, but only after a delay — a resolver that is slow yet perfectly alive.
type slowUpstream struct {
	conn  *net.UDPConn
	delay time.Duration
}

func newSlowUpstream(t *testing.T, delay time.Duration) *slowUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	u := &slowUpstream{conn: conn, delay: delay}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte(nil), buf[:n]...)
			reply[2] |= 0x80
			go func() {
				time.Sleep(u.delay)
				_, _ = conn.WriteToUDP(reply, addr)
			}()
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return u
}

// A slow-but-alive upstream must still be answered. Splitting the budget evenly across attempts caps every
// attempt at budget/attempts, so a resolver that reliably answers in (say) 1.5s is cut off at ~1.3s on a 4s
// budget and every retry repeats the mistake — the retry then CAUSES the failure it exists to prevent. Only
// the early probes are short; the LAST attempt gets whatever budget remains.
func TestUDPUpstreamAnswersSlowButAliveUpstream(t *testing.T) {
	const delay = 1500 * time.Millisecond // longer than upstreamFastProbeTimeout, well inside the budget
	upstream := newSlowUpstream(t, delay)
	u := udpUpstreamDNS{addr: upstream.conn.LocalAddr().String(), timeout: 4 * time.Second, attempts: defaultUpstreamAttempts}

	start := time.Now()
	resp, err := u.Resolve(rawQuery())
	if err != nil {
		t.Fatalf("a slow-but-alive upstream (%s, budget 4s) was not answered — the retry truncated it: %v", delay, err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Resolve took %s, beyond the 4s budget", elapsed)
	}
}

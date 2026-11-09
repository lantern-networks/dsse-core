package edgeplane

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Review R3 (2026-11-07). Dialling the vetted addresses one after another lost what net.Dialer gives a name
// with several answers: an IPv6 route that never answers must not hold a working IPv4 answer back for the
// whole of its timeout. The attempts now overlap, 300 ms apart, and the first to connect wins.
func TestADeadRouteInOneFamilyDoesNotHoldTheOtherBack(t *testing.T) {
	withGuard(t, false)
	withIPv6Egress(t, true)
	ln, _ := listenerThatCountsAccepts(t)
	port := ln.Addr().(*net.TCPAddr).Port
	resolver := &answeringResolver{answers: [][]net.IPAddr{{
		{IP: net.ParseIP("2001:db8::1")}, // the AAAA, which will hang
		{IP: net.IPv4(127, 0, 0, 1)},     // the A, which answers
	}}}
	withResolver(t, resolver)

	previous := vettedDial
	var hung atomic.Int32
	vettedDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[2001:db8::1]") {
			hung.Add(1)
			<-ctx.Done() // a route that never answers
			return nil, ctx.Err()
		}
		return previous(ctx, network, address)
	}
	t.Cleanup(func() { vettedDial = previous })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	began := time.Now()
	conn, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(ctx,
		NetworkExtensionRuntimeCopyTCPRoute{Host: "dual-stack.test", Port: port})
	took := time.Since(began)
	if err != nil {
		t.Fatalf("the IPv4 answer was never reached: %v", err)
	}
	conn.Close()
	if hung.Load() != 1 {
		t.Fatalf("the IPv6 answer was tried %d times, want 1", hung.Load())
	}
	if took > 1500*time.Millisecond {
		t.Fatalf("the working IPv4 route waited %s behind the dead IPv6 one; the attempts must overlap", took)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("the name was resolved %d times", resolver.calls.Load())
	}
}

func TestEveryVettedAddressRefusingIsReportedAsTheLastRefusal(t *testing.T) {
	withGuard(t, false)
	resolver := &answeringResolver{answers: [][]net.IPAddr{{{IP: net.IPv4(127, 0, 0, 1)}, {IP: net.IPv4(127, 0, 0, 2)}}}}
	withResolver(t, resolver)
	previous := vettedDial
	vettedDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("refused " + address)
	}
	t.Cleanup(func() { vettedDial = previous })
	_, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(context.Background(),
		NetworkExtensionRuntimeCopyTCPRoute{Host: "all-refuse.test", Port: 443})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("expected the refusal to be reported: %v", err)
	}
}

func TestInterleaveByFamilyAlternatesWithIPv6First(t *testing.T) {
	got := interleaveByFamily([]net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2), net.ParseIP("2001:db8::a"), net.ParseIP("2001:db8::b")})
	want := []string{"2001:db8::a", "1.1.1.1", "2001:db8::b", "2.2.2.2"}
	for i, ip := range got {
		if ip.String() != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

// closeCountingConn records whether the race closed it.
type closeCountingConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *closeCountingConn) Close() error { c.closed.Add(1); return c.Conn.Close() }

// Re-review RR4: an attempt that connects after the race was decided belongs to nobody unless the race
// closes it. Two answers connect almost together; the loser is closed. A caller that gave up before either
// answered gets neither, and both are closed.
func TestAConnectionTheRaceDidNotAdoptIsClosed(t *testing.T) {
	withGuard(t, false)
	withIPv6Egress(t, true)
	resolver := &answeringResolver{answers: [][]net.IPAddr{{{IP: net.ParseIP("2001:db8::1")}, {IP: net.IPv4(127, 0, 0, 1)}}}}
	withResolver(t, resolver)
	previous := vettedDial
	conns := make(chan *closeCountingConn, 4)
	release := make(chan struct{})
	vettedDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _ = b }()
		c := &closeCountingConn{Conn: a}
		conns <- c
		if strings.HasPrefix(address, "[2001:db8::1]") {
			// The IPv6 answer connects, but only after the caller has chosen (or given up).
			<-release
		}
		return c, nil
	}
	t.Cleanup(func() { vettedDial = previous })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	winner, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(ctx,
		NetworkExtensionRuntimeCopyTCPRoute{Host: "late-answer.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	close(release) // the IPv6 attempt now connects, after the decision
	first, second := receiveConn(t, conns, "first"), receiveConn(t, conns, "second")
	loser := first
	if winner == net.Conn(first) || (winner != nil && winnerIs(winner, first)) {
		loser = second
	}
	deadline := time.Now().Add(2 * time.Second)
	for loser.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if loser.closed.Load() == 0 {
		t.Fatal("the connection the race did not adopt was never closed")
	}
	winner.Close()

	// A caller that gives up before any answer: both late answers are closed.
	release2 := make(chan struct{})
	conns2 := make(chan *closeCountingConn, 4)
	vettedDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		<-release2
		a, _ := net.Pipe()
		c := &closeCountingConn{Conn: a}
		conns2 <- c
		return c, nil
	}
	// Long enough for both attempts to start (they are 300 ms apart), short enough that neither answers.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel2()
	if _, err := (NetworkExtensionRuntimeCopyNetDialer{}).OpenTCPConnection(ctx2,
		NetworkExtensionRuntimeCopyTCPRoute{Host: "late-answer.test", Port: 443}); err == nil {
		t.Fatal("a caller that gave up was handed a connection")
	}
	close(release2)
	for i := 0; i < 2; i++ {
		var c *closeCountingConn
		select {
		case c = <-conns2:
		case <-time.After(2 * time.Second):
			t.Fatalf("late answer %d never connected", i+1)
		}
		deadline := time.Now().Add(2 * time.Second)
		for c.closed.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if c.closed.Load() == 0 {
			t.Fatalf("late answer %d after the caller gave up was never closed", i+1)
		}
	}
}

// withIPv6Egress fixes, for one test, whether this Edge believes it can egress IPv6. The dialler skips IPv6
// answers on a node without IPv6 egress, so a test about the IPv6 answer must not depend on whether the machine
// running it reaches the internet over IPv6 (a hosted CI runner does not).
func withIPv6Egress(t *testing.T, can bool) {
	t.Helper()
	before := edgeIPv6EgressMeasured.Load()
	SetMeasuredIPv6Egress(can)
	t.Cleanup(func() { edgeIPv6EgressMeasured.Store(before) })
}

// receiveConn waits a bounded time for a dial attempt, so a missing attempt fails the test instead of hanging it.
func receiveConn(t *testing.T, conns <-chan *closeCountingConn, which string) *closeCountingConn {
	t.Helper()
	select {
	case c := <-conns:
		return c
	case <-time.After(3 * time.Second):
		t.Fatalf("the %s dial attempt never happened", which)
		return nil
	}
}

func winnerIs(winner io.ReadWriteCloser, c *closeCountingConn) bool {
	w, ok := winner.(*closeCountingConn)
	return ok && w == c
}

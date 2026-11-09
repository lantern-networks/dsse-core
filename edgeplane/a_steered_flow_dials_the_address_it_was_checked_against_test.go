package edgeplane

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	swg "github.com/lantern-networks/dsse-core/swg"
)

// ★★★ THE GUARD LOOKED AT ONE ADDRESS AND THE SOCKET CONNECTED TO ANOTHER (2026-11-07, security review S2).
//
// The steer dialer checked a name with the SSRF guard and then handed the NAME to net.Dialer, which resolved
// it again. A resolver under the device user's control answers a public address the first time and the
// node's own network the second, and the check has measured nothing. These tests stand in a resolver whose
// answers change between calls and show that the dialer asks it once and connects to what it was told.

type answeringResolver struct {
	calls   atomic.Int32
	answers [][]net.IPAddr
}

func (r *answeringResolver) lookup(context.Context, string) ([]net.IPAddr, error) {
	n := int(r.calls.Add(1)) - 1
	if n >= len(r.answers) {
		n = len(r.answers) - 1
	}
	return r.answers[n], nil
}

func withResolver(t *testing.T, r *answeringResolver) {
	t.Helper()
	previous := swg.LookupIPAddr
	swg.LookupIPAddr = r.lookup
	t.Cleanup(func() { swg.LookupIPAddr = previous })
}

func withGuard(t *testing.T, on bool) {
	t.Helper()
	wasOn := swg.CheckEgressDestination(context.Background(), "169.254.169.254") != nil
	swg.SetInternalBlockEnabled(on)
	t.Cleanup(func() { swg.SetInternalBlockEnabled(wasOn) })
}

func listenerThatCountsAccepts(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	return ln, &accepted
}

func TestTheSteerDialerConnectsToTheAddressTheGuardVetted(t *testing.T) {
	withGuard(t, false) // the lab setting: loopback is allowed, so the vetted address is the listener's
	ln, accepted := listenerThatCountsAccepts(t)
	port := ln.Addr().(*net.TCPAddr).Port
	resolver := &answeringResolver{answers: [][]net.IPAddr{{{IP: net.IPv4(127, 0, 0, 1)}}}}
	withResolver(t, resolver)

	conn, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(context.Background(),
		NetworkExtensionRuntimeCopyTCPRoute{Host: "answers-change.test", Port: port})
	if err != nil {
		t.Fatalf("dial through the vetted address: %v", err)
	}
	conn.Close()
	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("the name was resolved %d times; the check and the dial must be one lookup", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for accepted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if accepted.Load() != 1 {
		t.Fatalf("the listener at the vetted address accepted %d connections, want 1", accepted.Load())
	}
}

func TestARebindingResolverCannotMoveTheSocketAfterTheCheck(t *testing.T) {
	withGuard(t, true)
	ln, accepted := listenerThatCountsAccepts(t)
	port := ln.Addr().(*net.TCPAddr).Port
	// First answer: a public address (TEST-NET-3, which goes nowhere). Second answer, were anybody to ask:
	// the node's loopback, where the listener is.
	resolver := &answeringResolver{answers: [][]net.IPAddr{
		{{IP: net.IPv4(203, 0, 113, 9)}},
		{{IP: net.IPv4(127, 0, 0, 1)}},
	}}
	withResolver(t, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	conn, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(ctx,
		NetworkExtensionRuntimeCopyTCPRoute{Host: "rebinding.test", Port: port})
	if err == nil {
		conn.Close()
		t.Fatal("a flow whose name was vetted as public was connected somewhere; the second answer was used")
	}
	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("the name was resolved %d times; a second lookup is the rebinding window", got)
	}
	if accepted.Load() != 0 {
		t.Fatalf("the listener on the node's loopback accepted %d connections from a flow vetted as public", accepted.Load())
	}
}

func TestANameThatResolvesInternallyIsRefusedBeforeAnySocket(t *testing.T) {
	withGuard(t, true)
	resolver := &answeringResolver{answers: [][]net.IPAddr{{{IP: net.IPv4(169, 254, 169, 254)}}}}
	withResolver(t, resolver)
	_, err := NetworkExtensionRuntimeCopyNetDialer{}.OpenTCPConnection(context.Background(),
		NetworkExtensionRuntimeCopyTCPRoute{Host: "metadata-by-name.test", Port: 80})
	if err == nil || !strings.Contains(err.Error(), "refused before it was dialled") {
		t.Fatalf("a name resolving to the metadata service was not refused before dialling: %v", err)
	}
}

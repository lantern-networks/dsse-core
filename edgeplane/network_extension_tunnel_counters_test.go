package edgeplane

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// ★★ A COUNTER ON ONE ENTRY POINT OF THREE READS ZERO AND LOOKS LIKE PEACE (2026-08-18).
//
// The first version of these counters sat in the runtime-copy HTTP handler. steer.go bridges directly for both
// the ordinary and the interactive case, so two of the three paths were uncounted. The declared-posture check
// caught it within the hour: reaped_idle_total read 8 while started_total read 0. That is not a ratio, it is a
// counter that is not wired — the exact failure the posture file exists to prevent, a zero passing as "nothing
// happened" when it means "not measured".
//
// This exercises the bridge itself, which is where every path converges.
func TestEveryBridgedTunnelIsCounted(t *testing.T) {
	before, beforeDone, _ := NetworkExtensionTunnelCounts()

	// Two ends of a pipe, closed immediately: the bridge sees EOF both ways and returns.
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	go func() { _ = a2.Close() }()
	go func() { _ = b2.Close() }()
	BridgeNetworkExtensionRuntimeCopyTunnel(context.Background(), a1, b1)

	after, afterDone, _ := NetworkExtensionTunnelCounts()
	if after != before+1 {
		t.Fatalf("started moved by %d, want 1 — a bridged tunnel was not counted", after-before)
	}
	if afterDone != beforeDone+1 {
		t.Fatalf("completed moved by %d, want 1 — started minus completed is the live population and it "+
			"would drift upward forever", afterDone-beforeDone)
	}

	// ★ The interactive path (unlimited full-duplex idle) is a SEPARATE exported entry point, and it is the
	// one steer.go uses for east-west. Counting only the ordinary bridge is how this broke the first time.
	c1, c2 := net.Pipe()
	d1, d2 := net.Pipe()
	go func() { _ = c2.Close() }()
	go func() { _ = d2.Close() }()
	BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(context.Background(), c1, d1, 0, 50*time.Millisecond)

	final, finalDone, _ := NetworkExtensionTunnelCounts()
	if final != after+1 || finalDone != afterDone+1 {
		t.Fatalf("the interactive bridge counted %d started / %d completed, want one of each",
			final-after, finalDone-afterDone)
	}
}

// ★ AND THE CONTROL: the counter must not move for things that are not tunnels, or "started" stops meaning
// anything and the ratio the posture check reads becomes noise.
func TestTheTunnelCounterDoesNotMoveWithoutABridge(t *testing.T) {
	before, _, _ := NetworkExtensionTunnelCounts()
	var sink io.Writer = io.Discard
	_, _ = sink.Write([]byte("not a tunnel"))
	if after, _, _ := NetworkExtensionTunnelCounts(); after != before {
		t.Fatalf("the started counter moved by %d without a bridge", after-before)
	}
}

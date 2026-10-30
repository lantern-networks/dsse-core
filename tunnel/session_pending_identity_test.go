package tunnel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRoundTripRejectsDuplicatePendingRequestID(t *testing.T) {
	transport := newFakeFrameTransport()
	session := &Session{
		TunnelID:       "tun_pending_identity",
		conn:           transport,
		pending:        map[string]chan Frame{},
		requestTimeout: time.Second,
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		_, err := session.RoundTrip(firstCtx, Frame{Type: FrameProbeRequest, RequestID: "same-id"})
		firstDone <- err
	}()
	transport.waitForWrite(t)

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelSecond()
	_, err := session.RoundTrip(secondCtx, Frame{Type: FrameProbeRequest, RequestID: "same-id"})
	if err == nil || !strings.Contains(err.Error(), "already pending") {
		t.Fatalf("duplicate request error = %v, want immediate duplicate refusal", err)
	}
	select {
	case <-transport.writes:
		t.Fatal("duplicate request was written to the tunnel")
	default:
	}
	cancelFirst()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first request remained pending after cancellation")
	}
}

func TestOldPendingCleanupCannotRemoveReplacement(t *testing.T) {
	old := make(chan Frame, 1)
	replacement := make(chan Frame, 1)
	session := &Session{pending: map[string]chan Frame{"reused": replacement}}
	session.deletePending("reused", old)
	session.deliver(Frame{Type: FrameProbeResult, RequestID: "reused"})
	select {
	case frame := <-replacement:
		if frame.Type != FrameProbeResult {
			t.Fatalf("delivered frame type = %q", frame.Type)
		}
	default:
		t.Fatal("stale cleanup removed the replacement pending request")
	}
}

package tunnel

import (
	"testing"
	"time"
)

func TestUnconfiguredStreamByteAndTimeQuotasAreDisabled(t *testing.T) {
	now := time.Now()
	registry := NewTCPConnectionRegistry()
	frame := validTCPOpenFrame()
	frame.ByteCap = 0
	frame.IdleTimeoutMillis = 0
	frame.MaxConnectionLifetimeMillis = 0
	if err := registry.Open(frame, now); err != nil {
		t.Fatal(err)
	}
	// Accounting regression, not a network throughput measurement: cross the
	// previous 1 GiB boundary without allocating or transmitting a GiB fixture.
	registry.connections[frame.RequestID].bytesUp = 2 << 30
	data, err := NewTCPDataFrame(frame.RequestID, TCPDirectionDown, []byte("still live"))
	if err != nil {
		t.Fatal(err)
	}
	if _, closed, err := registry.RecordData(data, now.Add(24*time.Hour)); err != nil || closed {
		t.Fatalf("unconfigured byte/time quota cut stream: %v", err)
	}
	if closed := registry.CloseExpired(now.Add(48 * time.Hour)); len(closed) != 0 {
		t.Fatal("unconfigured lifetime or idle quota reaped a stream")
	}
	bounded := frame
	bounded.RequestID = "operator-bounded"
	bounded.ByteCap = 8 << 30
	bounded.MaxConnectionLifetimeMillis = int((24 * time.Hour) / time.Millisecond)
	bounded.IdleTimeoutMillis = int((2 * time.Hour) / time.Millisecond)
	if err := registry.Open(bounded, now); err != nil {
		t.Fatalf("operator budget was clamped to old bounds: %v", err)
	}
	registry.connections[bounded.RequestID].bytesUp = 8 << 30
	data.RequestID = bounded.RequestID
	if _, closed, err := registry.RecordData(data, now); err != nil || !closed {
		t.Fatal("explicit byte quota was not enforced")
	}
}

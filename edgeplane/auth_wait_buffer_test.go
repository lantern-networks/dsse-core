package edgeplane

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestAuthWaitBufferBoundAndResume(t *testing.T) {
	h := NewBufferedPipeHalf(muxVirtualConnCap)
	if !h.setAuthLimit(16*1024, true) {
		t.Fatal("cannot begin wait")
	}
	payload := bytes.Repeat([]byte{7}, 16*1024)
	if n, err := h.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	if cap(h.buf) > 16*1024 {
		t.Fatal("allocation exceeds auth budget")
	}
	if !h.setAuthLimit(muxVirtualConnCap, false) {
		t.Fatal("cannot resume")
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(h, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatal("held data corrupted")
	}
}

func TestAuthWaitOverflowDoesNotBlockSharedReader(t *testing.T) {
	h := NewBufferedPipeHalf(muxVirtualConnCap)
	if !h.setAuthLimit(16*1024, true) {
		t.Fatal("begin")
	}
	done := make(chan error, 1)
	go func() { _, err := h.Write(make([]byte, 16*1024+1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("overflow accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("held flow blocked demultiplexer")
	}
	if h.setAuthLimit(muxVirtualConnCap, false) {
		t.Fatal("overflow flow resumed")
	}
	if len(h.buf) != 0 {
		t.Fatal("denied data retained")
	}
}

func TestAuthWaitRejectsDataAlreadyAboveBudget(t *testing.T) {
	h := NewBufferedPipeHalf(muxVirtualConnCap)
	_, _ = h.Write(make([]byte, 16*1024+1))
	if h.setAuthLimit(16*1024, true) {
		t.Fatal("pre-existing data evaded budget")
	}
	if len(h.buf) != 0 {
		t.Fatal("denied data retained")
	}
}

// Exercise actual wire dispatch: overflow must send CLOSE and must not stall
// the next flow while the peer has not yet read the rejection.
func TestAuthWaitOverflowSendsCloseAndKeepsOtherFlow(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	mux := NewSteerMux(server)
	ready := make(chan struct{})
	other := make(chan string, 1)
	go mux.Run(func(id uint32, dst string, vc *MuxVirtualConn) {
		if id == 1 {
			if !vc.BeginAuthWait() {
				return
			}
			close(ready)
			<-vc.Closed()
			vc.Close() // must not suppress or duplicate the queued rejection
			return
		}
		data := make([]byte, 2)
		if _, err := io.ReadFull(vc, data); err == nil {
			other <- string(data)
		}
	})
	frame := func(id uint32, kind byte, data []byte) {
		t.Helper()
		raw := make([]byte, 9+len(data))
		binary.BigEndian.PutUint32(raw, id)
		raw[4] = kind
		binary.BigEndian.PutUint32(raw[5:], uint32(len(data)))
		copy(raw[9:], data)
		if _, err := client.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	frame(1, muxFrameOpen, []byte("held:22"))
	<-ready
	frame(1, muxFrameData, make([]byte, 16*1024+1))
	frame(2, muxFrameOpen, []byte("other:22"))
	frame(2, muxFrameData, []byte("ok"))
	select {
	case got := <-other:
		if got != "ok" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("other flow stalled")
	}
	header := make([]byte, 9)
	if _, err := io.ReadFull(client, header); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(header) != 1 || header[4] != muxFrameClose || binary.BigEndian.Uint32(header[5:]) != 0 {
		t.Fatalf("wrong CLOSE header: %v", header)
	}
}

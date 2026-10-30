package edgeplane

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestSteerMuxDuplicateOpenTearsDownOriginalFlow(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	first := make(chan *MuxVirtualConn, 1)
	runDone := make(chan struct{})
	go func() {
		NewSteerMux(server).Run(func(_ uint32, _ string, vc *MuxVirtualConn) { first <- vc })
		close(runDone)
	}()
	writeOpen := func() {
		t.Helper()
		payload := []byte("service.example:443")
		hdr := make([]byte, muxHeaderLen)
		binary.BigEndian.PutUint32(hdr[0:4], 7)
		hdr[4] = muxFrameOpen
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
		if _, err := client.Write(append(hdr, payload...)); err != nil {
			t.Fatal(err)
		}
	}
	writeOpen()
	var vc *MuxVirtualConn
	select {
	case vc = <-first:
	case <-time.After(time.Second):
		t.Fatal("first OPEN was not handled")
	}
	writeOpen()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		_ = client.Close()
		<-runDone
		t.Fatal("duplicate OPEN did not terminate malformed mux")
	}
	select {
	case <-vc.Closed():
	default:
		t.Fatal("original flow remained open after duplicate OPEN")
	}
}

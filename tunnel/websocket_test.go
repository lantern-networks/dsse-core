package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestWebSocketJSONRoundTrip(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverDone := make(chan error, 1)
	go func() {
		var frame Frame
		if err := serverConn.ReadJSON(&frame); err != nil {
			serverDone <- err
			return
		}
		frame.Type = FrameHTTPResponse
		frame.StatusCode = http.StatusOK
		serverDone <- serverConn.WriteJSON(frame)
	}()

	if err := clientConn.WriteJSON(Frame{Type: FrameHTTPRequest, RequestID: "req_test_001", Path: "/private-app/dummy"}); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	var response Frame
	if err := clientConn.ReadJSON(&response); err != nil {
		t.Fatalf("ReadJSON returned error: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
	if response.RequestID != "req_test_001" {
		t.Fatalf("request_id = %q, want req_test_001", response.RequestID)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status_code = %d, want %d", response.StatusCode, http.StatusOK)
	}
}

func TestWebSocketReadFrameRejectsOversizedPayload(t *testing.T) {
	var frame bytes.Buffer
	frame.WriteByte(0x81)
	frame.WriteByte(127)
	var extended [8]byte
	binary.BigEndian.PutUint64(extended[:], uint64(maxWebSocketFramePayloadBytes+1))
	frame.Write(extended[:])

	conn := &Conn{reader: bufio.NewReader(&frame)}
	_, _, err := conn.readFrame()
	if err == nil {
		t.Fatal("readFrame returned nil, want oversized payload error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("error = %q", err.Error())
	}
}

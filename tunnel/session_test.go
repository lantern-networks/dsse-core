package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerMarksReconnect(t *testing.T) {
	manager := NewManager()
	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	defer firstServer.Close()
	firstConn := &Conn{conn: firstClient, reader: bufio.NewReader(firstClient), maskWrites: true}

	_, reconnect := manager.Register("conn_lab_001", "tun_lab_001", firstConn)
	if reconnect {
		t.Fatal("first Register returned reconnect=true")
	}
	manager.Unregister("conn_lab_001", "tun_lab_001")

	secondClient, secondServer := net.Pipe()
	defer secondClient.Close()
	defer secondServer.Close()
	secondConn := &Conn{conn: secondClient, reader: bufio.NewReader(secondClient), maskWrites: true}
	_, reconnect = manager.Register("conn_lab_001", "tun_lab_002", secondConn)
	if !reconnect {
		t.Fatal("second Register returned reconnect=false")
	}
}

func TestManagerRegisterAcceptsFrameTransportWithoutWebSocketConn(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	transport := newFakeFrameTransport()
	session, reconnect := manager.Register("conn_lab_fake_transport", "tun_lab_fake_transport", transport)
	if reconnect {
		t.Fatal("Register returned reconnect=true for first fake transport session")
	}

	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	serverDone := make(chan error, 1)
	go func() {
		frame := transport.waitForWrite(t)
		if frame.Type != FrameHTTPRequest || frame.RequestID != "req_fake_transport_001" || frame.TunnelID != "tun_lab_fake_transport" {
			serverDone <- fmt.Errorf("written frame = %+v", frame)
			return
		}
		transport.reads <- Frame{Type: FrameHTTPResponse, RequestID: frame.RequestID, StatusCode: 204}
		serverDone <- nil
	}()

	response, err := session.RoundTrip(context.Background(), Frame{
		Type:      FrameHTTPRequest,
		RequestID: "req_fake_transport_001",
		Path:      "/private-app/dummy",
	})
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if response.StatusCode != 204 {
		t.Fatalf("response status = %d, want 204", response.StatusCode)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("fake transport exchange returned error: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Session Close returned error: %v", err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Session Run returned error after fake transport close: %v", err)
	}
	if !transport.Closed() {
		t.Fatal("fake transport was not closed")
	}
}

// Review #21: deliver() must be a NON-BLOCKING send. The pending response channel is buffer-1; a duplicate
// response frame for the same request_id finds the buffer full, and a blocking send there wedges the single
// Session.Run reader goroutine forever whenever the RoundTrip has already abandoned the channel (exited via
// timeout/ctx without draining) — stalling every other request on the session. This white-box test wires up
// exactly that state (a pending entry whose buffer is full and whose reader is gone) and asserts deliver()
// of a duplicate returns promptly and clears the entry instead of blocking.
func TestSessionDeliverDuplicateDoesNotBlock(t *testing.T) {
	s := &Session{pending: map[string]chan Frame{}, streams: map[string]chan Frame{}}
	ch := make(chan Frame, 1)
	s.pending["req_dup"] = ch
	ch <- Frame{Type: FrameHTTPResponse, RequestID: "req_dup", StatusCode: 200} // buffer now full; no reader

	done := make(chan struct{})
	go func() {
		s.deliver(Frame{Type: FrameHTTPResponse, RequestID: "req_dup", StatusCode: 200}) // duplicate
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deliver() blocked on a full pending buffer — Session.Run would be wedged")
	}
	// The full-buffer path drops the entry (fail-closed), mirroring deliverTCPStream.
	s.mu.Lock()
	_, stillPending := s.pending["req_dup"]
	s.mu.Unlock()
	if stillPending {
		t.Fatal("deliver() should drop the pending entry when its buffer is full")
	}
}

// failPending must likewise never block on a full pending buffer or a stream whose consumer stopped reading,
// so a session teardown always completes.
func TestSessionFailPendingDoesNotBlock(t *testing.T) {
	s := &Session{pending: map[string]chan Frame{}, streams: map[string]chan Frame{}}
	pendingCh := make(chan Frame, 1)
	pendingCh <- Frame{} // full
	s.pending["req_x"] = pendingCh
	streamCh := make(chan Frame, 1)
	streamCh <- Frame{} // full
	s.streams["req_y"] = streamCh

	done := make(chan struct{})
	go func() {
		s.failPending(errors.New("session torn down"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("failPending() blocked on a full buffer — session teardown would hang")
	}
}

func TestManagerSessionStateSnapshotUsesStableAffinityHashAndCurrentProtocol(t *testing.T) {
	manager := NewManager()
	firstTransport := newFakeFrameTransport()
	secondTransport := newFakeFrameTransport()
	defer firstTransport.Close()
	defer secondTransport.Close()

	first, _ := manager.Register("conn_lab_b", "tun_lab_b", firstTransport)
	second, _ := manager.RegisterWithTransportProtocol("conn_lab_a", "tun_lab_a", secondTransport, WebSocketTextJSONTransportProtocol)

	firstRecord, err := first.StateRecord()
	if err != nil {
		t.Fatalf("first StateRecord returned error: %v", err)
	}
	secondRecord, err := second.StateRecord()
	if err != nil {
		t.Fatalf("second StateRecord returned error: %v", err)
	}
	firstKey, err := SessionAffinityKey("conn_lab_b")
	if err != nil {
		t.Fatalf("SessionAffinityKey returned error: %v", err)
	}
	if firstRecord.AffinityKey != firstKey {
		t.Fatalf("first affinity key = %q, want %q", firstRecord.AffinityKey, firstKey)
	}
	if firstRecord.AffinityKey == firstRecord.ConnectorID || firstRecord.RawConnectorIdentifierInKey {
		t.Fatalf("affinity key exposed raw connector id: %+v", firstRecord)
	}
	if secondRecord.TransportProtocol != WebSocketTextJSONTransportProtocol {
		t.Fatalf("transport protocol = %q, want %q", secondRecord.TransportProtocol, WebSocketTextJSONTransportProtocol)
	}
	if !secondRecord.SessionAffinityRequired || secondRecord.ExternalRegistryRequired || secondRecord.MultiEdgeStatelessClaimed || secondRecord.ProductionScaleClaimed {
		t.Fatalf("scale claim gates are wrong: %+v", secondRecord)
	}
	if secondRecord.StateScope != SessionStateScopeEdgeLocalAffinity ||
		secondRecord.AffinityStrategy != SessionAffinityStrategyConnectorIDHash ||
		secondRecord.ExternalRegistryGate != SessionExternalRegistryGateNotRequired ||
		secondRecord.MigratableWithoutReconnect != SessionMigratableWithoutReconnectNo ||
		secondRecord.ProductionScaleClaim != SessionProductionScaleClaimNotPerformed ||
		!secondRecord.NoSecretAttestation {
		t.Fatalf("session state record gates are wrong: %+v", secondRecord)
	}

	snapshot := manager.SessionStateSnapshot()
	if len(snapshot) != 2 {
		t.Fatalf("snapshot length = %d, want 2", len(snapshot))
	}
	if snapshot[0].ConnectorID != "conn_lab_a" || snapshot[1].ConnectorID != "conn_lab_b" {
		t.Fatalf("snapshot order = %+v, want connector id order", snapshot)
	}
}

func TestSessionRoundTripTimesOut(t *testing.T) {
	manager := NewManagerWithRequestTimeout(10 * time.Millisecond)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}

	readDone := make(chan error, 1)
	go func() {
		var frame Frame
		readDone <- serverConn.ReadJSON(&frame)
	}()

	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	_, err := session.RoundTrip(context.Background(), Frame{
		Type:      FrameHTTPRequest,
		RequestID: "req_timeout_001",
		Path:      "/private-app/dummy",
	})
	if err == nil {
		t.Fatal("RoundTrip returned nil error, want timeout")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("RoundTrip error = %q, want timed out", err.Error())
	}
	if err := <-readDone; err != nil {
		t.Fatalf("server ReadJSON returned error: %v", err)
	}
}

func TestSessionRunDeliversTCPStreamFramesSeparatelyFromHTTPRoundTrip(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	streamCh, cleanup, err := session.RegisterTCPStream("req_tcp_001")
	if err != nil {
		t.Fatalf("RegisterTCPStream returned error: %v", err)
	}
	defer cleanup()

	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	if err := serverConn.WriteJSON(Frame{Type: FrameTCPData, RequestID: "req_tcp_001", Direction: TCPDirectionUp, Data: base64.StdEncoding.EncodeToString([]byte("hello"))}); err != nil {
		t.Fatalf("server WriteJSON tcp_data returned error: %v", err)
	}
	select {
	case frame := <-streamCh:
		if frame.Type != FrameTCPData || frame.RequestID != "req_tcp_001" {
			t.Fatalf("stream frame = %+v, want tcp_data req_tcp_001", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tcp stream frame")
	}

	serverHTTPDone := make(chan error, 1)
	go func() {
		var frame Frame
		if err := serverConn.ReadJSON(&frame); err != nil {
			serverHTTPDone <- err
			return
		}
		if frame.Type != FrameHTTPRequest || frame.RequestID != "req_http_001" {
			serverHTTPDone <- fmt.Errorf("http frame = %+v", frame)
			return
		}
		serverHTTPDone <- serverConn.WriteJSON(Frame{Type: FrameHTTPResponse, RequestID: frame.RequestID, StatusCode: 200})
	}()
	response, err := session.RoundTrip(context.Background(), Frame{Type: FrameHTTPRequest, RequestID: "req_http_001", Path: "/private-app/dummy"})
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("response status = %d, want 200", response.StatusCode)
	}
	if err := <-serverHTTPDone; err != nil {
		t.Fatalf("server http exchange returned error: %v", err)
	}
	clientRaw.Close()
	if err := <-runDone; err != nil {
		if !strings.Contains(err.Error(), "closed pipe") {
			t.Fatalf("session Run returned error: %v", err)
		}
	}
}

func TestSessionRegisterTCPStreamRejectsDuplicateRequestID(t *testing.T) {
	manager := NewManager()
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	_, cleanup, err := session.RegisterTCPStream("req_tcp_001")
	if err != nil {
		t.Fatalf("RegisterTCPStream returned error: %v", err)
	}
	defer cleanup()
	if _, _, err := session.RegisterTCPStream("req_tcp_001"); err == nil {
		t.Fatal("RegisterTCPStream returned nil error for duplicate request_id")
	}
}

func TestSessionOpenTCPWritesOpenFrameAndWaitsForResult(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	serverDone := make(chan error, 1)
	go func() {
		var frame Frame
		if err := serverConn.ReadJSON(&frame); err != nil {
			serverDone <- err
			return
		}
		if frame.Type != FrameTCPOpen || frame.RequestID != "req_tcp_open_001" || frame.TunnelID != "tun_lab_001" {
			serverDone <- fmt.Errorf("tcp open frame = %+v", frame)
			return
		}
		serverDone <- serverConn.WriteJSON(Frame{Type: FrameTCPOpenResult, RequestID: frame.RequestID})
	}()

	streamCh, cleanup, response, err := session.OpenTCP(context.Background(), validTCPOpenFrameWithRequestID("req_tcp_open_001"))
	if err != nil {
		t.Fatalf("OpenTCP returned error: %v", err)
	}
	defer cleanup()
	if response.Type != FrameTCPOpenResult || response.RequestID != "req_tcp_open_001" {
		t.Fatalf("open response = %+v", response)
	}
	if streamCh == nil {
		t.Fatal("OpenTCP returned nil stream channel")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
	clientRaw.Close()
	if err := <-runDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
}

func TestSessionOpenTCPReturnsOpenResultError(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	serverDone := make(chan error, 1)
	go func() {
		var frame Frame
		if err := serverConn.ReadJSON(&frame); err != nil {
			serverDone <- err
			return
		}
		serverDone <- serverConn.WriteJSON(Frame{Type: FrameTCPOpenResult, RequestID: frame.RequestID, Error: "dial denied"})
	}()

	_, _, response, err := session.OpenTCP(context.Background(), validTCPOpenFrameWithRequestID("req_tcp_open_error_001"))
	if err == nil {
		t.Fatal("OpenTCP returned nil error")
	}
	if response.Error != "dial denied" || !strings.Contains(err.Error(), "dial denied") {
		t.Fatalf("response=%+v err=%v, want dial denied", response, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
	clientRaw.Close()
	if err := <-runDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
}

func TestSessionOpenTCPRejectsInvalidOpenFramesBeforeWrite(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Frame)
		errContains string
	}{
		{
			name: "missing_application_id",
			mutate: func(frame *Frame) {
				frame.ApplicationID = ""
			},
			errContains: "application_id",
		},
		{
			name: "invalid_port",
			mutate: func(frame *Frame) {
				frame.Port = 0
			},
			errContains: "port",
		},
		{
			name: "idle_timeout_exceeds_lifetime",
			mutate: func(frame *Frame) {
				frame.MaxConnectionLifetimeMillis = int((5 * time.Second) / time.Millisecond)
				frame.IdleTimeoutMillis = int((6 * time.Second) / time.Millisecond)
			},
			errContains: "idle_timeout_ms cannot exceed",
		},
		{
			name: "missing_byte_cap",
			mutate: func(frame *Frame) {
				frame.ByteCap = 0
			},
			errContains: "byte_cap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := validTCPOpenFrameWithRequestID("req_tcp_open_reject_" + tt.name)
			tt.mutate(&frame)
			raw := &recordingNetConn{}
			session := &Session{
				TunnelID: "tun_lab_001",
				conn: &Conn{
					conn:       raw,
					reader:     bufio.NewReader(raw),
					maskWrites: true,
				},
				streams: map[string]chan Frame{},
			}

			streamCh, cleanup, response, err := session.OpenTCP(context.Background(), frame)
			if err == nil {
				t.Fatal("OpenTCP returned nil error for invalid tcp_open frame")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.errContains)
			}
			if streamCh != nil || cleanup != nil || response.Type != "" {
				t.Fatalf("streamCh=%v cleanupNil=%v response=%+v, want no stream or response before write", streamCh, cleanup == nil, response)
			}
			if raw.bytesWritten != 0 {
				t.Fatalf("bytesWritten = %d, want invalid tcp_open rejected before websocket write", raw.bytesWritten)
			}
			if len(session.streams) != 0 {
				t.Fatalf("registered streams = %d, want invalid tcp_open rejected before stream registration", len(session.streams))
			}
		})
	}
}

func TestSessionWriteTCPStreamFrameWritesDataAndClose(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	serverConn := &Conn{conn: serverRaw, reader: bufio.NewReader(serverRaw), maskWrites: false}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	serverDone := make(chan error, 1)
	go func() {
		var openFrame Frame
		if err := serverConn.ReadJSON(&openFrame); err != nil {
			serverDone <- err
			return
		}
		if err := serverConn.WriteJSON(Frame{Type: FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
			serverDone <- err
			return
		}
		var dataFrame Frame
		if err := serverConn.ReadJSON(&dataFrame); err != nil {
			serverDone <- err
			return
		}
		if dataFrame.Type != FrameTCPData || dataFrame.Direction != TCPDirectionUp || dataFrame.TunnelID != "tun_lab_001" {
			serverDone <- fmt.Errorf("tcp data frame = %+v", dataFrame)
			return
		}
		payload, err := TCPDataFramePayload(dataFrame)
		if err != nil {
			serverDone <- err
			return
		}
		if string(payload) != "client-request" {
			serverDone <- fmt.Errorf("payload = %q", string(payload))
			return
		}
		var closeFrame Frame
		if err := serverConn.ReadJSON(&closeFrame); err != nil {
			serverDone <- err
			return
		}
		if closeFrame.Type != FrameTCPClose || closeFrame.Direction != TCPDirectionLocal || closeFrame.CloseReason != TCPCloseReasonEOF || closeFrame.TunnelID != "tun_lab_001" {
			serverDone <- fmt.Errorf("tcp close frame = %+v", closeFrame)
			return
		}
		serverDone <- nil
	}()

	_, cleanup, _, err := session.OpenTCP(context.Background(), validTCPOpenFrameWithRequestID("req_tcp_write_001"))
	if err != nil {
		t.Fatalf("OpenTCP returned error: %v", err)
	}
	defer cleanup()
	dataFrame, err := NewTCPDataFrame("req_tcp_write_001", TCPDirectionUp, []byte("client-request"))
	if err != nil {
		t.Fatalf("NewTCPDataFrame returned error: %v", err)
	}
	if err := session.WriteTCPStreamFrame(dataFrame); err != nil {
		t.Fatalf("WriteTCPStreamFrame data returned error: %v", err)
	}
	if err := session.WriteTCPStreamFrame(Frame{Type: FrameTCPClose, RequestID: "req_tcp_write_001", Direction: TCPDirectionLocal, CloseReason: TCPCloseReasonEOF}); err != nil {
		t.Fatalf("WriteTCPStreamFrame close returned error: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
	clientRaw.Close()
	if err := <-runDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
}

func TestSessionTCPStreamFrameSendReceiveOverInProcessConn(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := NewInProcessConn(clientRaw, true)
	serverConn := NewInProcessConn(serverRaw, false)
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)

	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run()
	}()

	requestID := "req_tcp_inprocess_send_receive"
	upstreamPayload := []byte("synthetic-edge-client-bytes")
	downstreamPayload := []byte("synthetic-private-response-bytes")
	serverDone := make(chan error, 1)
	go func() {
		var openFrame Frame
		if err := serverConn.ReadJSON(&openFrame); err != nil {
			serverDone <- err
			return
		}
		if openFrame.Type != FrameTCPOpen || openFrame.RequestID != requestID || openFrame.TunnelID != "tun_lab_001" {
			serverDone <- fmt.Errorf("tcp open frame = %+v", openFrame)
			return
		}
		if err := serverConn.WriteJSON(Frame{Type: FrameTCPOpenResult, RequestID: openFrame.RequestID}); err != nil {
			serverDone <- err
			return
		}

		var upstreamFrame Frame
		if err := serverConn.ReadJSON(&upstreamFrame); err != nil {
			serverDone <- err
			return
		}
		if upstreamFrame.Type != FrameTCPData || upstreamFrame.RequestID != requestID ||
			upstreamFrame.Direction != TCPDirectionUp || upstreamFrame.TunnelID != "tun_lab_001" {
			serverDone <- fmt.Errorf("upstream frame = %+v", upstreamFrame)
			return
		}
		payload, err := TCPDataFramePayload(upstreamFrame)
		if err != nil {
			serverDone <- err
			return
		}
		if string(payload) != string(upstreamPayload) {
			serverDone <- fmt.Errorf("upstream payload = %q", string(payload))
			return
		}

		downstreamFrame, err := NewTCPDataFrame(openFrame.RequestID, TCPDirectionDown, downstreamPayload)
		if err != nil {
			serverDone <- err
			return
		}
		if err := serverConn.WriteJSON(downstreamFrame); err != nil {
			serverDone <- err
			return
		}
		serverDone <- serverConn.WriteJSON(Frame{
			Type:           FrameTCPClose,
			RequestID:      openFrame.RequestID,
			Direction:      TCPDirectionRemote,
			CloseReason:    TCPCloseReasonEOF,
			BytesUp:        int64(len(upstreamPayload)),
			BytesDown:      int64(len(downstreamPayload)),
			DurationMillis: 42,
		})
	}()

	streamCh, cleanup, response, err := session.OpenTCP(context.Background(), validTCPOpenFrameWithRequestID(requestID))
	if err != nil {
		t.Fatalf("OpenTCP returned error: %v", err)
	}
	defer cleanup()
	if response.Type != FrameTCPOpenResult || response.RequestID != requestID || response.Error != "" {
		t.Fatalf("open response = %+v, want successful tcp_open_result", response)
	}

	upstreamFrame, err := NewTCPDataFrame(requestID, TCPDirectionUp, upstreamPayload)
	if err != nil {
		t.Fatalf("NewTCPDataFrame upstream returned error: %v", err)
	}
	if err := session.WriteTCPStreamFrame(upstreamFrame); err != nil {
		t.Fatalf("WriteTCPStreamFrame upstream returned error: %v", err)
	}

	select {
	case downstreamFrame := <-streamCh:
		if downstreamFrame.Type != FrameTCPData || downstreamFrame.RequestID != requestID || downstreamFrame.Direction != TCPDirectionDown {
			t.Fatalf("downstream frame = %+v, want tcp_data down for request", downstreamFrame)
		}
		payload, err := TCPDataFramePayload(downstreamFrame)
		if err != nil {
			t.Fatalf("downstream TCPDataFramePayload returned error: %v", err)
		}
		if string(payload) != string(downstreamPayload) {
			t.Fatalf("downstream payload = %q, want %q", string(payload), string(downstreamPayload))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for downstream tcp_data")
	}

	select {
	case closeFrame := <-streamCh:
		if closeFrame.Type != FrameTCPClose || closeFrame.RequestID != requestID ||
			closeFrame.Direction != TCPDirectionRemote || closeFrame.CloseReason != TCPCloseReasonEOF {
			t.Fatalf("close frame = %+v, want remote eof close for request", closeFrame)
		}
		if closeFrame.BytesUp != int64(len(upstreamPayload)) || closeFrame.BytesDown != int64(len(downstreamPayload)) || closeFrame.DurationMillis != 42 {
			t.Fatalf("close metrics = up:%d down:%d duration:%d", closeFrame.BytesUp, closeFrame.BytesDown, closeFrame.DurationMillis)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for remote eof tcp_close")
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server returned error: %v", err)
	}
	clientRaw.Close()
	if err := <-runDone; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("session Run returned error: %v", err)
	}
}

func TestSessionWriteTCPStreamFrameRejectsInvalidFramesBeforeWrite(t *testing.T) {
	tests := []struct {
		name        string
		frame       Frame
		errContains string
	}{
		{
			name: "http_frame",
			frame: Frame{
				Type:      FrameHTTPRequest,
				RequestID: "req_tcp_reject_http",
			},
			errContains: "tcp_data or tcp_close frame is required",
		},
		{
			name: "tcp_data_wrong_direction",
			frame: Frame{
				Type:      FrameTCPData,
				RequestID: "req_tcp_reject_direction",
				Direction: TCPDirectionLocal,
				Data:      base64.StdEncoding.EncodeToString([]byte("client bytes")),
			},
			errContains: "tcp_data direction",
		},
		{
			name: "tcp_data_bad_base64",
			frame: Frame{
				Type:      FrameTCPData,
				RequestID: "req_tcp_reject_base64",
				Direction: TCPDirectionUp,
				Data:      "not base64",
			},
			errContains: "base64",
		},
		{
			name: "tcp_close_unknown_reason",
			frame: Frame{
				Type:        FrameTCPClose,
				RequestID:   "req_tcp_reject_close_reason",
				Direction:   TCPDirectionLocal,
				CloseReason: "surprise",
			},
			errContains: "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := &recordingNetConn{}
			session := &Session{
				TunnelID: "tun_lab_001",
				conn: &Conn{
					conn:       raw,
					reader:     bufio.NewReader(raw),
					maskWrites: true,
				},
			}

			err := session.WriteTCPStreamFrame(tt.frame)
			if err == nil {
				t.Fatal("WriteTCPStreamFrame returned nil error for invalid frame")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error = %q, want %q", err.Error(), tt.errContains)
			}
			if raw.bytesWritten != 0 {
				t.Fatalf("bytesWritten = %d, want invalid frame rejected before websocket write", raw.bytesWritten)
			}
		})
	}
}

func TestValidateTCPOpenFrameRequiresDoSGuardLimits(t *testing.T) {
	frame := validTCPOpenFrame()
	if err := ValidateTCPOpenFrame(frame); err != nil {
		t.Fatalf("ValidateTCPOpenFrame returned error: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Frame)
		wantErr string
	}{
		{
			name: "missing byte cap",
			mutate: func(frame *Frame) {
				frame.ByteCap = 0
			},
			wantErr: "byte_cap",
		},
		{
			name: "missing concurrent connection cap",
			mutate: func(frame *Frame) {
				frame.ConcurrentConnectionCap = 0
			},
			wantErr: "concurrent_connection_cap",
		},
		{
			name: "idle timeout exceeds lifetime",
			mutate: func(frame *Frame) {
				frame.MaxConnectionLifetimeMillis = int((60 * time.Second) / time.Millisecond)
				frame.IdleTimeoutMillis = int((70 * time.Second) / time.Millisecond)
			},
			wantErr: "idle_timeout_ms cannot exceed",
		},
		{
			name: "invalid port",
			mutate: func(frame *Frame) {
				frame.Port = 0
			},
			wantErr: "port",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := validTCPOpenFrame()
			test.mutate(&frame)
			err := ValidateTCPOpenFrame(frame)
			if err == nil {
				t.Fatal("ValidateTCPOpenFrame returned nil error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
		})
	}
}

// TestValidateTCPOpenFrameAllowsUnlimitedIdleAndLifetime pins the 0 = unlimited contract that interactive
// East-West streams (ssh/rdp) rely on: idle/lifetime of 0 is accepted (no timer reap), a positive value is still
// bounded by its cap, and the idle<=lifetime invariant only applies when the lifetime is itself bounded.
func TestValidateTCPOpenFrameAllowsUnlimitedIdleAndLifetime(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Frame)
		wantErr string // "" = must be accepted
	}{
		{
			name:   "both unlimited",
			mutate: func(f *Frame) { f.IdleTimeoutMillis = 0; f.MaxConnectionLifetimeMillis = 0 },
		},
		{
			name: "bounded idle under unlimited lifetime",
			mutate: func(f *Frame) {
				f.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
				f.MaxConnectionLifetimeMillis = 0
			},
		},
		{
			name: "unlimited idle under bounded lifetime",
			mutate: func(f *Frame) {
				f.IdleTimeoutMillis = 0
				f.MaxConnectionLifetimeMillis = int((60 * time.Second) / time.Millisecond)
			},
		},
		{
			name:    "positive idle still capped",
			mutate:  func(f *Frame) { f.IdleTimeoutMillis = MaxTCPIdleTimeoutMillis + 1 },
			wantErr: "idle_timeout_ms",
		},
		{
			name: "positive lifetime still capped",
			mutate: func(f *Frame) {
				f.MaxConnectionLifetimeMillis = MaxTCPConnectionLifetimeMillis + 1
				f.IdleTimeoutMillis = 0
			},
			wantErr: "max_connection_lifetime_ms",
		},
		{
			name: "bounded idle over bounded lifetime still rejected",
			mutate: func(f *Frame) {
				f.MaxConnectionLifetimeMillis = int((60 * time.Second) / time.Millisecond)
				f.IdleTimeoutMillis = int((70 * time.Second) / time.Millisecond)
			},
			wantErr: "idle_timeout_ms cannot exceed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := validTCPOpenFrame()
			test.mutate(&frame)
			err := ValidateTCPOpenFrame(frame)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateTCPOpenFrame rejected a valid frame: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

// TestTCPConnectionRegistryCloseExpiredNeverReapsUnlimited proves an interactive stream opened with idle=0 and
// lifetime=0 is never torn down by CloseExpired, even arbitrarily far in the future with no activity — the
// property that stops ssh being cut at a prompt. Teardown of such a stream is driven by the Edge bridge instead.
func TestTCPConnectionRegistryCloseExpiredNeverReapsUnlimited(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 6, 1, 18, 5, 0, 0, time.UTC)

	frame := validTCPOpenFrameWithRequestID("req_tcp_unlimited")
	frame.IdleTimeoutMillis = 0
	frame.MaxConnectionLifetimeMillis = 0
	if err := registry.Open(frame, now); err != nil {
		t.Fatalf("Open unlimited frame returned error: %v", err)
	}
	// No RecordData at all (fully idle), and a full day later.
	if closed := registry.CloseExpired(now.Add(24 * time.Hour)); len(closed) != 0 {
		t.Fatalf("CloseExpired reaped %d unlimited streams, want 0", len(closed))
	}
	if registry.Count() != 1 {
		t.Fatalf("unlimited stream count = %d, want 1 (still open)", registry.Count())
	}
}

func TestTCPConnectionRegistryOpenRejectsInvalidFramesWithoutMutation(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 6, 1, 17, 20, 0, 0, time.UTC)
	existing := validTCPOpenFrameWithRequestID("req_tcp_registry_guard_existing")
	if err := registry.Open(existing, now); err != nil {
		t.Fatalf("Open existing returned error: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Frame)
		wantErr string
	}{
		{
			name: "missing_application_id",
			mutate: func(frame *Frame) {
				frame.ApplicationID = ""
			},
			wantErr: "application_id",
		},
		{
			name: "invalid_port",
			mutate: func(frame *Frame) {
				frame.Port = 0
			},
			wantErr: "port",
		},
		{
			name: "idle_timeout_exceeds_lifetime",
			mutate: func(frame *Frame) {
				frame.MaxConnectionLifetimeMillis = int((10 * time.Second) / time.Millisecond)
				frame.IdleTimeoutMillis = int((11 * time.Second) / time.Millisecond)
			},
			wantErr: "idle_timeout_ms cannot exceed",
		},
		{
			name: "missing_byte_cap",
			mutate: func(frame *Frame) {
				frame.ByteCap = 0
			},
			wantErr: "byte_cap",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := validTCPOpenFrameWithRequestID("req_tcp_registry_guard_" + test.name)
			test.mutate(&frame)
			err := registry.Open(frame, now.Add(time.Second))
			if err == nil {
				t.Fatal("Open returned nil error for invalid tcp_open frame")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
			if got := registry.Count(); got != 1 {
				t.Fatalf("Count = %d, want invalid tcp_open rejected before registry mutation", got)
			}
		})
	}
}

func TestTCPConnectionRegistryRecordDataRejectsInvalidFramesWithoutMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 17, 30, 0, 0, time.UTC)
	tests := []struct {
		name    string
		frame   func(requestID string) Frame
		wantErr string
	}{
		{
			name: "missing_request_id",
			frame: func(_ string) Frame {
				return Frame{
					Type:      FrameTCPData,
					Direction: TCPDirectionUp,
					Data:      base64.StdEncoding.EncodeToString([]byte("client bytes")),
				}
			},
			wantErr: "request_id",
		},
		{
			name: "wrong_direction",
			frame: func(requestID string) Frame {
				return Frame{
					Type:      FrameTCPData,
					RequestID: requestID,
					Direction: TCPDirectionLocal,
					Data:      base64.StdEncoding.EncodeToString([]byte("client bytes")),
				}
			},
			wantErr: "direction",
		},
		{
			name: "bad_base64",
			frame: func(requestID string) Frame {
				return Frame{
					Type:      FrameTCPData,
					RequestID: requestID,
					Direction: TCPDirectionUp,
					Data:      "not base64",
				}
			},
			wantErr: "base64",
		},
		{
			name: "oversized_payload",
			frame: func(requestID string) Frame {
				return Frame{
					Type:      FrameTCPData,
					RequestID: requestID,
					Direction: TCPDirectionUp,
					Data:      base64.StdEncoding.EncodeToString(make([]byte, MaxTCPDataFramePayloadBytes+1)),
				}
			},
			wantErr: "exceeds limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewTCPConnectionRegistry()
			requestID := "req_tcp_registry_record_guard_" + test.name
			if err := registry.Open(validTCPOpenFrameWithRequestID(requestID), now); err != nil {
				t.Fatalf("Open returned error: %v", err)
			}
			closeFrame, closed, err := registry.RecordData(test.frame(requestID), now.Add(time.Second))
			if err == nil {
				t.Fatal("RecordData returned nil error for invalid tcp_data frame")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
			if closed || closeFrame.Type != "" {
				t.Fatalf("RecordData closed=%v frame=%+v, want invalid tcp_data rejected before close", closed, closeFrame)
			}
			if got := registry.Count(); got != 1 {
				t.Fatalf("Count = %d, want invalid tcp_data rejected before registry mutation", got)
			}
			finalClose, err := registry.Close(requestID, TCPDirectionRemote, TCPCloseReasonEOF, now.Add(2*time.Second))
			if err != nil {
				t.Fatalf("Close after rejected RecordData returned error: %v", err)
			}
			if finalClose.BytesUp != 0 || finalClose.BytesDown != 0 {
				t.Fatalf("final close bytes up/down = %d/%d, want invalid tcp_data rejected before metrics mutation", finalClose.BytesUp, finalClose.BytesDown)
			}
		})
	}
}

func TestTCPConnectionRegistryCloseRejectsInvalidInputsWithoutMutation(t *testing.T) {
	now := time.Date(2026, 6, 1, 17, 50, 0, 0, time.UTC)
	tests := []struct {
		name      string
		requestID func(openRequestID string) string
		direction string
		reason    string
		wantErr   string
	}{
		{
			name: "missing_request_id",
			requestID: func(string) string {
				return ""
			},
			direction: TCPDirectionRemote,
			reason:    TCPCloseReasonEOF,
			wantErr:   "not open",
		},
		{
			name: "unknown_request_id",
			requestID: func(string) string {
				return "req_tcp_registry_close_guard_unknown"
			},
			direction: TCPDirectionRemote,
			reason:    TCPCloseReasonEOF,
			wantErr:   "not open",
		},
		{
			name: "wrong_direction",
			requestID: func(openRequestID string) string {
				return openRequestID
			},
			direction: TCPDirectionUp,
			reason:    TCPCloseReasonEOF,
			wantErr:   "direction",
		},
		{
			name: "unknown_reason",
			requestID: func(openRequestID string) string {
				return openRequestID
			},
			direction: TCPDirectionRemote,
			reason:    "surprise",
			wantErr:   "not allowed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewTCPConnectionRegistry()
			requestID := "req_tcp_registry_close_guard_" + test.name
			if err := registry.Open(validTCPOpenFrameWithRequestID(requestID), now); err != nil {
				t.Fatalf("Open returned error: %v", err)
			}
			if _, _, err := registry.RecordData(Frame{
				Type:      FrameTCPData,
				RequestID: requestID,
				Direction: TCPDirectionUp,
				Data:      base64.StdEncoding.EncodeToString([]byte("hello")),
			}, now.Add(time.Second)); err != nil {
				t.Fatalf("RecordData returned error: %v", err)
			}

			closeFrame, err := registry.Close(test.requestID(requestID), test.direction, test.reason, now.Add(2*time.Second))
			if err == nil {
				t.Fatal("Close returned nil error for invalid close input")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.wantErr)
			}
			if closeFrame.Type != "" {
				t.Fatalf("Close frame = %+v, want invalid close rejected before emitting close frame", closeFrame)
			}
			if got := registry.Count(); got != 1 {
				t.Fatalf("Count = %d, want invalid close rejected before registry mutation", got)
			}

			finalClose, err := registry.Close(requestID, TCPDirectionRemote, TCPCloseReasonEOF, now.Add(3*time.Second))
			if err != nil {
				t.Fatalf("Close after rejected close input returned error: %v", err)
			}
			if finalClose.BytesUp != 5 || finalClose.BytesDown != 0 {
				t.Fatalf("final close bytes up/down = %d/%d, want rejected close to preserve metrics", finalClose.BytesUp, finalClose.BytesDown)
			}
			if got := registry.Count(); got != 0 {
				t.Fatalf("Count = %d after final close, want 0", got)
			}
		})
	}
}

func TestValidateTCPDataFrameEnforcesChunkLimit(t *testing.T) {
	frame := Frame{
		Type:      FrameTCPData,
		RequestID: "req_tcp_001",
		Direction: TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString(make([]byte, MaxTCPDataFramePayloadBytes)),
	}
	if err := ValidateTCPDataFrame(frame); err != nil {
		t.Fatalf("ValidateTCPDataFrame returned error: %v", err)
	}

	frame.Data = base64.StdEncoding.EncodeToString(make([]byte, MaxTCPDataFramePayloadBytes+1))
	err := ValidateTCPDataFrame(frame)
	if err == nil {
		t.Fatal("ValidateTCPDataFrame returned nil error for oversized chunk")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("error = %q, want exceeds limit", err.Error())
	}
}

func TestValidateTCPCloseFrameRequiresKnownReasonAndMetrics(t *testing.T) {
	frame := Frame{
		Type:           FrameTCPClose,
		RequestID:      "req_tcp_001",
		Direction:      TCPDirectionLocal,
		CloseReason:    TCPCloseReasonByteCapExceeded,
		BytesUp:        4096,
		BytesDown:      2048,
		DurationMillis: 1250,
	}
	if err := ValidateTCPCloseFrame(frame); err != nil {
		t.Fatalf("ValidateTCPCloseFrame returned error: %v", err)
	}

	frame.CloseReason = "surprise"
	err := ValidateTCPCloseFrame(frame)
	if err == nil {
		t.Fatal("ValidateTCPCloseFrame returned nil error for unknown reason")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %q, want not allowed", err.Error())
	}

	frame.CloseReason = TCPCloseReasonEOF
	frame.BytesDown = -1
	err = ValidateTCPCloseFrame(frame)
	if err == nil {
		t.Fatal("ValidateTCPCloseFrame returned nil error for negative metrics")
	}
	if !strings.Contains(err.Error(), "cannot be negative") {
		t.Fatalf("error = %q, want cannot be negative", err.Error())
	}
}

func TestTCPConnectionRegistryRejectsDuplicateAndConcurrentCap(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 5, 26, 9, 0, 0, 0, time.UTC)
	frame := validTCPOpenFrameWithRequestID("req_tcp_registry_001")
	frame.ConcurrentConnectionCap = 1

	if err := registry.Open(frame, now); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if err := registry.Open(frame, now); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("duplicate Open error = %v, want already open", err)
	}

	second := validTCPOpenFrameWithRequestID("req_tcp_registry_002")
	second.ConcurrentConnectionCap = 1
	if err := registry.Open(second, now); err == nil || !strings.Contains(err.Error(), "concurrent connection cap") {
		t.Fatalf("second Open error = %v, want concurrent connection cap", err)
	}
	if got := registry.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1", got)
	}
}

func TestTCPConnectionRegistryClosesWhenByteCapExceeded(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 5, 26, 9, 0, 0, 0, time.UTC)
	frame := validTCPOpenFrameWithRequestID("req_tcp_byte_cap_001")
	frame.ByteCap = 4
	if err := registry.Open(frame, now); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	closeFrame, closed, err := registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: "req_tcp_byte_cap_001",
		Direction: TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString([]byte("ab")),
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("RecordData returned error: %v", err)
	}
	if closed || closeFrame.Type != "" {
		t.Fatalf("RecordData closed=%v frame=%+v, want no close", closed, closeFrame)
	}

	closeFrame, closed, err = registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: "req_tcp_byte_cap_001",
		Direction: TCPDirectionDown,
		Data:      base64.StdEncoding.EncodeToString([]byte("cde")),
	}, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("RecordData returned error: %v", err)
	}
	if !closed {
		t.Fatal("RecordData closed=false, want true")
	}
	if closeFrame.CloseReason != TCPCloseReasonByteCapExceeded || closeFrame.Direction != TCPDirectionLocal {
		t.Fatalf("closeFrame = %+v, want local byte_cap_exceeded", closeFrame)
	}
	if closeFrame.BytesUp != 2 || closeFrame.BytesDown != 3 {
		t.Fatalf("closeFrame bytes up/down = %d/%d, want 2/3", closeFrame.BytesUp, closeFrame.BytesDown)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("Count = %d, want 0", got)
	}
}

func TestTCPConnectionRegistryClosesExpiredConnections(t *testing.T) {
	now := time.Date(2026, 5, 26, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		mutate     func(*Frame)
		at         time.Time
		wantReason string
	}{
		{
			name: "idle timeout",
			mutate: func(frame *Frame) {
				frame.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
				frame.MaxConnectionLifetimeMillis = int((5 * time.Minute) / time.Millisecond)
			},
			at:         now.Add(31 * time.Second),
			wantReason: TCPCloseReasonIdleTimeoutExceeded,
		},
		{
			name: "lifetime",
			mutate: func(frame *Frame) {
				frame.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
				frame.MaxConnectionLifetimeMillis = int((1 * time.Minute) / time.Millisecond)
			},
			at:         now.Add(61 * time.Second),
			wantReason: TCPCloseReasonLifetimeExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewTCPConnectionRegistry()
			frame := validTCPOpenFrameWithRequestID("req_tcp_expired_001")
			tt.mutate(&frame)
			if err := registry.Open(frame, now); err != nil {
				t.Fatalf("Open returned error: %v", err)
			}
			closed := registry.CloseExpired(tt.at)
			if len(closed) != 1 {
				t.Fatalf("CloseExpired returned %d frames, want 1", len(closed))
			}
			if closed[0].CloseReason != tt.wantReason || closed[0].Direction != TCPDirectionLocal {
				t.Fatalf("closed frame = %+v, want reason %s direction local", closed[0], tt.wantReason)
			}
			if got := registry.Count(); got != 0 {
				t.Fatalf("Count = %d, want 0", got)
			}
		})
	}
}

func TestTCPConnectionRegistryCloseExpiredPreservesMetricsAndKeepsActiveRecords(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 6, 1, 18, 5, 0, 0, time.UTC)
	closeAt := now.Add(70 * time.Second)

	lifetime := validTCPOpenFrameWithRequestID("req_tcp_expired_lifetime_metrics")
	lifetime.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
	lifetime.MaxConnectionLifetimeMillis = int((60 * time.Second) / time.Millisecond)
	if err := registry.Open(lifetime, now); err != nil {
		t.Fatalf("Open lifetime returned error: %v", err)
	}
	if _, _, err := registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: lifetime.RequestID,
		Direction: TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString([]byte("up!")),
	}, now.Add(10*time.Second)); err != nil {
		t.Fatalf("RecordData lifetime returned error: %v", err)
	}

	idle := validTCPOpenFrameWithRequestID("req_tcp_expired_idle_metrics")
	idle.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
	idle.MaxConnectionLifetimeMillis = int((5 * time.Minute) / time.Millisecond)
	if err := registry.Open(idle, now); err != nil {
		t.Fatalf("Open idle returned error: %v", err)
	}
	if _, _, err := registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: idle.RequestID,
		Direction: TCPDirectionDown,
		Data:      base64.StdEncoding.EncodeToString([]byte("down")),
	}, now.Add(20*time.Second)); err != nil {
		t.Fatalf("RecordData idle returned error: %v", err)
	}

	active := validTCPOpenFrameWithRequestID("req_tcp_expired_active_metrics")
	active.IdleTimeoutMillis = int((30 * time.Second) / time.Millisecond)
	active.MaxConnectionLifetimeMillis = int((5 * time.Minute) / time.Millisecond)
	if err := registry.Open(active, now); err != nil {
		t.Fatalf("Open active returned error: %v", err)
	}
	if _, _, err := registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: active.RequestID,
		Direction: TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString([]byte("active")),
	}, closeAt.Add(-time.Second)); err != nil {
		t.Fatalf("RecordData active returned error: %v", err)
	}

	closed := registry.CloseExpired(closeAt)
	if len(closed) != 2 {
		t.Fatalf("CloseExpired returned %d frames, want 2", len(closed))
	}
	closedByRequestID := map[string]Frame{}
	for _, frame := range closed {
		closedByRequestID[frame.RequestID] = frame
	}

	lifetimeClose, ok := closedByRequestID[lifetime.RequestID]
	if !ok {
		t.Fatalf("CloseExpired did not close %s", lifetime.RequestID)
	}
	if lifetimeClose.CloseReason != TCPCloseReasonLifetimeExceeded || lifetimeClose.Direction != TCPDirectionLocal {
		t.Fatalf("lifetime close frame = %+v, want local lifetime_exceeded", lifetimeClose)
	}
	if lifetimeClose.BytesUp != 3 || lifetimeClose.BytesDown != 0 || lifetimeClose.DurationMillis != 70000 {
		t.Fatalf("lifetime close metrics = up:%d down:%d duration:%d, want 3/0/70000", lifetimeClose.BytesUp, lifetimeClose.BytesDown, lifetimeClose.DurationMillis)
	}

	idleClose, ok := closedByRequestID[idle.RequestID]
	if !ok {
		t.Fatalf("CloseExpired did not close %s", idle.RequestID)
	}
	if idleClose.CloseReason != TCPCloseReasonIdleTimeoutExceeded || idleClose.Direction != TCPDirectionLocal {
		t.Fatalf("idle close frame = %+v, want local idle_timeout_exceeded", idleClose)
	}
	if idleClose.BytesUp != 0 || idleClose.BytesDown != 4 || idleClose.DurationMillis != 70000 {
		t.Fatalf("idle close metrics = up:%d down:%d duration:%d, want 0/4/70000", idleClose.BytesUp, idleClose.BytesDown, idleClose.DurationMillis)
	}

	if got := registry.Count(); got != 1 {
		t.Fatalf("Count = %d after CloseExpired, want only active record kept", got)
	}
	activeClose, err := registry.Close(active.RequestID, TCPDirectionRemote, TCPCloseReasonEOF, closeAt.Add(time.Second))
	if err != nil {
		t.Fatalf("Close active after CloseExpired returned error: %v", err)
	}
	if activeClose.BytesUp != 6 || activeClose.BytesDown != 0 {
		t.Fatalf("active close bytes up/down = %d/%d, want active metrics preserved", activeClose.BytesUp, activeClose.BytesDown)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("Count = %d after active close, want 0", got)
	}
}

func TestTCPConnectionRegistryCloseRemovesConnectionWithMetrics(t *testing.T) {
	registry := NewTCPConnectionRegistry()
	now := time.Date(2026, 5, 26, 9, 0, 0, 0, time.UTC)
	frame := validTCPOpenFrameWithRequestID("req_tcp_close_001")
	if err := registry.Open(frame, now); err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if _, _, err := registry.RecordData(Frame{
		Type:      FrameTCPData,
		RequestID: "req_tcp_close_001",
		Direction: TCPDirectionUp,
		Data:      base64.StdEncoding.EncodeToString([]byte("hello")),
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("RecordData returned error: %v", err)
	}

	closeFrame, err := registry.Close("req_tcp_close_001", TCPDirectionRemote, TCPCloseReasonEOF, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if closeFrame.Direction != TCPDirectionRemote || closeFrame.CloseReason != TCPCloseReasonEOF {
		t.Fatalf("closeFrame = %+v, want remote eof", closeFrame)
	}
	if closeFrame.BytesUp != 5 || closeFrame.BytesDown != 0 || closeFrame.DurationMillis != 2000 {
		t.Fatalf("closeFrame metrics = up:%d down:%d duration:%d, want 5/0/2000", closeFrame.BytesUp, closeFrame.BytesDown, closeFrame.DurationMillis)
	}
	if got := registry.Count(); got != 0 {
		t.Fatalf("Count = %d, want 0", got)
	}
}

func TestSessionFailPendingNotifiesPendingAndStreams(t *testing.T) {
	manager := NewManager()
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)

	pendingCh := make(chan Frame, 1)
	session.mu.Lock()
	session.pending["req_http_001"] = pendingCh
	session.mu.Unlock()

	streamCh, streamCleanup, err := session.RegisterTCPStream("req_tcp_001")
	if err != nil {
		t.Fatalf("RegisterTCPStream returned error: %v", err)
	}
	defer streamCleanup()

	session.failPending(errors.New("connection reset"))

	select {
	case frame := <-pendingCh:
		if !strings.Contains(frame.Error, "connection reset") {
			t.Fatalf("pending frame error = %q, want connection reset", frame.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for pending frame notification")
	}

	select {
	case frame := <-streamCh:
		if frame.Type != FrameTCPClose || frame.CloseReason != TCPCloseReasonError {
			t.Fatalf("stream frame = %+v, want tcp_close reason=error", frame)
		}
		if !strings.Contains(frame.Error, "connection reset") {
			t.Fatalf("stream frame error = %q, want connection reset", frame.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for stream frame notification")
	}

	_, cleanup2, err := session.RegisterTCPStream("req_tcp_002")
	if err != nil {
		t.Fatalf("RegisterTCPStream after failPending returned error: %v", err)
	}
	defer cleanup2()
}

func TestSessionDeliverTCPStreamBackpressureFailsClosedOnOverflow(t *testing.T) {
	manager := NewManager()
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	clientConn := &Conn{conn: clientRaw, reader: bufio.NewReader(clientRaw), maskWrites: true}
	session, _ := manager.Register("conn_lab_001", "tun_lab_001", clientConn)

	streamCh, streamCleanup, err := session.RegisterTCPStream("req_tcp_backpressure_001")
	if err != nil {
		t.Fatalf("RegisterTCPStream returned error: %v", err)
	}
	defer streamCleanup()

	for i := 0; i < cap(streamCh); i++ {
		session.deliverTCPStream(Frame{Type: FrameTCPData, RequestID: "req_tcp_backpressure_001", Data: "AA=="})
	}

	session.deliverTCPStream(Frame{Type: FrameTCPData, RequestID: "req_tcp_backpressure_001", Data: "AQ=="})

	session.mu.Lock()
	_, stillRegistered := session.streams["req_tcp_backpressure_001"]
	session.mu.Unlock()
	if stillRegistered {
		t.Fatal("deliverTCPStream left stream registered after overflow")
	}

	for i := 0; i < cap(streamCh); i++ {
		select {
		case _, ok := <-streamCh:
			if !ok {
				t.Fatal("stream closed before buffered frames were drained")
			}
		case <-time.After(time.Second):
			t.Fatal("timeout draining buffered stream frame")
		}
	}
	select {
	case _, ok := <-streamCh:
		if ok {
			t.Fatal("stream remained open after backpressure overflow")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for stream close after overflow")
	}
}

type fakeFrameTransport struct {
	reads     chan Frame
	writes    chan Frame
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeFrameTransport() *fakeFrameTransport {
	return &fakeFrameTransport{
		reads:  make(chan Frame, 4),
		writes: make(chan Frame, 4),
		closed: make(chan struct{}),
	}
}

func (transport *fakeFrameTransport) ReadJSON(value any) error {
	select {
	case frame := <-transport.reads:
		target, ok := value.(*Frame)
		if !ok {
			return errors.New("fake frame transport only supports *Frame reads")
		}
		*target = frame
		return nil
	case <-transport.closed:
		return io.EOF
	}
}

func (transport *fakeFrameTransport) WriteJSON(value any) error {
	frame, ok := value.(Frame)
	if !ok {
		return errors.New("fake frame transport only supports Frame writes")
	}
	select {
	case transport.writes <- frame:
		return nil
	case <-transport.closed:
		return io.ErrClosedPipe
	}
}

func (transport *fakeFrameTransport) Close() error {
	transport.closeOnce.Do(func() {
		close(transport.closed)
	})
	return nil
}

func (transport *fakeFrameTransport) Closed() bool {
	select {
	case <-transport.closed:
		return true
	default:
		return false
	}
}

func (transport *fakeFrameTransport) waitForWrite(t *testing.T) Frame {
	t.Helper()
	select {
	case frame := <-transport.writes:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for fake transport write")
		return Frame{}
	}
}

func validTCPOpenFrame() Frame {
	return validTCPOpenFrameWithRequestID("req_tcp_001")
}

func validTCPOpenFrameWithRequestID(requestID string) Frame {
	return Frame{
		Type:                        FrameTCPOpen,
		RequestID:                   requestID,
		ApplicationID:               "app_dummy_https",
		Host:                        "dummy-private-app.local",
		Port:                        443,
		ConnectTimeoutMillis:        int((5 * time.Second) / time.Millisecond),
		MaxConnectionLifetimeMillis: int((5 * time.Minute) / time.Millisecond),
		IdleTimeoutMillis:           int((30 * time.Second) / time.Millisecond),
		ByteCap:                     64 << 20,
		ConcurrentConnectionCap:     32,
	}
}

type recordingNetConn struct {
	bytesWritten int
}

func (c *recordingNetConn) Read(_ []byte) (int, error) {
	return 0, errors.New("recording connection does not support reads")
}

func (c *recordingNetConn) Write(payload []byte) (int, error) {
	c.bytesWritten += len(payload)
	return len(payload), nil
}

func (c *recordingNetConn) Close() error {
	return nil
}

func (c *recordingNetConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (c *recordingNetConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (c *recordingNetConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *recordingNetConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *recordingNetConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type recordingAddr string

func (a recordingAddr) Network() string {
	return string(a)
}

func (a recordingAddr) String() string {
	return string(a)
}

// Regression: a FrameDNSResult must be delivered to the pending RoundTrip (conditional DNS forwarding). It was
// omitted from the session read loop's response allowlist, so every internal DNS query silently timed out —
// a bug only the live-connector E2E surfaced. See docs/dns_conditional_forwarding_design.md.
func TestSessionRoundTripDeliversDNSResult(t *testing.T) {
	manager := NewManagerWithRequestTimeout(time.Second)
	transport := newFakeFrameTransport()
	session, _ := manager.Register("conn_dns_result", "tun_dns_result", transport)
	go func() { _ = session.Run() }()
	go func() {
		frame := transport.waitForWrite(t)
		transport.reads <- Frame{Type: FrameDNSResult, RequestID: frame.RequestID, DNSResponse: "cmF3LXJlc3A="}
	}()
	response, err := session.RoundTrip(context.Background(), Frame{
		Type:        FrameDNSQuery,
		RequestID:   "dnsq_regression_001",
		DNSUpstream: "10.10.0.10:53",
		DNSQuery:    "cXVlcnk=",
	})
	if err != nil {
		t.Fatalf("RoundTrip(FrameDNSQuery) errored: %v — FrameDNSResult must reach the pending RoundTrip", err)
	}
	if response.Type != FrameDNSResult || response.DNSResponse != "cmF3LXJlc3A=" {
		t.Fatalf("expected the DNS result frame, got %+v", response)
	}
	_ = session.Close()
}

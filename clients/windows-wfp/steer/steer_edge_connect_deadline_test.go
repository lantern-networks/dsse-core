package main

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func acceptCONNECT(t *testing.T, ln net.Listener) (net.Conn, <-chan struct{}) {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	requestRead := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				close(requestRead)
				return
			}
		}
	}()
	select {
	case conn := <-accepted:
		return conn, requestRead
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT server did not accept")
		return nil, nil
	}
}

func TestEdgeCONNECTResponseUsesConfiguredDialTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, status, _, _, err := dialEdgeCONNECT(edgeConfig{
			edgeURL:      "http://" + ln.Addr().String(),
			genericSteer: true,
			dialTimeout:  80 * time.Millisecond,
		}, netip.MustParseAddrPort("192.0.2.1:443"))
		if conn != nil {
			conn.Close()
		}
		if status != 0 || err == nil {
			result <- io.ErrUnexpectedEOF
			return
		}
		result <- nil
	}()
	server, requestRead := acceptCONNECT(t, ln)
	defer server.Close()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT server did not receive request")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(450 * time.Millisecond):
		server.Close()
		<-result
		t.Fatal("Edge CONNECT waited indefinitely for a silent peer")
	}
}

func TestEdgeCONNECTClearsHandshakeDeadlineAfterSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	connResult := make(chan net.Conn, 1)
	errorResult := make(chan error, 1)
	go func() {
		conn, status, _, _, err := dialEdgeCONNECT(edgeConfig{
			edgeURL:      "http://" + ln.Addr().String(),
			genericSteer: true,
			dialTimeout:  80 * time.Millisecond,
		}, netip.MustParseAddrPort("192.0.2.1:443"))
		if err != nil || status != 200 {
			errorResult <- err
			return
		}
		connResult <- conn
	}()
	server, requestRead := acceptCONNECT(t, ln)
	defer server.Close()
	select {
	case <-requestRead:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT server did not receive request")
	}
	if _, err := io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var tunnel net.Conn
	select {
	case tunnel = <-connResult:
	case err := <-errorResult:
		t.Fatalf("CONNECT failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT did not complete")
	}
	defer tunnel.Close()
	time.Sleep(160 * time.Millisecond)
	if _, err := io.WriteString(server, "x"); err != nil {
		t.Fatal(err)
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := tunnel.Read(b[:]); err != nil || b[0] != 'x' {
		t.Fatalf("established tunnel inherited handshake deadline: byte=%q err=%v", b, err)
	}
}

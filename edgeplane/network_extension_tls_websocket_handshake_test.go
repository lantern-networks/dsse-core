package edgeplane

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// Exercise the actual TLS record boundary, not just writes to a bytes.Buffer.
// Some WebSocket clients reject handshakes delivered through excessive small
// reads. The limits below model tungstenite's public AttackCheck; this is not a
// test of a particular application's bundled WebSocket library.
func TestWebSocketHandshakeAvoidsTinyTLSRecords(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			root, key, pool := interceptionTestRoot(t)
			leaf := interceptionTestLeaf(t, root, key, "websocket.example.com")
			serverRaw, clientRaw := net.Pipe()
			defer serverRaw.Close()
			defer clientRaw.Close()
			deadline := time.Now().Add(5 * time.Second)
			serverRaw.SetDeadline(deadline)
			clientRaw.SetDeadline(deadline)
			server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: version, MaxVersion: version})
			client := tls.Client(clientRaw, &tls.Config{RootCAs: pool, ServerName: "websocket.example.com", MinVersion: version, MaxVersion: version})
			response := &http.Response{StatusCode: http.StatusSwitchingProtocols, Status: "101 Switching Protocols", Header: http.Header{}}
			response.Header.Set("Sec-WebSocket-Accept", NetworkExtensionLabTLSWebSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="))
			response.Header.Set("Sec-WebSocket-Protocol", "test-protocol")
			response.Header.Add("Set-Cookie", "a=1; Secure")
			response.Header.Add("Set-Cookie", "b=2; Secure")
			response.Header.Set("Content-Length", "123")
			response.Header.Set("Transfer-Encoding", "chunked")
			for i := 0; i < 24; i++ {
				response.Header.Set(fmt.Sprintf("X-Test-%02d", i), "test-value")
			}
			frame := []byte{0x81, 0x02, 'o', 'k'}
			done := make(chan error, 1)
			go func() {
				defer serverRaw.Close()
				err := writeNetworkExtensionLabTLSWebSocketSwitchingProtocolResponse(server, response)
				if err == nil {
					_, err = server.Write(frame)
				}
				done <- err
			}()
			// Also join the writer on failure, when the client rejects the header.
			defer func() {
				clientRaw.Close()
				if err := <-done; err != nil && !t.Failed() {
					t.Errorf("server: %v", err)
				}
			}()
			var header bytes.Buffer
			buf := make([]byte, 4096)
			reads := 0
			for !bytes.Contains(header.Bytes(), []byte("\r\n\r\n")) {
				n, err := client.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				reads++
				header.Write(buf[:n])
				if header.Len() > 65536 || reads > 512 || (reads > 64 && reads*128 > header.Len()) {
					t.Fatalf("handshake rejected by small-read guard: reads=%d bytes=%d", reads, header.Len())
				}
			}
			t.Logf("handshake accepted: reads=%d bytes=%d", reads, header.Len())
			reader := bufio.NewReader(io.MultiReader(bytes.NewReader(header.Bytes()), client))
			got, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.StatusCode != 101 || got.Header.Get("Connection") != "Upgrade" || got.Header.Get("Upgrade") != "websocket" || got.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" || got.Header.Get("Sec-WebSocket-Protocol") != "test-protocol" {
				t.Fatalf("invalid handshake: %v", got)
			}
			if cookies := got.Header.Values("Set-Cookie"); len(cookies) != 2 || cookies[0] != "a=1; Secure" || cookies[1] != "b=2; Secure" {
				t.Fatalf("cookies changed: %v", cookies)
			}
			if got.Header.Get("Content-Length") != "" || got.Header.Get("Transfer-Encoding") != "" {
				t.Fatal("HTTP body framing leaked into upgrade response")
			}
			if response.Header.Get("Content-Length") != "123" || response.Header.Get("Connection") != "" {
				t.Fatal("upstream headers mutated")
			}
			gotFrame := make([]byte, len(frame))
			if _, err := io.ReadFull(reader, gotFrame); err != nil || !bytes.Equal(gotFrame, frame) {
				t.Fatalf("first frame corrupted or buffered: %x, %v", gotFrame, err)
			}
		})
	}
}

type websocketHandshakeTestWriter func([]byte) (int, error)

func (f websocketHandshakeTestWriter) Write(p []byte) (int, error) { return f(p) }

func TestWebSocketHandshakeWriteErrors(t *testing.T) {
	want := errors.New("downstream disconnected")
	for _, tc := range []struct {
		name   string
		writer websocketHandshakeTestWriter
		want   error
	}{
		{"disconnected", func([]byte) (int, error) { return 0, want }, want},
		{"short-write", func(p []byte) (int, error) { return len(p) - 1, nil }, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeNetworkExtensionLabTLSWebSocketSwitchingProtocolResponse(tc.writer, &http.Response{StatusCode: 101, Header: http.Header{}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

package tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDialCancellationInterruptsSilentPeer(t *testing.T) {
	for _, scheme := range []string{"ws", "wss"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := DialTLS(ctx, scheme+"://"+listener.Addr().String()+"/tunnel", nil, nil)
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case peer := <-accepted:
				defer peer.Close()
			case <-time.After(3 * time.Second):
				t.Fatal("dial did not reach the listener")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled dial remained blocked on the silent peer")
			}
		})
	}
}

type notifyWriteConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *notifyWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

func TestCloseInterruptsBlockedWebSocketWriter(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	raw := &notifyWriteConn{Conn: a, entered: make(chan struct{})}
	conn := NewInProcessConn(raw, true)
	written := make(chan error, 1)
	go func() { written <- conn.WriteJSON(Frame{Type: FrameHTTPRequest, RequestID: "pending"}) }()
	<-raw.entered
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited behind a blocked websocket writer")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt the blocked writer")
	}
}

func TestDialPreservesEscapedPathAndQuery(t *testing.T) {
	observed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.RequestURI
		conn, err := Upgrade(w, r)
		if err == nil {
			conn.conn.Close()
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	path := "/tunnel/a%2Fb?label=a%2Fb&mode=active"
	conn, err := Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.conn.Close()
	if got := <-observed; got != path {
		t.Fatalf("request target = %q, want %q", got, path)
	}
}

func TestDialCancellationAfterTLSInterruptsHTTPUpgrade(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}))
	defer func() { close(release); server.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := DialTLS(ctx, "wss"+strings.TrimPrefix(server.URL, "https"), nil,
			server.Client().Transport.(*http.Transport).TLSClientConfig)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not reach the HTTP handler")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled TLS connection remained blocked on the HTTP upgrade")
	}
}

func TestEstablishedTunnelOutlivesDialContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		var frame Frame
		if conn.ReadJSON(&frame) == nil {
			_ = conn.WriteJSON(frame)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := DialTLS(ctx, "wss"+strings.TrimPrefix(server.URL, "https"), nil,
		server.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.conn.SetDeadline(time.Now().Add(3 * time.Second))
	cancel()
	frame := Frame{Type: FrameHTTPRequest, RequestID: "still-live"}
	if err := conn.WriteJSON(frame); err != nil {
		t.Fatal(err)
	}
	var response Frame
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatal(err)
	}
	if response.RequestID != frame.RequestID {
		t.Fatalf("wrong response: %q", response.RequestID)
	}
}

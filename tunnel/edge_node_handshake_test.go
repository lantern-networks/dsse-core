package tunnel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The accepting Edge names itself on the 101 and the dialling side can read it. Without this a client behind
// an L4 front door has no way to know WHICH node of a fleet it reached — it dialled the door.
func TestTheAcceptingSideNamesItselfOnTheHandshake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := UpgradeWithHeaders(w, r, http.Header{EdgeNodeHeader: []string{"edge-b"}})
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		var frame Frame
		_ = conn.ReadJSON(&frame)
	}))
	defer server.Close()

	host := server.Listener.Addr().String()
	conn, err := Dial(context.Background(), "ws://"+net.JoinHostPort(hostOnly(host), portOnly(host))+"/tunnel", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if conn.ResponseHeader == nil {
		t.Fatal("the dialling side kept no response header, so it cannot tell which node answered")
	}
	if got := conn.ResponseHeader.Get(EdgeNodeHeader); got != "edge-b" {
		t.Fatalf("expected the accepting node's name on the handshake, got %q", got)
	}
}

// A plain Upgrade must still produce a valid handshake — the header block has to be terminated exactly once.
func TestUpgradeWithoutExtraHeadersStillCompletes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		var frame Frame
		_ = conn.ReadJSON(&frame)
	}))
	defer server.Close()

	host := server.Listener.Addr().String()
	conn, err := Dial(context.Background(), "ws://"+host+"/tunnel", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.ResponseHeader.Get(EdgeNodeHeader); got != "" {
		t.Fatalf("an Edge that names no node must send none, got %q", got)
	}
}

func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func portOnly(hostport string) string {
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return port
}

// A refused upgrade must reach the caller as something it can ACT on: the status, and what the server said
// about itself while refusing. Without the headers a connector cannot tell "you already hold this node" from
// any other rejection, and it would treat the walk's normal answer as a failure.
func TestARefusedUpgradeCarriesTheServersAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ConnectorHoldsHeader) == "" {
			t.Error("the dialling side did not declare what it holds")
		}
		w.Header().Set(EdgeNodeHeader, "edge-b")
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	headers := http.Header{}
	headers.Set(ConnectorHoldsHeader, "edge-a,edge-b")
	_, err := DialTLS(context.Background(), "ws://"+server.Listener.Addr().String()+"/tunnel", headers, nil)
	if err == nil {
		t.Fatal("expected the refusal to surface as an error")
	}
	var rejected *UpgradeRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected a typed rejection the caller can inspect, got %T: %v", err, err)
	}
	if rejected.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d", rejected.StatusCode)
	}
	if got := rejected.Header.Get(EdgeNodeHeader); got != "edge-b" {
		t.Fatalf("the refusing node must still name itself, got %q", got)
	}
}

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSilentHeartbeatAfterFailbackClosesHeldTunnelAndReachesOtherRegion(t *testing.T) {
	stop := make(chan struct{})
	var failures atomic.Int64
	hung := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		failures.Add(1)
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer hung.Close()
	defer close(stop)
	reached := make(chan struct{}, 1)
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		select {
		case reached <- struct{}{}:
		default:
		}
	}))
	defer good.Close()
	doors := parseConnectorEndpoints("a=" + hung.URL + ";b=" + good.URL)
	doors.advance(errors.New("setup failure"))
	doors.resetToPreferred()
	// A real held socket must end on movement; changing only the URL is insufficient.
	held, peer := net.Pipe()
	defer peer.Close()
	defer held.Close()
	closed := make(chan struct{})
	go func() { _, _ = peer.Read(make([]byte, 1)); close(closed) }()
	var countAtMove atomic.Int64
	doors.SetOnMove(func() { countAtMove.Store(failures.Load()); _ = held.Close() })
	base := hung.Client()
	base.Timeout = 30 * time.Second
	health := connectorHeartbeatHTTPClient(base, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConnectorHeartbeats(ctx, doors, func(at string) error {
			return sendHeartbeat(health, at, "fixture", "secret", "tenant", "", "", false, nil)
		}, func() {
			// Registration's control-plane reporting may block even when the
			// replacement door accepts this already enrolled Connector. It must
			// not run merely because the previous door stopped answering.
			<-ctx.Done()
		}, 10*time.Millisecond)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("health loop did not stop")
		}
	}()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("silent door retained after failback; healthy Region never received a heartbeat")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("held dead-region tunnel was not closed")
	}
	if countAtMove.Load() != 3 {
		t.Fatalf("moved after %d failures, want the retained three-failure policy", countAtMove.Load())
	}
	if doors.current() != good.URL {
		t.Fatal("connector did not stay on the healthy door")
	}
	if base.Timeout != 30*time.Second {
		t.Fatal("heartbeat changed the management request budget")
	}
}

func TestStaleHeartbeatAndTunnelVerdictsCannotMoveNewSelectionOrABA(t *testing.T) {
	doors := parseConnectorEndpoints("a=https://a.example;b=https://b.example")
	first := doors.selection()
	doors.advanceIfSelected(first, errors.New("network failure"))
	second := doors.selection()
	if doors.advanceIfSelected(first, errors.New("late heartbeat")) != "" || doors.selection() != second {
		t.Fatal("old heartbeat moved the new Region")
	}
	doors.resetToPreferred()
	if doors.advanceIfSelected(first, errors.New("old A verdict after ABA")) != "" {
		t.Fatal("an old connection verdict was applied to a new visit to A")
	}
	if doors.advanceIfSelected(doors.selection(), errors.New("current A failed")) != second.url {
		t.Fatal("failback hid a genuine current failure")
	}
}

func TestHealthClientPreservesShorterExplicitTimeout(t *testing.T) {
	base := &http.Client{Timeout: time.Millisecond}
	if connectorHeartbeatHTTPClient(base, 5*time.Second).Timeout != time.Millisecond {
		t.Fatal("shorter request budget ignored")
	}
	if connectorHeartbeatHTTPClient(nil, 5*time.Second).Timeout != 5*time.Second {
		t.Fatal("missing health request deadline")
	}
}

func TestAnsweringAuthorizationRefusalReregistersWithoutRegionMovement(t *testing.T) {
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer refused.Close()
	doors := parseConnectorEndpoints("a=" + refused.URL + ";b=https://not-selected.example")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registered := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConnectorHeartbeats(ctx, doors, func(at string) error {
			return sendHeartbeat(refused.Client(), at, "fixture", "secret", "tenant", "", "", false, nil)
		}, func() { registered <- struct{}{}; cancel() }, time.Millisecond)
	}()
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("answering refusal did not trigger re-registration")
	}
	<-done
	if doors.current() != refused.URL {
		t.Fatal("authorization refusal incorrectly moved Region")
	}
}

package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestStepUpResultBelongsToExactRequestAndOSSession(t *testing.T) {
	id := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	otherID := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	owner := stepUpOwner{PID: 7, Session: 2, SID: "S-1-5-21-100-200-300-1001"}
	launched := make(chan struct{}, 1)
	notified := make(chan string, 1)
	c := newStepUpCoordinator(time.Minute, nil, nil)
	c.validate = func(string) bool { return true }
	c.launchForOwner = func(string, string, stepUpOwner) { launched <- struct{}{} }
	c.resultForOwner = func(result string, _ stepUpOwner) { notified <- result }
	if !c.TriggerForOwner("app:22", "https://portal.example/clientless/auth/start?request_id="+id, owner) {
		t.Fatal("request not admitted")
	}
	<-launched
	if c.HandleResultForOwner("app:22", otherID, "resumed", owner) ||
		c.HandleResultForOwner("app:22", id, "resumed", stepUpOwner{Session: 3, SID: owner.SID}) ||
		c.HandleResultForOwner("app:22", id, "unknown", owner) {
		t.Fatal("unrelated result accepted")
	}
	if !c.HandleResultForOwner("app:22", id, "resumed", owner) || c.HandleResultForOwner("app:22", id, "resumed", owner) {
		t.Fatal("result not delivered exactly once")
	}
	select {
	case got := <-notified:
		if got != "resumed" {
			t.Fatalf("result=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("result notice not delivered")
	}
}

func TestMuxResultFrameReachesOnlyOriginatingFlow(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	local, remote := net.Pipe()
	defer remote.Close()
	owner := stepUpOwner{PID: 7, Session: 2, SID: "S-1-5-21-100-200-300-1001", LogonID: 19}
	launched, notified := make(chan struct{}, 1), make(chan string, 1)
	c := newStepUpCoordinator(time.Minute, nil, nil)
	c.launchForOwner = func(string, string, stepUpOwner) { launched <- struct{}{} }
	c.resultForOwner = func(result string, _ stepUpOwner) { notified <- result }
	m := &steerMuxClient{conn: local, dead: make(chan struct{}), stepUp: c, flows: make(map[uint32]*muxFlowConn)}
	m.flows[7] = &muxFlowConn{flowID: 7, mux: m, inbound: newMuxPipe(1024), authority: "app:22", owner: owner}
	go m.readLoop(bufio.NewReader(local))
	send := func(flowID uint32, typ byte, payload string) {
		t.Helper()
		var frame [muxHeaderLen]byte
		binary.BigEndian.PutUint32(frame[:4], flowID)
		frame[4] = typ
		binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
		if _, err := remote.Write(frame[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := remote.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	send(7, muxFrameStepUp, "https://portal.example/clientless/auth/start?request_id="+id)
	select {
	case <-launched:
	case <-time.After(time.Second):
		t.Fatal("step-up not delivered")
	}
	send(8, muxFrameAuthResult, `{"request_id":"`+id+`","result":"resumed"}`)
	send(7, muxFrameAuthResult, `{"request_id":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","result":"resumed"}`)
	select {
	case <-notified:
		t.Fatal("unrelated flow or request reported success")
	case <-time.After(20 * time.Millisecond):
	}
	send(7, muxFrameAuthResult, `{"request_id":"`+id+`","result":"resumed"}`)
	select {
	case got := <-notified:
		if got != "resumed" {
			t.Fatalf("result=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("result not delivered")
	}
	_ = remote.Close()
	select {
	case <-m.dead:
	case <-time.After(time.Second):
		t.Fatal("mux did not stop")
	}
}

func TestStepUpResultExpiresWithoutAnotherTrigger(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	owner := stepUpOwner{PID: 7, Session: 2, SID: "S-1-5-21-100-200-300-1001", LogonID: 19}
	clock := &fakeClock{t: time.Now()}
	c := newStepUpCoordinator(time.Minute, nil, nil)
	c.now = clock.now
	c.launchForOwner = func(string, string, stepUpOwner) {}
	if !c.TriggerForOwner("app:22", "https://portal.example/clientless/auth/start?request_id="+id, owner) {
		t.Fatal("request not admitted")
	}
	clock.add(10 * time.Minute)
	if c.HandleResultForOwner("app:22", id, "resumed", owner) {
		t.Fatal("expired result accepted")
	}
}

func TestStepUpRequeryKeepsOriginalLoginAndConsumesOnce(t *testing.T) {
	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	owner := stepUpOwner{PID: 7, Session: 2, SID: "S-1-5-21-100-200-300-1001", LogonID: 19}
	notified := make(chan string, 1)
	c := newStepUpCoordinator(time.Minute, nil, nil)
	c.launchForOwner = func(string, string, stepUpOwner) {}
	c.resultForOwner = func(result string, got stepUpOwner) {
		if got != owner {
			t.Errorf("result delivered to another login: %+v", got)
		}
		notified <- result
	}
	if !c.TriggerForOwner("app:22", "https://portal.example/clientless/auth/start?request_id="+id, owner) {
		t.Fatal("trigger")
	}
	queries := c.pendingResultQueries()
	if len(queries) != 1 || queries[0].RequestID != id || queries[0].Principal != owner.authPrincipal() || queries[0].Session != owner.authSession() {
		t.Fatalf("requery binding = %+v", queries)
	}
	if c.HandleQueriedResult("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "resumed") ||
		!c.HandleQueriedResult(id, "not_resumed") || c.HandleQueriedResult(id, "resumed") {
		t.Fatal("untracked or duplicate requery result accepted")
	}
	select {
	case got := <-notified:
		if got != "not_resumed" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("missing result")
	}
	if len(c.pendingResultQueries()) != 0 {
		t.Fatal("final request still pending")
	}
}

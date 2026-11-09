package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// The doors this walks are the operator's decision: the first one is where this connector is meant to live.
func TestADoorListKnowsWhereHomeIs(t *testing.T) {
	doors := parseConnectorEndpoints("region-b=https://b.example;region-a=https://a.example")
	if !doors.atPreferred() {
		t.Fatal("a connector starts at the door the operator put first")
	}
	home, region := doors.preferred()
	if home != "https://b.example" || region != "region-b" {
		t.Fatalf("preferred: got %q %q", home, region)
	}

	doors.advance(errConnectorNodeAlreadyHeld)
	if doors.atPreferred() {
		t.Fatal("after failing over it is not at its preferred door — which is the state that must be noticed")
	}
	// Preferred does not move with the connector: it is where it should be, not where it is.
	if home, _ := doors.preferred(); home != "https://b.example" {
		t.Fatalf("preferred moved with the connector: %q", home)
	}

	doors.resetToPreferred()
	if !doors.atPreferred() {
		t.Fatal("going home means being at the first door again")
	}
}

// ★ A single-door connector has no home to go to and no failover to notice — nothing here may fire for it.
func TestASingleDoorConnectorIsAlwaysHome(t *testing.T) {
	doors := parseConnectorEndpoints("region-a=https://a.example")
	if !doors.atPreferred() {
		t.Fatal("one door is always the preferred one")
	}
	doors.advance(errConnectorNodeAlreadyHeld)
	if !doors.atPreferred() {
		t.Fatal("a connector with one door never leaves it, so it is never away from home")
	}
}

// Letting go of everything is what makes the workers re-dial; without it a working tunnel holds the connector
// in the region it failed over to for ever.
func TestLettingGoOfEverythingEndsEveryAttachment(t *testing.T) {
	a := newConnectorFleetAttachments()
	ended := map[string]bool{}
	_, _ = a.claim("a-1", "region-a", func() { ended["a-1"] = true })
	_, _ = a.claim("a-2", "region-a", func() { ended["a-2"] = true })

	letGo := a.letGoOfEverything()
	if len(letGo) != 2 || letGo[0] != "a-1" || letGo[1] != "a-2" {
		t.Fatalf("expected both attachments named, got %v", letGo)
	}
	if !ended["a-1"] || !ended["a-2"] {
		t.Fatalf("naming them is not ending them: %v", ended)
	}

	// Holding nothing is not an error, and says nothing.
	empty := newConnectorFleetAttachments()
	if letGo := empty.letGoOfEverything(); len(letGo) != 0 {
		t.Fatalf("expected nothing, got %v", letGo)
	}
}

// ★★★ LETTING GO HAS TO END THE TUNNEL, NOT ASK IT TO STOP — AND THIS TESTS THE CALL SITE. A worker sits in
// a blocking read on the websocket; a context cannot interrupt that. Measured live: the connector announced it
// was going home, "let go" of both attachments, and was still holding them — still naming the nodes of the
// region it had left — two minutes later. A test of a hand-written letGo would have passed throughout, so this
// runs the real connectTunnelOnce against a fake Edge and asserts it RETURNS when let go.
func TestLettingGoEndsTheRealTunnelWorker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := tunnel.UpgradeWithHeaders(w, r, http.Header{tunnel.EdgeNodeHeader: []string{"edge-a"}})
		if err != nil {
			return
		}
		defer conn.Close()
		// The Edge says nothing: the connector's worker blocks in its read, which is the case that matters.
		var frame tunnel.Frame
		for conn.ReadJSON(&frame) == nil {
		}
	}))
	defer server.Close()

	attachments := newConnectorFleetAttachments()
	done := make(chan error, 1)
	go func() {
		_, _, err := connectTunnelOnce(context.Background(), server.URL, "region-a", "conn-1", "secret",
			"http://127.0.0.1:1", nil, connectorTCPNetDialer{}, nil, attachments)
		done <- err
	}()

	deadline := time.After(10 * time.Second)
	for {
		if len(attachments.nodes()) > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the worker returned before attaching: %v", err)
		case <-deadline:
			t.Fatal("the worker never attached to the fake Edge")
		case <-time.After(20 * time.Millisecond):
		}
	}

	attachments.letGoOfEverything()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("letting go did not end the worker — it is still blocked in its read, so the tunnel is held " +
			"until the far side or the OS notices, and the cutover has no length this deployment decides")
	}
	if held := attachments.nodes(); len(held) != 0 {
		t.Fatalf("the attachment was not released: %v", held)
	}
}

// ★★★ GOING HOME REDIALS AT ONCE (2026-11-07, measured on 0.4.1 acceptance B). Every worker used to pause two
// seconds after letting go — the pause meant for a door that just failed — so for two seconds a connector that
// had just watched its home door answer three checks in a row was attached nowhere, and everything behind it was
// unreachable from every Region. This runs the real tunnel loop against two fake Edges and measures from the
// decision to the new tunnel arriving at home.
func TestGoingHomeRedialsTheHomeDoorWithoutPausing(t *testing.T) {
	fakeEdge := func(node string, arrived chan<- time.Time) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := tunnel.UpgradeWithHeaders(w, r, http.Header{tunnel.EdgeNodeHeader: []string{node}})
			if err != nil {
				return
			}
			defer conn.Close()
			select {
			case arrived <- time.Now():
			default:
			}
			var frame tunnel.Frame
			for conn.ReadJSON(&frame) == nil {
			}
		}))
	}
	homeArrived := make(chan time.Time, 8)
	awayArrived := make(chan time.Time, 8)
	home := fakeEdge("edge-home", homeArrived)
	defer home.Close()
	away := fakeEdge("edge-away", awayArrived)
	defer away.Close()

	doors := parseConnectorEndpoints("region-a=" + home.URL + ";region-b=" + away.URL)
	doors.advance(errors.New("region-a is down, as it was during the outage"))
	if doors.atPreferred() {
		t.Fatal("the connector did not start away from home")
	}
	attachments := newConnectorFleetAttachments()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go connectTunnelLoop(ctx, doors, attachments, true, "conn-1", "secret", "http://127.0.0.1:1", nil,
		connectorTCPNetDialer{}, nil)

	select {
	case <-awayArrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the connector never attached to the door it failed over to")
	}
	for len(attachments.nodes()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// What watchForHome does once home has answered enough checks.
	decided := time.Now()
	if !doors.resetToPreferred() {
		t.Fatal("going home did not count as crossing a Region")
	}
	attachments.letGoOfEverything()

	select {
	case at := <-homeArrived:
		if gap := at.Sub(decided); gap > time.Second {
			t.Fatalf("the connector reached home %s after deciding to go — attached nowhere for that long, for a "+
				"door it had just proved", gap.Round(time.Millisecond))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the connector never reached home")
	}
}

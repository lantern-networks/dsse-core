package main

import (
	"context"
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

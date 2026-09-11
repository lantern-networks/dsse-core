package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// ★ The refusal has to be decided from the REQUEST, before anything is registered — the tunnel manager keeps
// one session per connector and closes the one it replaces, so upgrading first would kill the tunnel the
// probe is asking about.
func TestANodeTheConnectorAlreadyHoldsIsRefusedFromTheRequest(t *testing.T) {
	req := func(values ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/connectors/conn-1/tunnel", nil)
		for _, v := range values {
			r.Header.Add(tunnel.ConnectorHoldsHeader, v)
		}
		return r
	}

	if !connectorAlreadyHoldsThisNode(req("edge-a,edge-b"), "edge-b") {
		t.Fatal("a node named in the declaration must refuse")
	}
	if !connectorAlreadyHoldsThisNode(req(" edge-a , edge-b "), "edge-a") {
		t.Fatal("whitespace around a name must not hide it")
	}
	if !connectorAlreadyHoldsThisNode(req("edge-a", "edge-b"), "edge-b") {
		t.Fatal("a declaration split across repeated headers must still be read")
	}
	if connectorAlreadyHoldsThisNode(req("edge-a,edge-b"), "edge-c") {
		t.Fatal("a node NOT named must accept — this is how the rest of the fleet gets covered")
	}

	// ★ A connector that declares nothing is never refused: an older connector sends no declaration, and one
	// that has just restarted holds nothing. Refusing either would leave it with no tunnel at all.
	if connectorAlreadyHoldsThisNode(req(), "edge-a") {
		t.Fatal("an undeclared connector must connect normally")
	}
	if connectorAlreadyHoldsThisNode(req(""), "edge-a") {
		t.Fatal("an empty declaration must connect normally")
	}
	// And a node with no name of its own can never match a declaration.
	if connectorAlreadyHoldsThisNode(req("edge-a"), "") {
		t.Fatal("an unnamed node must not refuse anybody")
	}
}

// ★ A denominator that is not known must never be sent. A count of zero would let a connector conclude it
// covers a fleet of none — the exact inversion of what this number exists to reveal.
func TestTheHandshakeSendsAFleetSizeOnlyWhenItIsKnown(t *testing.T) {
	if got := connectorTunnelHandshakeHeaders("edge-a", 0, false).Get(tunnel.EdgeFleetNodesHeader); got != "" {
		t.Fatalf("an unknown fleet size must not be advertised, got %q", got)
	}
	if got := connectorTunnelHandshakeHeaders("edge-a", -1, false).Get(tunnel.EdgeFleetNodesHeader); got != "" {
		t.Fatalf("a negative fleet size must not be advertised, got %q", got)
	}
	h := connectorTunnelHandshakeHeaders("edge-a", 2, false)
	if got := h.Get(tunnel.EdgeFleetNodesHeader); got != "2" {
		t.Fatalf("fleet size: got %q", got)
	}
	if got := h.Get(connectorReachedNodeHeader); got != "edge-a" {
		t.Fatalf("the node still names itself: got %q", got)
	}
	// An Edge with neither fact sends no handshake headers at all rather than empty ones.
	if h := connectorTunnelHandshakeHeaders("", 0, false); h != nil {
		t.Fatalf("expected no headers, got %v", h)
	}
}

// ★ THE NODE SAYS IT ONLY WHEN IT IS TRUE. A connector that is not told assumes the others do not relay, which
// is what its warning is right about on a deployment whose Edges cannot reach each other.
func TestTheNodeSaysWhetherItsSiblingsRelay(t *testing.T) {
	if h := connectorTunnelHandshakeHeaders("node-1", 2, false); h.Get("X-Dsse-Edge-Siblings-Relay") != "" {
		t.Fatal("a node that cannot promise the relay must not claim it")
	}
	if h := connectorTunnelHandshakeHeaders("node-1", 2, true); h.Get("X-Dsse-Edge-Siblings-Relay") != "true" {
		t.Fatal("a node whose region relays must say so, or the connector warns about a hole that is closed")
	}
}

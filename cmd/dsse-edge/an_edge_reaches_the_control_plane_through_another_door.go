package main

// an_edge_reaches_the_control_plane_through_another_door.go — the Edge's way to the control plane does not end
// at the door on its own machine.
//
// ★★★ THE EDGE BESIDE A STOPPED DOOR LOST THE CONTROL PLANE (2026-11-08, acceptance C, third walk). The
// leader's entrance was stopped; its Edge resolved admin.<region>.<host> and authority.<region>.<host> to that
// entrance, and for six minutes it could not check an administrator's session, pull configuration or
// revocations, or ship audit: "no in-boundary CP reachable — denying egress". The Console had already moved to
// another door, so every screen that asked this Edge directly — the Internet access rules, for one — waited
// about 25 seconds and got 401. The control plane, two other doors and the Edge itself were all fine.
//
// The installer names this machine's door (DSSE_EDGE_LOCAL_DOORS, the front door's fixed address) and the
// other machines' doors (DSSE_EDGE_DOOR_FALLBACKS). Only a dial to this machine's door can take the detour;
// everything else this Edge dials — identity providers, connectors, the Internet — is dialled as it is. See
// frontdoor.Dialer for why the TLS name and certificate check stay those of the URL.

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	frontdoor "github.com/lantern-networks/dsse-core/frontdoor"
)

const (
	edgeDoorFallbacksEnv = "DSSE_EDGE_DOOR_FALLBACKS"
	edgeLocalDoorsEnv    = "DSSE_EDGE_LOCAL_DOORS"
)

var edgeDoors atomic.Pointer[frontdoor.Dialer]

var edgeDirectDialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// edgeDial is the DialContext of every connection this Edge makes to the control plane.
func edgeDial(ctx context.Context, network, address string) (net.Conn, error) {
	if d := edgeDoors.Load(); d != nil {
		return d.DialContext(ctx, network, address)
	}
	return edgeDirectDialer.DialContext(ctx, network, address)
}

// edgeTransport is an http.Transport for the control plane that may leave through another door.
func edgeTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{TLSClientConfig: tlsCfg, DialContext: edgeDial}
}

// installEdgeDoors reads the two settings once, at start. An unreadable list stops the Edge: a list the
// operator wrote and the Edge silently ignored is the outage it exists to prevent. The default transport gets
// the same dial, so a client that does not build its own is covered too; with DSSE_EDGE_LOCAL_DOORS set, only
// dials to this machine's door are ever affected.
func installEdgeDoors(fallbacks, local string) {
	d, err := frontdoor.Parse(fallbacks, edgeDoorFallbacksEnv)
	if err != nil {
		log.Fatal(err)
	}
	if d == nil {
		return
	}
	if strings.TrimSpace(local) == "" {
		log.Fatalf("%s is set and %s is not: without this machine's door named, the Edge cannot tell a dial to it "+
			"from a dial to an identity provider or a connector", edgeDoorFallbacksEnv, edgeLocalDoorsEnv)
	}
	if err := d.OnlyFor(local, edgeLocalDoorsEnv); err != nil {
		log.Fatal(err)
	}
	d.Who = "this Edge"
	edgeDoors.Store(d)
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.DialContext = edgeDial
	}
	log.Printf("front door: when this machine's door (%s) does not answer, this Edge reaches the control plane through %s",
		strings.TrimSpace(local), strings.Join(d.Fallbacks(), ", "))
}

func installEdgeDoorsFromEnvironment() {
	installEdgeDoors(os.Getenv(edgeDoorFallbacksEnv), os.Getenv(edgeLocalDoorsEnv))
}

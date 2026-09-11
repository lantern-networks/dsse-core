package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeEdge401 starts a loopback listener that answers a single steered CONNECT with a 401 + the given
// step-up header, mimicking the Edge's "authenticate" deny for a native flow with no live grant. Returns the
// host:port to point edgeURL at, and a stop func.
func fakeEdge401(t *testing.T, stepUpURL string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				// Drain the CONNECT request (request line + headers up to the blank line) before replying.
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				body := `{"decision":"authenticate"}`
				fmt.Fprintf(conn, "HTTP/1.1 401 Unauthorized\r\n%s: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
					stepUpChallengeHeader, stepUpURL, len(body), body)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// TestHandleFlow_TriggersStepUpOn401 exercises the full wire path (minus WFP capture): a real CONNECT over a
// real socket to a fake Edge that denies with 401 + X-Dsse-Stepup-Url must drive handleFlow -> the step-up
// coordinator with the recovered original destination as the resource and the Edge-issued portal URL.
func TestHandleFlow_TriggersStepUpOn401(t *testing.T) {
	const portal = "https://edge:8443/clientless/auth/start?return_to=10.0.0.7%3A445&idp=corp&acr=phishing_resistant"
	addr, stop := fakeEdge401(t, portal)
	defer stop()

	launched := make(chan [2]string, 1)
	coord := newStepUpCoordinator(30*time.Second, func(resource, url string) {
		launched <- [2]string{resource, url}
	}, nil)

	s := edgeSteerer{cfg: edgeConfig{
		edgeURL:      "http://" + addr,
		genericSteer: true,
		stepUp:       coord,
	}}

	// The app side of the captured flow; handleFlow closes it on the (denied) 401 path.
	appConn, other := net.Pipe()
	defer other.Close()
	origDst := netip.MustParseAddrPort("10.0.0.7:445")
	go s.handleFlow(SteeredFlow{OrigDst: origDst, Conn: appConn})

	select {
	case got := <-launched:
		if got[0] != origDst.String() {
			t.Fatalf("step-up resource = %q, want %q", got[0], origDst.String())
		}
		if got[1] != portal {
			t.Fatalf("step-up portal url = %q, want %q", got[1], portal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("step-up was not triggered on a 401 + X-Dsse-Stepup-Url")
	}
}

// TestHandleFlow_NoStepUpHeaderNoTrigger confirms an authenticate-shaped deny that carries NO portal header
// (e.g. the gate disabled / no broker) does not call the launcher -- the flow is simply denied (fail-closed).
func TestHandleFlow_NoStepUpHeaderNoTrigger(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "" {
						break
					}
				}
				fmt.Fprint(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()

	var launched int32
	done := make(chan struct{})
	coord := newStepUpCoordinator(30*time.Second, func(string, string) {
		launched = 1
		close(done)
	}, nil)
	s := edgeSteerer{cfg: edgeConfig{edgeURL: "http://" + ln.Addr().String(), genericSteer: true, stepUp: coord}}
	appConn, other := net.Pipe()
	defer other.Close()
	s.handleFlow(SteeredFlow{OrigDst: netip.MustParseAddrPort("10.0.0.7:445"), Conn: appConn})

	select {
	case <-done:
		t.Fatal("launcher must not fire on a 401 with no step-up header")
	case <-time.After(300 * time.Millisecond):
		// expected: no trigger
	}
	if launched != 0 {
		t.Fatal("launcher fired unexpectedly")
	}
}

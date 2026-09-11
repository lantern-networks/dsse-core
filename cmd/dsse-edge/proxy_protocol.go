package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// proxy_protocol.go — recovering the device's address from behind an L4 front door.
//
// ★★★ THE FRONT DOOR MUST BE L4, AND THAT COSTS THE SOURCE ADDRESS. A device's transport is mTLS and its
// identity comes from the verified client certificate, so a layer-7 load balancer that terminates TLS
// destroys the identity every decision rests on — what reaches the Edge is then "the balancer said so". The
// front door therefore passes TCP through untouched.
//
// The cost is that every connection arrives from the front door. The rate limiter's own flag says what that
// does: "so clients behind a LB don't all collapse to the LB's IP". Without something, every device shares
// one bucket, and one noisy device throttles the fleet.
//
// ★ X-Forwarded-For IS NOT AVAILABLE HERE. That is an HTTP header, and the transport plane is not HTTP. The
// PROXY protocol is the equivalent one layer down: the front door states the original address before the
// first byte of TLS, and the connection continues untouched.
//
// ★★★ AND IT IS ACCEPTED ONLY FROM DECLARED ADDRESSES. A listener that lets anyone announce their own source
// address is worse than one that loses it: an attacker would choose an address, and every per-address
// decision — rate limiting, and anything that follows it — would be theirs to set. Empty means the header is
// never read, which is the safe default and what a deployment without a front door wants.

// proxyProtocolV1MaxLine is the specification's limit for a v1 header, including CRLF.
const proxyProtocolV1MaxLine = 107

// proxyProtocolHeaderTimeout bounds how long a connection may take to state its origin. A front door writes
// the header immediately; anything slower is either not a front door or is not well.
const proxyProtocolHeaderTimeout = 5 * time.Second

// proxyProtocolListener reads a PROXY v1 header from connections that arrive from a trusted front door, and
// reports the address the header names as the connection's remote address.
type proxyProtocolListener struct {
	net.Listener
	trusted []*net.IPNet
}

// newProxyProtocolListener wraps ln. With no trusted addresses it returns ln unchanged: not "accept from
// anyone", which would be the dangerous reading of an empty list.
func newProxyProtocolListener(ln net.Listener, trusted []*net.IPNet) net.Listener {
	if len(trusted) == 0 {
		return ln
	}
	return &proxyProtocolListener{Listener: ln, trusted: trusted}
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.trustedRemote(conn.RemoteAddr()) {
		// Not the front door: the connection is whatever it is, and any PROXY header in it is just bytes that
		// will fail to be a TLS ClientHello — which is the correct outcome for someone trying to declare an
		// address they were not asked for.
		return conn, nil
	}
	return proxyProtocolConn(conn)
}

func (l *proxyProtocolListener) trustedRemote(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range l.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// proxyProtocolConn reads the header and returns a connection that reports the declared address. A connection
// from a trusted front door that does NOT begin with a header keeps its own address and loses nothing: the
// bytes read are replayed, the same way the ClientHello peek does it.
func proxyProtocolConn(conn net.Conn) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(proxyProtocolHeaderTimeout))
	r := bufio.NewReaderSize(conn, proxyProtocolV1MaxLine)
	prefix, err := r.Peek(6)
	if err != nil || string(prefix) != "PROXY " {
		_ = conn.SetReadDeadline(time.Time{})
		return &bufferedConn{Conn: conn, r: r}, nil
	}
	line, err := r.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || len(line) > proxyProtocolV1MaxLine {
		// A trusted peer that begins a header and does not finish one is a fault worth failing on: continuing
		// would serve a connection whose first bytes were consumed as something they were not.
		_ = conn.Close()
		return nil, fmt.Errorf("proxy protocol: malformed header from %s", conn.RemoteAddr())
	}
	declared := parseProxyProtocolV1(strings.TrimRight(line, "\r\n"))
	if declared == nil {
		// "PROXY UNKNOWN" is the front door saying it does not know either. The connection is served; the
		// address stays the front door's, which is honest rather than invented.
		return &bufferedConn{Conn: conn, r: r}, nil
	}
	return &bufferedConn{Conn: conn, r: r, remote: declared}, nil
}

// parseProxyProtocolV1 returns the address the header names, or nil for UNKNOWN or anything malformed.
func parseProxyProtocolV1(line string) net.Addr {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "PROXY" {
		return nil
	}
	switch f[1] {
	case "TCP4", "TCP6":
	default:
		return nil // UNKNOWN, or a family this does not speak
	}
	if len(f) != 6 {
		return nil
	}
	ip := net.ParseIP(f[2])
	port, err := strconv.Atoi(f[4])
	if ip == nil || err != nil || port < 0 || port > 65535 {
		return nil
	}
	return &net.TCPAddr{IP: ip, Port: port}
}

// bufferedConn serves the bytes already read before the rest of the connection, and reports the declared
// remote address when there is one.
type bufferedConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// parseTrustedFrontDoors turns the flag's value into networks. A bare address becomes a /32 or /128.
func parseTrustedFrontDoors(raw string) []*net.IPNet {
	out := []*net.IPNet{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			out = append(out, n)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

// agentPlaneFrontDoors is the trusted set for the AGENT-FACING door of the main listener. It is a package
// variable for the same reason the node's own region id is: it is decided once at startup and read by a
// function whose signature already carries everything else about how to serve.
var agentPlaneFrontDoors []*net.IPNet

func setTrustedFrontDoors(nets []*net.IPNet) { agentPlaneFrontDoors = nets }

// wrapAgentPlaneListener reads the PROXY header on the door devices arrive at, and on no other.
//
// ★★★ WHICH DOOR THIS IS COST A WALK (2026-08-24, found by running it). The PROXY header was accepted on the
// secure transport listener only — and the generated deployment does not use it: devices enrol and steer on
// the MAIN listener's agent-facing door. So the front door sent a header nobody consumed, TLS read "PROXY
// TCP4 ..." as a ClientHello, and every device got EOF. The unit tests were green the whole time, because
// they exercised the parser and not the door the deployment actually opens.
//
// ★★ AND NOT THE ADMIN DOOR, DELIBERATELY. Nothing fronts the admin surface — it is answered per node,
// because per-node observation is what it is for. Accepting a PROXY header there would let anyone who can
// reach it name the address that lands in the audit log, which is the one place a wrong address is a lie
// rather than a degradation.
func wrapAgentPlaneListener(ln net.Listener, door string) net.Listener {
	if door != "agent-plane" {
		return ln
	}
	return newProxyProtocolListener(ln, agentPlaneFrontDoors)
}

// trustedFrontDoorsFlag names the front door(s) whose PROXY header this Edge believes.
//
// ★ IT LIVES HERE AND NOT IN main.go, because a ratchet says new flags do. The rule is worth keeping: a
// flag beside the code that reads it is a flag whose meaning can be checked without leaving the file.
var trustedFrontDoorsFlag = flag.String("trusted-front-doors", "", "comma-separated IPs or CIDRs of the L4 front door(s) in front of this region's Edges. A connection FROM one of these may state the device's original address with a PROXY protocol v1 header, and that address is what every per-address decision uses. Empty = no PROXY header is read from anyone (correct with no front door; never means 'trust anyone')")

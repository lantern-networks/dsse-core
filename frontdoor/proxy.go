package frontdoor

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Package frontdoor recovers a client's address from behind the deployment's L4 front door, for every
// listener that stands behind it (the Edge's agent door and the Admin Console), and bounds how fast one
// address may try a door.
//
// proxy.go — recovering the client's address from behind an L4 front door.
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

// ProxyProtocolV1MaxLine is the specification's limit for a v1 header, including CRLF.
const ProxyProtocolV1MaxLine = 107

// ProxyProtocolHeaderTimeout bounds how long a connection may take to state its origin. A front door writes
// the header immediately; anything slower is either not a front door or is not well.
const ProxyProtocolHeaderTimeout = 5 * time.Second

// proxyProtocolListener reads a PROXY v1 header from connections that arrive from a trusted front door, and
// reports the address the header names as the connection's remote address.
type proxyProtocolListener struct {
	net.Listener
	trusted []*net.IPNet
}

// newProxyProtocolListener wraps ln. With no trusted addresses it returns ln unchanged: not "accept from
// anyone", which would be the dangerous reading of an empty list.
func NewProxyProtocolListener(ln net.Listener, trusted []*net.IPNet) net.Listener {
	if len(trusted) == 0 {
		return ln
	}
	return &proxyProtocolListener{Listener: ln, trusted: trusted}
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.trustedRemote(conn.RemoteAddr()) {
			// An untrusted peer's PROXY header remains ordinary payload: it cannot
			// choose a source address and will fail the TLS handshake.
			return conn, nil
		}
		wrapped, err := ProxyProtocolConn(conn)
		if err == nil {
			return wrapped, nil
		}
		// A malformed connection is not a listener failure. Returning its parse
		// error makes http.Server.Serve close the entire agent-facing listener.
		_ = conn.Close()
	}
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
func ProxyProtocolConn(conn net.Conn) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(ProxyProtocolHeaderTimeout))
	r := bufio.NewReaderSize(conn, ProxyProtocolV1MaxLine)
	prefix, err := r.Peek(6)
	if err != nil || string(prefix) != "PROXY " {
		_ = conn.SetReadDeadline(time.Time{})
		return &bufferedConn{Conn: conn, r: r}, nil
	}
	// ReadString grows until a newline. ReadSlice bounds parsing to the v1
	// header buffer and rejects a peer that fills it without terminating.
	line, err := r.ReadSlice('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || len(line) > ProxyProtocolV1MaxLine {
		// A trusted peer that begins a header and does not finish one is a fault worth failing on: continuing
		// would serve a connection whose first bytes were consumed as something they were not.
		_ = conn.Close()
		return nil, fmt.Errorf("proxy protocol: malformed header from %s", conn.RemoteAddr())
	}
	declared := ParseProxyProtocolV1(strings.TrimRight(string(line), "\r\n"))
	if declared == nil {
		// "PROXY UNKNOWN" is the front door saying it does not know either. The connection is served; the
		// address stays the front door's, which is honest rather than invented.
		return &bufferedConn{Conn: conn, r: r}, nil
	}
	return &bufferedConn{Conn: conn, r: r, remote: declared}, nil
}

// parseProxyProtocolV1 returns the address the header names, or nil for UNKNOWN or anything malformed.
func ParseProxyProtocolV1(line string) net.Addr {
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

// ParseTrustedNets turns a comma-separated list of addresses and CIDRs into networks. A bare address becomes
// a /32 or /128; anything unparsable is dropped, never widened.
func ParseTrustedNets(raw string) []*net.IPNet {
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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// dnsProxy is the Windows half of  requirement ② (DNS steering): a local DNS proxy that forwards
// every query to the Edge resolver as application/dns-message (DoH/RFC8484 shape) over the (T) encrypted
// transport. Pointing the system resolver at this proxy (127.0.0.1:53) means domain names never leave the
// endpoint as plaintext UDP -- only the Edge sees and resolves them. Mirrors the macOS NE localhost DNS
// proxy approach.
type dnsProxy struct {
	queryURL string       // {transport-or-edge}/steer/dns-query
	client   *http.Client // dials over the (T) pinned mTLS tunnel when transport is enabled
	cache    *dnsCache    // TTL-respecting answer cache — removes repeat round-trips over the tunnel

	// fail-open posture (--fail-open): when the Edge is unreachable, forward queries to the captured upstream
	// resolver(s) directly instead of failing, so name resolution keeps working during a control-plane outage.
	// This LEAKS plaintext DNS to the LAN/ISP for the outage window — the explicit availability-over-security
	// tradeoff the operator chose at install time. fallback is the upstream server list (e.g. 192.0.2.1);
	// health is the shared circuit breaker so a sustained outage skips the Edge round-trip entirely.
	failOpen bool
	fallback []string
	// publicFallback is an OPTIONAL, operator-configured set of network-independent resolvers appended to the
	// fail-open path as a last resort (e.g. for a Wi-Fi roam where the captured pre-steer upstream is unreachable).
	// It defaults to EMPTY: the fail-open path uses the captured PRE-STEER upstream (fallback) only, so the client
	// never silently races DNS to an undisclosed third party. An operator who wants a public last resort sets it
	// explicitly (see PublicResolverDefaults for a common choice). (Fail-open review #26.)
	publicFallback []string
	health         *edgeHealth
	// answerNCSI answers the Windows NCSI DNS probe (dns.msftncsi.com) locally so the OS reliably detects
	// "Internet" under steer-all instead of timing out through the tunnel. See ncsi_answer.go.
	answerNCSI bool
}

// newDNSProxy builds the forwarder. With the (T) transport on, DNS rides the same pinned mTLS tunnel as the
// steered flows; otherwise (lab) it posts to the plaintext edge. Either way the query is the raw DNS wire
// message and the response is the raw DNS wire reply.
func newDNSProxy(tc transportConfig, edgeURL string, failOpen bool, health *edgeHealth) *dnsProxy {
	p := &dnsProxy{cache: newDNSCache(), failOpen: failOpen, health: health}
	if tc.enabled {
		p.queryURL = "https://" + tc.host + "/steer/dns-query"
		p.client = &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tc.dial(8 * time.Second)
				},
				// This proxy carries EVERY DNS lookup on the box, and a browser opening a page fires many at
				// once. Go's default MaxIdleConnsPerHost is 2, so everything past the second concurrent query
				// got a connection that was closed rather than pooled — and on this path a new connection is a
				// full mTLS handshake through the (T) tunnel, not a TCP connect. Under load that spends the 8s
				// budget on handshakes and times out, which the circuit breaker then reads as "the Edge is
				// down" while the Edge is in fact serving other clients normally.
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		}
		return p
	}
	p.queryURL = strings.TrimRight(edgeURL, "/") + "/steer/dns-query"
	p.client = &http.Client{Timeout: 8 * time.Second}
	return p
}

// setFallback records the upstream resolver(s) used by the fail-open path. Captured from the pre-takeover DNS
// snapshot (the real servers the box used before we repointed it at the loopback proxy).
func (p *dnsProxy) setFallback(servers []string) { p.fallback = servers }

// setPublicFallback records the OPTIONAL operator-configured network-independent last-resort resolvers. Empty
// (the default) = none, so the fail-open path uses only the captured pre-steer upstream. (Fail-open review #26.)
func (p *dnsProxy) setPublicFallback(servers []string) { p.publicFallback = servers }

// setAnswerNCSI toggles local answering of the Windows NCSI DNS probe (dns.msftncsi.com).
func (p *dnsProxy) setAnswerNCSI(on bool) { p.answerNCSI = on }

// resolve returns the raw DNS response for query — from the TTL-respecting cache when warm, otherwise by
// posting it to the Edge over the tunnel and caching the answer. Caching removes the repeat tunnel round-trips
// that otherwise dominate a real page's DNS (and fail as ERR_NAME_NOT_RESOLVED under the 8s timeout).
//
// In --fail-open mode an Edge transport failure does not fail the query: it forwards to the captured upstream
// resolver instead (and the shared circuit breaker short-circuits the Edge round-trip during a sustained
// outage). A healthy Edge that simply returns a non-200 is NOT a transport failure and is surfaced as an error.
func (p *dnsProxy) resolve(query []byte) ([]byte, error) {
	// NCSI DNS probe (dns.msftncsi.com): answer locally + instantly so Windows connectivity detection doesn't
	// depend on a tunnel round-trip (which it times out -> "No Internet"). Microsoft's fixed probe value.
	if p.answerNCSI {
		if reply, ok := ncsiDNSReply(query); ok {
			return reply, nil
		}
	}
	if p.cache != nil {
		if cached, ok := p.cache.get(query); ok {
			return cached, nil
		}
	}
	// Circuit already open from a recent outage: skip the Edge, go straight upstream.
	if p.failOpen && !p.health.shouldTryEdge() {
		return p.forwardUpstream(query)
	}
	out, err := p.queryEdge(query)
	if err != nil {
		if p.failOpen {
			var statusErr *edgeDNSStatusError
			if errors.As(err, &statusErr) {
				// A bad ANSWER, not an outage. Resolve this one upstream, but leave the circuit closed so
				// enforcement stays on for every TCP flow. Name the question: without it these are just a
				// count, and the Edge-side cause cannot be correlated to what was being looked up.
				p.health.recordSuccess()
				q, ok := dnsQuestionKey(query)
				if !ok {
					q = "unparsed-question"
				}
				fmt.Printf("dns_edge_status: %v question=%s — answered upstream; the Edge answered, so the circuit stays CLOSED (enforcement unaffected)\n", err, q)
			} else if opened := p.health.recordFailure(); opened {
				fmt.Printf("dns_failopen: edge unreachable (%v) — circuit OPEN, forwarding DNS upstream for the cooldown (plaintext DNS leaves the box)\n", err)
			}
			return p.forwardUpstream(query)
		}
		return nil, err
	}
	p.health.recordSuccess()
	if p.cache != nil {
		p.cache.put(query, out)
	}
	return out, nil
}

// queryEdge posts the raw DNS query to the Edge resolver over the (T) tunnel and returns the raw reply.
// edgeDNSStatusError is a non-200 ANSWER from the Edge's resolver. It means this lookup failed, not that the
// Edge is down: a 502 here is the Edge telling us its own upstream resolution failed. Conflating the two made
// a DNS problem open the shared circuit breaker, which drops EVERY TCP flow to unmediated egress — measured on
// win-dev-1 as 220 fail-open engagements, 28 of them from exactly this status path, while the Edge was serving
// the macOS client normally throughout.
type edgeDNSStatusError struct{ status int }

func (e *edgeDNSStatusError) Error() string {
	return fmt.Sprintf("edge /steer/dns-query status %d", e.status)
}

func (p *dnsProxy) queryEdge(query []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, p.queryURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain before returning. Closing a body that still has unread bytes makes Go throw the connection
		// away instead of pooling it, so a burst of 502s would cost one fresh mTLS handshake per query — the
		// Edge answering badly must not also cost us the connection.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65535))
		// The Edge ANSWERED. This query failed, but the Edge is demonstrably reachable — which is exactly what
		// edgeHealth documents as success ("any response from it, including a policy deny"). Typed so the
		// caller can tell it apart from a transport failure instead of opening the circuit on it.
		return nil, &edgeDNSStatusError{status: resp.StatusCode}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

// PublicResolverDefaults is a COMMON choice of network-independent public anycast resolvers an operator MAY
// opt into for the fail-open last resort (via setPublicFallback). It is NOT applied by default — see
// dnsProxy.publicFallback — so the client never silently races DNS to an undisclosed third party. (Review #26.)
var PublicResolverDefaults = []string{"8.8.8.8", "1.1.1.1"}

// forwardUpstream forwards the raw DNS wire query to the captured PRE-STEER upstream resolver(s) — and, ONLY if
// the operator configured them, the optional public last-resort resolvers — over UDP:53, returning the FIRST
// reply. This is the fail-open path when the Edge is unreachable. All are queried CONCURRENTLY: the captured set
// can include a now-unreachable resolver (the old network's DNS after a switch), and a serial walk would stall on
// its timeout; racing returns as soon as any reachable resolver answers. By default publicFallback is empty, so
// the fail-open path restores toward the PRE-STEER DNS (the captured upstream) rather than an undisclosed third
// party; if the captured upstream is unreachable (a Wi-Fi roam) the self-disarm/recover path restores automatic
// DNS for the current network. Answers are cached.
func (p *dnsProxy) forwardUpstream(query []byte) ([]byte, error) {
	servers := make([]string, 0, len(p.fallback)+len(p.publicFallback))
	servers = append(servers, p.fallback...)
	servers = append(servers, p.publicFallback...) // operator-configured last resort ONLY (empty by default)
	type result struct {
		resp []byte
		err  error
	}
	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(s string) {
			resp, err := dnsForwardUDP(query, s, 4*time.Second)
			ch <- result{resp, err}
		}(srv)
	}
	var lastErr error
	for i := 0; i < len(servers); i++ {
		r := <-ch
		if r.err == nil {
			if p.cache != nil {
				p.cache.put(query, r.resp)
			}
			return r.resp, nil
		}
		lastErr = r.err
	}
	return nil, fmt.Errorf("fail-open upstream forward failed: %w", lastErr)
}

// dnsForwardUDP sends a raw DNS query datagram to a server (host or host:port; bare host defaults to :53) and
// returns the raw reply.
func dnsForwardUDP(query []byte, server string, timeout time.Duration) ([]byte, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "53")
	}
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// serveUDP forwards each UDP datagram (one DNS query) to the Edge and writes the reply back to the sender.
func (p *dnsProxy) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func(q []byte, addr net.Addr) {
			if resp, err := p.resolve(q); err == nil {
				_, _ = pc.WriteTo(resp, addr)
			} else {
				fmt.Printf("dns_proxy resolve failed: %v\n", err)
			}
		}(q, addr)
	}
}

// serveTCP handles TCP DNS (RFC 1035: 2-byte length prefix on query and response).
func (p *dnsProxy) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handleTCP(c)
	}
}

func (p *dnsProxy) handleTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	var lenbuf [2]byte
	if _, err := io.ReadFull(c, lenbuf[:]); err != nil {
		return
	}
	qlen := int(lenbuf[0])<<8 | int(lenbuf[1])
	if qlen == 0 || qlen > 65535 {
		return
	}
	q := make([]byte, qlen)
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	resp, err := p.resolve(q)
	if err != nil || len(resp) > 65535 {
		return
	}
	out := make([]byte, 2+len(resp))
	out[0] = byte(len(resp) >> 8)
	out[1] = byte(len(resp))
	copy(out[2:], resp)
	_, _ = c.Write(out)
}

// startDNSProxy binds UDP+TCP for the DNS-over-tunnel proxy on BOTH the IPv4 and IPv6 loopback (so DNS over
// either transport is captured — an interface may have an IPv6 resolver that would otherwise bypass an
// IPv4-only proxy and leak). Returns a stop func and the list of loopback addresses actually bound
// (e.g. ["127.0.0.1","::1"]); the caller repoints only those families' resolvers, never one without a live
// listener. A caller that passes a specific non-loopback bind host gets that honored for the IPv4 slot.
func startDNSProxy(listen string, tc transportConfig, edgeURL string, failOpen bool, health *edgeHealth) (func(), []string, *dnsProxy, error) {
	p := newDNSProxy(tc, edgeURL, failOpen, health)
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "", "53"
	}
	targets := []struct{ addr, loop string }{
		{net.JoinHostPort("127.0.0.1", port), "127.0.0.1"},
		{net.JoinHostPort("::1", port), "::1"},
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "127.0.0.1" {
		targets[0] = struct{ addr, loop string }{net.JoinHostPort(host, port), host}
	}
	var closers []func()
	var bound []string
	for _, t := range targets {
		pc, err := net.ListenPacket("udp", t.addr)
		if err != nil {
			fmt.Printf("dns_proxy: udp listen %s skipped: %v\n", t.addr, err)
			continue
		}
		ln, err := net.Listen("tcp", t.addr)
		if err != nil {
			pc.Close()
			fmt.Printf("dns_proxy: tcp listen %s skipped: %v\n", t.addr, err)
			continue
		}
		go p.serveUDP(pc)
		go p.serveTCP(ln)
		closers = append(closers, func() { pc.Close(); ln.Close() })
		bound = append(bound, t.loop)
		fmt.Printf("dns_proxy listening %s -> %s (DNS-over-tunnel)\n", t.addr, p.queryURL)
	}
	if len(bound) == 0 {
		return nil, nil, nil, fmt.Errorf("dns proxy: no listener bound on %s", listen)
	}
	return func() {
		for _, c := range closers {
			c()
		}
	}, bound, p, nil
}

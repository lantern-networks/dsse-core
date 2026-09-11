package swg

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
)

// ssrf_egress_guard.go closes the SWG forward-proxy SSRF gap: the decrypt-and-forward egress path dials a
// caller-controlled destination (the SWG target-URL request header) directly when no connector fronts
// the host. Without a guard, an operator/endpoint could pivot the Edge into internal infrastructure — most
// dangerously the cloud metadata service (169.254.169.254) — or RFC1918 / loopback. The SWG is a forward proxy
// to the public internet by design, so the guard ONLY blocks internal/link-local/loopback/metadata egress;
// public destinations are unaffected, and internal apps are reached via the connector route (not this base
// dialer). Internal apps that legitimately need direct egress should be published behind a connector instead.

// internalBlockEnabled gates the guard. Set at startup from !devMode: OFF in lab (so loopback test
// upstreams keep working), ON in production. A process-level toggle avoids threading a flag through the egress
// dialer wiring (connectorEgressDialContext is shared by several call sites).
var internalBlockEnabled atomic.Bool

// SetInternalBlockEnabled toggles the guard: ON in production, OFF in lab (so loopback test upstreams work).
func SetInternalBlockEnabled(b bool) { internalBlockEnabled.Store(b) }

// EgressControl is a net.Dialer.Control hook. It runs AFTER DNS resolution and BEFORE connect with the
// ACTUAL resolved address, so it also mitigates DNS rebinding (a hostname that resolves public on the policy
// check but internal at dial time is still blocked here). No-op when the guard is disabled.
func EgressControl(_, address string, _ syscall.RawConn) error {
	if !internalBlockEnabled.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf egress guard: malformed dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf egress guard: dial address %q did not resolve to an IP", host)
	}
	if IsBlockedEgressIP(ip) {
		return fmt.Errorf("ssrf egress guard: egress to internal/link-local/loopback/metadata address %s is blocked", ip)
	}
	return nil
}

// GuardDialContext composes the egress guard onto an ARBITRARY DialContext. The Control-hook form
// (EgressControl) only protects dialers explicitly constructed with it, and the production egress paths were
// passing plain dialers — leaving the guard as dead code on the very path it was written for. This wrapper is
// installed unconditionally at the chokepoint (connectorEgressDialContext), so a future base dialer without
// the Control hook is still covered. It enforces AFTER connect (the only point where an opaque dial func
// exposes the resolved peer address, so DNS rebinding is still caught): the connection is closed before any
// bytes are sent, so no request reaches the internal target — only TCP reachability is observable. Prefer
// Control on the dialer where possible; this is defense-in-depth, not a replacement. Same process-level gate
// as EgressControl: no-op in lab.
func GuardDialContext(base func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base(ctx, network, addr)
		if err != nil || !internalBlockEnabled.Load() {
			return conn, err
		}
		if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok && IsBlockedEgressIP(tcp.IP) {
			conn.Close()
			return nil, fmt.Errorf("ssrf egress guard: egress to internal/link-local/loopback/metadata address %s is blocked", tcp.IP)
		}
		return conn, nil
	}
}

// CheckEgressDestination enforces the same internal/link-local/loopback/metadata block as EgressControl on egress
// paths where THIS process does not perform the dial — the browser-faithful egress broker re-originates in another
// process, so neither the Control hook nor the post-connect check can see the peer, and without this the decrypt-all
// egress path would carry no SSRF guard at all. Same process-level gate: no-op in lab.
//
// It is weaker than EgressControl by construction and must not be described as equivalent: the resolution performed
// here is not the one the broker will connect with, so a DNS-rebinding window remains open between this check and
// the broker's own dial. Closing it requires the guard inside the broker.
func CheckEgressDestination(ctx context.Context, host string) error {
	if !internalBlockEnabled.Load() {
		return nil
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("ssrf egress guard: empty destination host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedEgressIP(ip) {
			return fmt.Errorf("ssrf egress guard: egress to internal/link-local/loopback/metadata address %s is blocked", ip)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("ssrf egress guard: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("ssrf egress guard: %q resolved to no addresses", host)
	}
	for _, a := range addrs {
		if IsBlockedEgressIP(a.IP) {
			return fmt.Errorf("ssrf egress guard: %s resolves to internal/link-local/loopback/metadata address %s — blocked", host, a.IP)
		}
	}
	return nil
}

// cgnRange is RFC6598 100.64.0.0/10 (carrier-grade NAT shared address space). Go's IsPrivate does not cover
// it, but on a cloud Edge it is internal fabric address space (e.g. AWS internal load balancers), not public
// internet — an SSRF pivot target like RFC1918.
var cgnRange = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsBlockedEgressIP reports whether ip is an internal target the SWG forward proxy must not reach: loopback,
// link-local (incl. 169.254.169.254 cloud metadata and fe80::/10), private (RFC1918 + ULA fc00::/7),
// carrier-grade NAT (RFC6598), or the unspecified address. Public unicast is allowed (the forward proxy's
// purpose).
func IsBlockedEgressIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16 (incl. metadata) + fe80::/10
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || // 10/8, 172.16/12, 192.168/16, fc00::/7
		cgnRange.Contains(ip) || // 100.64.0.0/10 (RFC6598)
		ip.IsUnspecified()
}

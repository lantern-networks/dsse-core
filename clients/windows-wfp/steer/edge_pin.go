package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Edge endpoint pinning — lets the (T) transport Edge be a HOSTNAME (for availability: DNS-based failover /
// multiple Edge IPs) instead of forcing an IP literal. The problem it solves: under DNS-takeover the system
// resolver is the loopback proxy, which forwards over the very tunnel we are trying to (re)establish — so
// resolving the Edge hostname the normal way deadlocks (and worse, fails during an interface switch when the
// tunnel is down). We instead resolve the hostname OUT OF BAND (a direct resolver that queries real upstream /
// public DNS, never the loopback proxy), pin the resulting IPs, and dial those — while TLS still verifies the
// hostname against the pinned CA, so security is unchanged (dial by IP, verify by name).

// transportHostIsName reports whether the Edge transport host is a DNS name (needs pinning) rather than an IP
// literal (dialable as-is).
func transportHostIsName(tc transportConfig) bool {
	if !tc.enabled || strings.TrimSpace(tc.serverName) == "" {
		return false
	}
	_, err := netip.ParseAddr(tc.serverName)
	return err != nil // parse fails => it's a hostname
}

// newDirectResolver builds a resolver that queries the given DNS servers DIRECTLY over UDP:53, bypassing the
// system resolver (which under takeover is the loopback proxy). Empty/nil servers => public fallback so a
// hostname Edge still resolves on a box whose upstreams we don't know yet. It round-robins the servers.
func newDirectResolver(servers []string) *net.Resolver {
	var clean []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" || s == "127.0.0.1" || s == "::1" {
			continue // never query the loopback proxy here — that is the cycle we are breaking
		}
		clean = append(clean, s)
	}
	clean = append(clean, "8.8.8.8", "1.1.1.1") // public fallback (last resort)
	var idx atomic.Uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			s := clean[int(idx.Add(1))%len(clean)]
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			var d net.Dialer
			return d.DialContext(ctx, "udp", s)
		},
	}
}

// resolveEdgeEndpoints resolves the Edge hostname to "ip:port" pins. When useSystem is true (startup, before DNS
// takeover) it tries the normal system resolver first; otherwise (or on failure) it uses the direct resolver
// over `directServers`. Returns a sorted, deduplicated list so equal results compare equal across refreshes.
func resolveEdgeEndpoints(tc transportConfig, useSystem bool, directServers []string) ([]string, error) {
	host, port, err := net.SplitHostPort(tc.host)
	if err != nil {
		host, port = tc.serverName, "443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var ips []string
	if useSystem {
		if got, e := net.DefaultResolver.LookupHost(ctx, host); e == nil {
			ips = got
		}
	}
	if len(ips) == 0 {
		got, e := newDirectResolver(directServers).LookupHost(ctx, host)
		if e != nil {
			return nil, fmt.Errorf("resolve edge %q: %w", host, e)
		}
		ips = got
	}
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		if a, e := netip.ParseAddr(ip); e == nil {
			s := net.JoinHostPort(a.Unmap().String(), port)
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve edge %q: no usable addresses", host)
	}
	sort.Strings(out)
	return out, nil
}

// refreshEdgePins periodically re-resolves the Edge hostname (via the direct resolver, since the system resolver
// is the loopback proxy once takeover is active) and updates the shared pins — so a hostname Edge picks up
// DNS-based failover / new IPs without a restart. upstreams() supplies the box's real resolvers to prefer.
// onResolved, when non-nil, is called with the first pin on EVERY successful resolution, including the first
// success after a failure at arm time. That is the point of it: the destination loop guard is built from
// this address, and before the callback existed one failed lookup left the guard absent for the life of the
// process while these pins quietly repaired themselves.
func refreshEdgePins(stop <-chan struct{}, tc transportConfig, upstreams func() []string, interval time.Duration, onResolved func(string)) {
	if tc.pins == nil {
		return
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			var up []string
			if upstreams != nil {
				up = upstreams()
			}
			addrs, err := resolveEdgeEndpoints(tc, false, up)
			if err != nil {
				continue // keep the existing pins; transient resolve failure is fine
			}
			prev := tc.pins.Load()
			if prev == nil || !sameStrings(*prev, addrs) {
				tc.pins.Store(&addrs)
				fmt.Printf("steer: Edge %s re-pinned -> %v\n", tc.serverName, addrs)
			}
			// Told on EVERY success, not only on change: the guard may be missing while the address has
			// not moved at all, which is exactly the arm-time-failure case. The receiver decides what is new.
			if onResolved != nil && len(addrs) > 0 {
				onResolved(addrs[0])
			}
		}
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

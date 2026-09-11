//go:build windows

package main

// passthrough_domains_windows.go -- the deployment's own names reach the customer's network untouched.
//
// ★★★ WINDOWS WAS NOT READING THEM (2026-08-31, measured against a rebuilt lab). deployment.passthrough_domains
// carried the Console's three names; macOS honoured them and answered 200; this agent had no reference to the
// field anywhere and answered 502. A steered administrator could not open the Console of the deployment they
// were steering -- and the profile had been right the whole time. Second occurrence in two days of the same
// shape (steer_exclusions was the first): the document is correct, one platform never looks at it.
//
// ★ NAMES ARE RESOLVED AND HELD AS ADDRESSES. A name-shaped exception does not match a client that resolves
// the name itself and connects by address, which is what every browser and every ssh does. The capture
// classifies a flow by its destination, so a passthrough expressed as a name would never fire.
//
// ★ EVERY FAMILY THE NAME ANSWERS WITH IS KEPT. An address-shaped exception stops matching the moment a
// family is added -- the peer session lost both regions for thirty minutes to exactly that, when DNS began
// answering AAAA and an allow-list of v4 literals silently stopped matching.
//
// ★ AND IT SPEAKS EVEN WHEN IT MATCHES NOTHING. An implementation that only reports its hits cannot be told
// apart from one that was never given anything: silence would mean both "this deployment authored none" and
// "this device is ignoring the ones it has". The counts are printed either way.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// passthroughPorts are the ports a passthrough domain is bypassed on. The domains name a host, not a
// service; 443 is the one that matters (the Console) and 80 is kept because a redirect to it is ordinary.
var passthroughPorts = []uint16{443, 80}

// resolvePassthroughDomains turns the profile's names into the addresses the capture can match, using the
// out-of-band resolver so this never depends on the loopback DNS proxy that needs the very tunnel these
// addresses exist to keep open.
func resolvePassthroughDomains(domains []string, upstreams func() []string) ([]netip.AddrPort, []string) {
	var out []netip.AddrPort
	var unresolved []string
	seen := map[netip.AddrPort]bool{}
	var direct []string
	if upstreams != nil {
		direct = upstreams()
	}
	res := newDirectResolver(direct)
	for _, d := range domains {
		name := strings.TrimSpace(d)
		if name == "" {
			continue
		}
		// A literal needs no lookup, and a deployment is entitled to name one.
		if a, err := netip.ParseAddr(name); err == nil {
			for _, p := range passthroughPorts {
				ap := netip.AddrPortFrom(a.Unmap(), p)
				if !seen[ap] {
					seen[ap] = true
					out = append(out, ap)
				}
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := res.LookupHost(ctx, name)
		cancel()
		if err != nil || len(ips) == 0 {
			unresolved = append(unresolved, name)
			continue
		}
		for _, ip := range ips {
			a, perr := netip.ParseAddr(ip)
			if perr != nil {
				continue
			}
			for _, p := range passthroughPorts {
				ap := netip.AddrPortFrom(a.Unmap(), p)
				if !seen[ap] {
					seen[ap] = true
					out = append(out, ap)
				}
			}
		}
	}
	return out, unresolved
}

// keepPassthroughResolved applies the profile's passthrough domains and re-resolves them on an interval, so a
// Console that moves (or a name that was briefly unresolvable at arm time) is followed rather than lost.
//
// The first application is reported unconditionally, hits or not. Later ones are reported only when the set
// changes, because a steady re-resolution that finds the same answer is not news.
func keepPassthroughResolved(stop <-chan struct{}, dests *liveDests, domains []string,
	upstreams func() []string, every time.Duration) {
	if dests == nil {
		return
	}
	apply := func(first bool) {
		addrs, unresolved := resolvePassthroughDomains(domains, upstreams)
		changed := dests.setPassthrough(addrs)
		if !first && !changed {
			return
		}
		fmt.Printf("steer: passthrough domains=%d addresses=%d — the deployment's own names this device "+
			"sends STRAIGHT to the customer's network, never through the tunnel\n", len(domains), len(addrs))
		if len(domains) > 0 && len(addrs) == 0 {
			fmt.Printf("steer: ★ %d passthrough domain(s) were authored and NONE resolved — those "+
				"destinations WILL be steered, and the deployment's own Console is usually among them\n",
				len(domains))
		}
		if len(unresolved) > 0 && len(addrs) > 0 {
			fmt.Printf("steer: passthrough could not resolve %s — those names stay steered until they do\n",
				strings.Join(unresolved, ", "))
		}
	}
	apply(true)
	if len(domains) == 0 || every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				apply(false)
			}
		}
	}()
}

// currentEgressResolvers reads the resolvers the box is using on its egress links RIGHT NOW.
//
// ★ Read at arm time, before the DNS takeover, and deliberately not through the resolverManager: this runs
// before that manager exists, and a passthrough domain on a private zone (a Console inside the customer's
// network is the case this was written for) is resolvable only by the box's own servers. The public fallback
// would answer NXDOMAIN and the Console would stay steered.
func currentEgressResolvers() []string {
	state, err := egressDNSState(nil)
	if err != nil {
		return nil
	}
	var entries []resolverEntry
	for _, s := range state {
		entries = append(entries, resolverEntry{IfIndex: s.IfIndex, Family: s.Family, Servers: s.Servers})
	}
	return upstreamServers(entries)
}

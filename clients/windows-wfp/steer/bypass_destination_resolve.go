package main

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// resolveBypassDestinations preserves literal address families and all DNS answers.
// Port zero is reserved for an explicitly authored whole-host exception.
func resolveBypassDestinations(value string, lookup func(string) ([]net.IP, error)) []netip.AddrPort {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(value)
	var port uint16
	if err != nil {
		host = value
		if _, err := netip.ParseAddr(host); err != nil && strings.ContainsAny(host, ":[]") {
			return nil
		}
	} else {
		number, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || number == 0 {
			return nil
		}
		port = uint16(number)
	}
	if host == "" {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		// The driver matches address bytes, not interface zones; do not broaden a scoped rule.
		if addr.Zone() != "" {
			return nil
		}
		return []netip.AddrPort{netip.AddrPortFrom(addr, port)}
	}
	ips, err := lookup(host)
	if err != nil {
		return nil
	}
	var v4, v6 []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		entry := netip.AddrPortFrom(addr, port)
		if seen[entry] {
			continue
		}
		seen[entry] = true
		if addr.Is4() {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}
	// Preserve the existing IPv4-first selection for callers needing one transport guard.
	return append(v4, v6...)
}

func resolveAddrPort(hostPort string) (netip.AddrPort, bool) {
	entries := resolveBypassDestinations(hostPort, net.LookupIP)
	if len(entries) == 0 {
		return netip.AddrPort{}, false
	}
	return entries[0], true
}

func parseAddrPorts(hostPorts []string) []netip.AddrPort {
	var out []netip.AddrPort
	seen := make(map[netip.AddrPort]bool)
	for _, entry := range hostPorts {
		for _, addr := range resolveBypassDestinations(entry, net.LookupIP) {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}

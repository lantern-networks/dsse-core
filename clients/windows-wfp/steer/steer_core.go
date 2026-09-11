// Package main (windivert-steer) — pure, cross-platform helpers for the Windows transparent steering
// agent (W1). These have NO WinDivert / OS dependency so they are unit-testable on any platform; the
// Windows-only file wires them to WinDivert recv/send. See.
package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// ipv4TCP is the parsed view of an IPv4 + TCP packet we need for transparent redirect: the byte offsets
// of the IPv4 src/dst addresses and the TCP src/dst ports, plus the values themselves.
type ipv4TCP struct {
	ihl     int // IPv4 header length in bytes
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
	tcpOff  int // offset of the TCP header (== ihl for IPv4)
}

const ipProtoTCP = 6

// parseIPv4TCP parses an IPv4 TCP packet. It returns ok=false (caller should pass the packet through
// unchanged) for anything that is not a well-formed IPv4 TCP packet — IPv6, UDP, truncated, etc.
func parseIPv4TCP(packet []byte) (ipv4TCP, bool) {
	var p ipv4TCP
	if len(packet) < 20 {
		return p, false
	}
	if packet[0]>>4 != 4 {
		return p, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return p, false
	}
	if packet[9] != ipProtoTCP {
		return p, false
	}
	p.ihl = ihl
	p.tcpOff = ihl
	copy(p.srcIP[:], packet[12:16])
	copy(p.dstIP[:], packet[16:20])
	p.srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	p.dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	return p, true
}

// setDestination rewrites the IPv4 destination address+port in place and recomputes both checksums.
func setDestination(packet []byte, ip [4]byte, port uint16) error {
	p, ok := parseIPv4TCP(packet)
	if !ok {
		return errors.New("not an IPv4 TCP packet")
	}
	copy(packet[16:20], ip[:])
	binary.BigEndian.PutUint16(packet[p.tcpOff+2:p.tcpOff+4], port)
	return recomputeIPv4TCPChecksums(packet)
}

// setSource rewrites the IPv4 source address+port in place and recomputes both checksums.
func setSource(packet []byte, ip [4]byte, port uint16) error {
	p, ok := parseIPv4TCP(packet)
	if !ok {
		return errors.New("not an IPv4 TCP packet")
	}
	copy(packet[12:16], ip[:])
	binary.BigEndian.PutUint16(packet[p.tcpOff:p.tcpOff+2], port)
	return recomputeIPv4TCPChecksums(packet)
}

// recomputeIPv4TCPChecksums zeroes and recomputes the IPv4 header checksum and the TCP checksum (with
// the TCP pseudo-header). Address/port rewrites change both, so this must run after any rewrite.
func recomputeIPv4TCPChecksums(packet []byte) error {
	p, ok := parseIPv4TCP(packet)
	if !ok {
		return errors.New("not an IPv4 TCP packet")
	}
	// IPv4 header checksum.
	packet[10], packet[11] = 0, 0
	ipSum := onesComplementSum(packet[:p.ihl], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipSum)

	// TCP checksum over pseudo-header + TCP segment.
	tcpLen := len(packet) - p.tcpOff
	if tcpLen < 20 {
		return errors.New("tcp segment too short")
	}
	packet[p.tcpOff+16], packet[p.tcpOff+17] = 0, 0
	var pseudo [12]byte
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[8] = 0
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	sum := initialSum(pseudo[:])
	tcpSum := onesComplementSum(packet[p.tcpOff:], sum)
	binary.BigEndian.PutUint16(packet[p.tcpOff+16:p.tcpOff+18], tcpSum)
	return nil
}

// initialSum folds a byte slice into a running 32-bit ones-complement accumulator (not yet folded to 16
// bits). Used to seed the TCP checksum with the pseudo-header before summing the segment.
func initialSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// onesComplementSum computes the 16-bit ones-complement checksum of b, seeded with carryIn (a running
// accumulator from a preceding region such as the TCP pseudo-header).
func onesComplementSum(b []byte, carryIn uint32) uint16 {
	sum := carryIn + initialSum(b)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- IPv6 ---------------------------------------------------------------------------------------------
// Chrome (and most dual-stack clients) connect to real sites over IPv6, which the IPv4-only capture path
// never saw, so steer-all silently missed them. These mirror the IPv4 helpers for
// a fixed-header IPv6 + TCP packet: parse, rewrite src/dst, and recompute the TCP checksum (IPv6 has no
// header checksum, and the TCP pseudo-header uses the 16-byte addresses). Extension headers are not handled
// (a steered TCP flow has next-header == TCP directly); such packets parse as not-ok and pass through.

const ipv6HeaderLen = 40

// ipv6TCP is the parsed view of an IPv6 + TCP packet we need for transparent redirect.
type ipv6TCP struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	tcpOff  int // offset of the TCP header (== 40 for a header-only IPv6 packet)
}

// parseIPv6TCP parses an IPv6 TCP packet (fixed 40-byte header, next-header == TCP). Returns ok=false
// (caller passes the packet through unchanged) for IPv4, UDP, extension-header, or truncated packets.
func parseIPv6TCP(packet []byte) (ipv6TCP, bool) {
	var p ipv6TCP
	if len(packet) < ipv6HeaderLen+20 {
		return p, false
	}
	if packet[0]>>4 != 6 {
		return p, false
	}
	if packet[6] != ipProtoTCP { // next header; we don't walk extension headers
		return p, false
	}
	p.tcpOff = ipv6HeaderLen
	copy(p.srcIP[:], packet[8:24])
	copy(p.dstIP[:], packet[24:40])
	p.srcPort = binary.BigEndian.Uint16(packet[ipv6HeaderLen : ipv6HeaderLen+2])
	p.dstPort = binary.BigEndian.Uint16(packet[ipv6HeaderLen+2 : ipv6HeaderLen+4])
	return p, true
}

// setDestination6 rewrites the IPv6 destination address+port in place and recomputes the TCP checksum.
func setDestination6(packet []byte, ip [16]byte, port uint16) error {
	p, ok := parseIPv6TCP(packet)
	if !ok {
		return errors.New("not an IPv6 TCP packet")
	}
	copy(packet[24:40], ip[:])
	binary.BigEndian.PutUint16(packet[p.tcpOff+2:p.tcpOff+4], port)
	return recomputeIPv6TCPChecksum(packet)
}

// setSource6 rewrites the IPv6 source address+port in place and recomputes the TCP checksum.
func setSource6(packet []byte, ip [16]byte, port uint16) error {
	p, ok := parseIPv6TCP(packet)
	if !ok {
		return errors.New("not an IPv6 TCP packet")
	}
	copy(packet[8:24], ip[:])
	binary.BigEndian.PutUint16(packet[p.tcpOff:p.tcpOff+2], port)
	return recomputeIPv6TCPChecksum(packet)
}

// ipv6TCPPseudoHeader builds the 40-byte IPv6 TCP checksum pseudo-header: src(16) + dst(16) +
// TCP length(4, big endian) + zeros(3) + next header(1) == TCP. (RFC 2460 section 8.1.)
func ipv6TCPPseudoHeader(packet []byte, tcpLen int) [40]byte {
	var pseudo [40]byte
	copy(pseudo[0:16], packet[8:24])
	copy(pseudo[16:32], packet[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(tcpLen))
	pseudo[39] = ipProtoTCP
	return pseudo
}

// recomputeIPv6TCPChecksum zeroes and recomputes the TCP checksum over the IPv6 pseudo-header + TCP
// segment. IPv6 has no header checksum, so (unlike IPv4) only the TCP checksum is updated.
func recomputeIPv6TCPChecksum(packet []byte) error {
	p, ok := parseIPv6TCP(packet)
	if !ok {
		return errors.New("not an IPv6 TCP packet")
	}
	tcpLen := len(packet) - p.tcpOff
	if tcpLen < 20 {
		return errors.New("tcp segment too short")
	}
	packet[p.tcpOff+16], packet[p.tcpOff+17] = 0, 0
	pseudo := ipv6TCPPseudoHeader(packet, tcpLen)
	sum := initialSum(pseudo[:])
	tcpSum := onesComplementSum(packet[p.tcpOff:], sum)
	binary.BigEndian.PutUint16(packet[p.tcpOff+16:p.tcpOff+18], tcpSum)
	return nil
}

// flowKey identifies a redirected flow by the client's ephemeral source port AND its address family.
// steer-all carries IPv4 and IPv6 flows through separate loopback terminators (127.0.0.1 / ::1), and a v4
// and a v6 flow can independently pick the same ephemeral port, so the family must be part of the key.
type flowKey struct {
	port uint16
	v6   bool
}

// natEntry records what a redirected flow needs for the return path: the original source address
// (rewritten to loopback on the way out) and the original destination (restored as the apparent source on
// the way back so the client's socket matches). origSrc/origDst are family-agnostic (netip.Addr).
type natEntry struct {
	origSrc     netip.Addr
	origDst     netip.Addr
	origDstPort uint16
	// ifIdx/subIf are the WinDivert interface indices of the original app->target packet, reused to
	// re-inject the rewritten return packets inbound on the same real interface.
	ifIdx    uint32
	subIf    uint32
	lastSeen time.Time
}

// conntrack maps a redirected flow (ephemeral source port + family) to its NAT state. All redirected
// flows of a family share one local terminator, so (port, family) is a sufficient key.
type conntrack struct {
	mu      sync.Mutex
	entries map[flowKey]natEntry
	ttl     time.Duration
}

func newConntrack(ttl time.Duration) *conntrack {
	return &conntrack{entries: map[flowKey]natEntry{}, ttl: ttl}
}

// put records (or refreshes) the NAT state for a flow key.
func (c *conntrack) put(key flowKey, e natEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.lastSeen = now
	c.entries[key] = e
	c.gcLocked(now)
}

// lookup returns the NAT state for a flow key, refreshing its lastSeen.
func (c *conntrack) lookup(key flowKey, now time.Time) (natEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return natEntry{}, false
	}
	e.lastSeen = now
	c.entries[key] = e
	return e, true
}

// origDstAddr returns the original destination as a netip.AddrPort, for issuing the edge CONNECT.
func (e natEntry) origDstAddr() netip.AddrPort {
	return netip.AddrPortFrom(e.origDst, e.origDstPort)
}

func (c *conntrack) gcLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	for key, e := range c.entries {
		if now.Sub(e.lastSeen) > c.ttl {
			delete(c.entries, key)
		}
	}
}

func (c *conntrack) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

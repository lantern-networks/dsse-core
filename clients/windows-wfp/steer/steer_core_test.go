package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// buildIPv4TCP crafts a minimal IPv4+TCP packet (20+20 header) with the given 5-tuple and payload.
// Checksums are left zero; the caller recomputes.
func buildIPv4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	total := 20 + 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = ipProtoTCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50 // data offset 5 (20-byte TCP header)
	pkt[33] = 0x02 // SYN
	copy(pkt[40:], payload)
	return pkt
}

// ipv4ChecksumValid reports whether the IPv4 header checksum verifies (folded sum incl. checksum == 0).
func ipv4ChecksumValid(packet []byte) bool {
	ihl := int(packet[0]&0x0f) * 4
	return onesComplementSum(packet[:ihl], 0) == 0
}

// tcpChecksumValid reports whether the TCP checksum verifies over pseudo-header + segment.
func tcpChecksumValid(packet []byte) bool {
	ihl := int(packet[0]&0x0f) * 4
	tcpLen := len(packet) - ihl
	var pseudo [12]byte
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	return onesComplementSum(packet[ihl:], initialSum(pseudo[:])) == 0
}

func TestParseIPv4TCP(t *testing.T) {
	pkt := buildIPv4TCP([4]byte{10, 0, 0, 5}, [4]byte{93, 184, 216, 34}, 51234, 443, nil)
	p, ok := parseIPv4TCP(pkt)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.srcPort != 51234 || p.dstPort != 443 {
		t.Fatalf("ports: got src=%d dst=%d", p.srcPort, p.dstPort)
	}
	if p.dstIP != [4]byte{93, 184, 216, 34} {
		t.Fatalf("dstIP: got %v", p.dstIP)
	}
	if p.ihl != 20 {
		t.Fatalf("ihl: got %d", p.ihl)
	}
}

func TestParseRejectsNonIPv4TCP(t *testing.T) {
	if _, ok := parseIPv4TCP([]byte{0x60, 0, 0, 0}); ok {
		t.Fatal("IPv6 should not parse")
	}
	udp := buildIPv4TCP([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 100, 200, nil)
	udp[9] = 17 // UDP
	if _, ok := parseIPv4TCP(udp); ok {
		t.Fatal("UDP should not parse")
	}
	if _, ok := parseIPv4TCP([]byte{0x45, 0}); ok {
		t.Fatal("truncated should not parse")
	}
}

func TestChecksumRecompute(t *testing.T) {
	pkt := buildIPv4TCP([4]byte{10, 0, 0, 5}, [4]byte{93, 184, 216, 34}, 51234, 443, []byte("hello"))
	if err := recomputeIPv4TCPChecksums(pkt); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !ipv4ChecksumValid(pkt) {
		t.Fatal("IPv4 checksum invalid after recompute")
	}
	if !tcpChecksumValid(pkt) {
		t.Fatal("TCP checksum invalid after recompute")
	}
}

func TestSetDestinationRewritesAndKeepsChecksumsValid(t *testing.T) {
	pkt := buildIPv4TCP([4]byte{10, 0, 0, 5}, [4]byte{93, 184, 216, 34}, 51234, 443, []byte("payload"))
	if err := setDestination(pkt, [4]byte{127, 0, 0, 1}, 18099); err != nil {
		t.Fatalf("setDestination: %v", err)
	}
	p, _ := parseIPv4TCP(pkt)
	if p.dstIP != [4]byte{127, 0, 0, 1} || p.dstPort != 18099 {
		t.Fatalf("dst not rewritten: %v:%d", p.dstIP, p.dstPort)
	}
	if p.srcPort != 51234 {
		t.Fatalf("src port should be unchanged: %d", p.srcPort)
	}
	if !ipv4ChecksumValid(pkt) || !tcpChecksumValid(pkt) {
		t.Fatal("checksums invalid after setDestination")
	}
}

func TestSetSourceRewritesAndKeepsChecksumsValid(t *testing.T) {
	pkt := buildIPv4TCP([4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 18099, 51234, []byte("resp"))
	if err := setSource(pkt, [4]byte{93, 184, 216, 34}, 443); err != nil {
		t.Fatalf("setSource: %v", err)
	}
	p, _ := parseIPv4TCP(pkt)
	if p.srcIP != [4]byte{93, 184, 216, 34} || p.srcPort != 443 {
		t.Fatalf("src not rewritten: %v:%d", p.srcIP, p.srcPort)
	}
	if !ipv4ChecksumValid(pkt) || !tcpChecksumValid(pkt) {
		t.Fatal("checksums invalid after setSource")
	}
}

// buildIPv6TCP crafts a minimal IPv6+TCP packet (40+20 header) with the given 5-tuple and payload.
// The TCP checksum is left zero; the caller recomputes.
func buildIPv6TCP(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	total := ipv6HeaderLen + 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(20+len(payload)))
	pkt[6] = ipProtoTCP // next header
	pkt[7] = 64         // hop limit
	copy(pkt[8:24], srcIP[:])
	copy(pkt[24:40], dstIP[:])
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	pkt[52] = 0x50 // data offset 5 (20-byte TCP header)
	pkt[53] = 0x02 // SYN
	copy(pkt[60:], payload)
	return pkt
}

// ipv6TCPChecksumValid reports whether the TCP checksum verifies over the IPv6 pseudo-header + segment.
func ipv6TCPChecksumValid(packet []byte) bool {
	tcpLen := len(packet) - ipv6HeaderLen
	pseudo := ipv6TCPPseudoHeader(packet, tcpLen)
	return onesComplementSum(packet[ipv6HeaderLen:], initialSum(pseudo[:])) == 0
}

func mkV6(b ...byte) [16]byte {
	var a [16]byte
	copy(a[:], b)
	return a
}

func TestParseIPv6TCP(t *testing.T) {
	src := mkV6(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05)
	dst := mkV6(0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01)
	pkt := buildIPv6TCP(src, dst, 51234, 443, []byte("hi"))
	p, ok := parseIPv6TCP(pkt)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.srcPort != 51234 || p.dstPort != 443 {
		t.Fatalf("ports: got src=%d dst=%d", p.srcPort, p.dstPort)
	}
	if p.dstIP != dst || p.srcIP != src {
		t.Fatalf("addrs not parsed: src=%v dst=%v", p.srcIP, p.dstIP)
	}
	if p.tcpOff != ipv6HeaderLen {
		t.Fatalf("tcpOff: got %d", p.tcpOff)
	}
}

func TestParseRejectsNonIPv6TCP(t *testing.T) {
	if _, ok := parseIPv6TCP(buildIPv4TCP([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1, 2, nil)); ok {
		t.Fatal("IPv4 packet should not parse as IPv6")
	}
	udp6 := buildIPv6TCP(mkV6(1), mkV6(2), 100, 200, nil)
	udp6[6] = 17 // next header UDP
	if _, ok := parseIPv6TCP(udp6); ok {
		t.Fatal("IPv6 UDP should not parse")
	}
	if _, ok := parseIPv6TCP([]byte{0x60, 0, 0, 0}); ok {
		t.Fatal("truncated should not parse")
	}
}

func TestIPv6ChecksumRecompute(t *testing.T) {
	pkt := buildIPv6TCP(mkV6(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5),
		mkV6(0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 51234, 443, []byte("hello"))
	if err := recomputeIPv6TCPChecksum(pkt); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if !ipv6TCPChecksumValid(pkt) {
		t.Fatal("IPv6 TCP checksum invalid after recompute")
	}
}

func TestSetDestination6RewritesAndKeepsChecksumValid(t *testing.T) {
	pkt := buildIPv6TCP(mkV6(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5),
		mkV6(0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 51234, 443, []byte("payload"))
	loop6 := mkV6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) // ::1
	if err := setDestination6(pkt, loop6, 18099); err != nil {
		t.Fatalf("setDestination6: %v", err)
	}
	p, _ := parseIPv6TCP(pkt)
	if p.dstIP != loop6 || p.dstPort != 18099 {
		t.Fatalf("dst not rewritten: %v:%d", p.dstIP, p.dstPort)
	}
	if p.srcPort != 51234 {
		t.Fatalf("src port should be unchanged: %d", p.srcPort)
	}
	if !ipv6TCPChecksumValid(pkt) {
		t.Fatal("checksum invalid after setDestination6")
	}
}

func TestSetSource6RewritesAndKeepsChecksumValid(t *testing.T) {
	loop6 := mkV6(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	pkt := buildIPv6TCP(loop6, loop6, 18099, 51234, []byte("resp"))
	dst := mkV6(0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	if err := setSource6(pkt, dst, 443); err != nil {
		t.Fatalf("setSource6: %v", err)
	}
	p, _ := parseIPv6TCP(pkt)
	if p.srcIP != dst || p.srcPort != 443 {
		t.Fatalf("src not rewritten: %v:%d", p.srcIP, p.srcPort)
	}
	if !ipv6TCPChecksumValid(pkt) {
		t.Fatal("checksum invalid after setSource6")
	}
}

func TestConntrackPutLookupAndGC(t *testing.T) {
	now := time.Unix(1000, 0)
	ct := newConntrack(30 * time.Second)
	ct.put(flowKey{port: 51234}, natEntry{
		origSrc:     netip.AddrFrom4([4]byte{10, 0, 0, 5}),
		origDst:     netip.AddrFrom4([4]byte{93, 184, 216, 34}),
		origDstPort: 443,
	}, now)
	e, ok := ct.lookup(flowKey{port: 51234}, now.Add(time.Second))
	if !ok {
		t.Fatal("expected lookup hit")
	}
	if e.origDstAddr().String() != "93.184.216.34:443" {
		t.Fatalf("origDstAddr: got %s", e.origDstAddr().String())
	}
	if _, ok := ct.lookup(flowKey{port: 40000}, now); ok {
		t.Fatal("unexpected hit for unknown port")
	}
	// Expire via GC on the next put past TTL.
	ct.put(flowKey{port: 60000}, natEntry{}, now.Add(time.Minute))
	if _, ok := ct.lookup(flowKey{port: 51234}, now.Add(time.Minute)); ok {
		t.Fatal("entry should have been GC'd after TTL")
	}
	if ct.size() != 1 {
		t.Fatalf("size: got %d", ct.size())
	}
}

// A v4 and a v6 flow that happen to share the same ephemeral port must not collide (distinct flow keys).
func TestConntrackV4V6PortDoNotCollide(t *testing.T) {
	now := time.Unix(2000, 0)
	ct := newConntrack(time.Minute)
	ct.put(flowKey{port: 50000, v6: false}, natEntry{origDst: netip.AddrFrom4([4]byte{1, 1, 1, 1}), origDstPort: 443}, now)
	ct.put(flowKey{port: 50000, v6: true}, natEntry{origDst: netip.MustParseAddr("2606:4700::1111"), origDstPort: 443}, now)
	v4, ok4 := ct.lookup(flowKey{port: 50000, v6: false}, now)
	v6, ok6 := ct.lookup(flowKey{port: 50000, v6: true}, now)
	if !ok4 || !ok6 {
		t.Fatal("both v4 and v6 entries should be present")
	}
	if v4.origDstAddr().String() != "1.1.1.1:443" || v6.origDstAddr().String() != "[2606:4700::1111]:443" {
		t.Fatalf("v4/v6 entries collided: v4=%s v6=%s", v4.origDstAddr(), v6.origDstAddr())
	}
}

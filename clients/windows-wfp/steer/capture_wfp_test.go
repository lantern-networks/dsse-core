//go:build windows

package main

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

func TestWFPRedirectContextOrigDstIPv4(t *testing.T) {
	var ctx wfpRedirectContext
	ctx.Version = wfpRedirectContextVersion
	ctx.Family = afInet
	copy(ctx.OrigDstAddr[:4], []byte{93, 184, 216, 34})
	ctx.OrigDstPort = binary.BigEndian.Uint16([]byte{0x01, 0xbb}) // 443 in network order, read as native uint16
	ap, ok := ctx.origDst()
	if !ok {
		t.Fatal("expected a usable IPv4 origDst")
	}
	if ap.String() != "93.184.216.34:443" {
		t.Fatalf("origDst = %s, want 93.184.216.34:443", ap)
	}
}

func TestWFPRedirectContextOrigDstIPv6(t *testing.T) {
	var ctx wfpRedirectContext
	ctx.Version = wfpRedirectContextVersion
	ctx.Family = afInet6
	v6 := netip.MustParseAddr("2606:4700::1").As16()
	copy(ctx.OrigDstAddr[:], v6[:])
	ctx.OrigDstPort = binary.BigEndian.Uint16([]byte{0x01, 0xbb})
	ap, ok := ctx.origDst()
	if !ok {
		t.Fatal("expected a usable IPv6 origDst")
	}
	if ap.String() != "[2606:4700::1]:443" {
		t.Fatalf("origDst = %s, want [2606:4700::1]:443", ap)
	}
}

func TestWFPRedirectContextRejectsUnknownFamily(t *testing.T) {
	ctx := wfpRedirectContext{Version: wfpRedirectContextVersion, Family: 999}
	if _, ok := ctx.origDst(); ok {
		t.Fatal("unknown family should not yield an origDst")
	}
}

func TestBuildWFPPolicyMarshalsAppsAndDests(t *testing.T) {
	cfg := captureConfig{
		localPort:   18099,
		bypassApps:  []string{"Automation", "  ", "chrome"},
		bypassDests: parseAddrPorts([]string{"160.79.104.10:443"}),
	}
	p := buildWFPPolicy(cfg)
	if p.Version != wfpPolicyVer || p.LocalPort != 18099 {
		t.Fatalf("policy header wrong: ver=%d port=%d", p.Version, p.LocalPort)
	}
	if p.NumApps != 2 { // "automation","chrome" -- the blank entry is skipped
		t.Fatalf("NumApps = %d, want 2", p.NumApps)
	}
	if got := nulString(p.Apps[0][:]); got != "automation" {
		t.Fatalf("app[0] = %q, want automation (lowercased)", got)
	}
	if p.NumDests != 1 || p.Dests[0].Family != afInet {
		t.Fatalf("dest rule wrong: num=%d fam=%d", p.NumDests, p.Dests[0].Family)
	}
	// 443 in network order is 0x01bb.
	if p.Dests[0].Port != 0x01bb {
		t.Fatalf("dest port (network order) = 0x%04x, want 0x01bb", p.Dests[0].Port)
	}
	if [4]byte{p.Dests[0].Addr[0], p.Dests[0].Addr[1], p.Dests[0].Addr[2], p.Dests[0].Addr[3]} != [4]byte{160, 79, 104, 10} {
		t.Fatalf("dest addr = %v, want 160.79.104.10", p.Dests[0].Addr[:4])
	}
}

func TestBuildWFPPolicyExactAppsAndSkipsSignatureSubstrings(t *testing.T) {
	exact := []string{`\Device\HarddiskVolume3\Program Files\Anthropic\automation.exe`}
	ep := &atomic.Pointer[[]string]{}
	ep.Store(&exact)
	cfg := captureConfig{
		localPort:         18099,
		bypassApps:        []string{"automation", "subject:anthropic, pbc", "thumbprint:aabb"},
		verifiedExactApps: ep,
	}
	p := buildWFPPolicy(cfg)
	// Signature forms must NOT be pushed as kernel substrings (they would never match a path) — only the plain
	// "automation" substring remains in the substring table.
	if p.NumApps != 1 || nulString(p.Apps[0][:]) != "automation" {
		t.Fatalf("substring apps wrong: num=%d app0=%q (signature forms must be excluded from the substring table)", p.NumApps, nulString(p.Apps[0][:]))
	}
	// The verified NT path goes into the exact-APP_ID table (the Phase 2 enforcement channel).
	if p.NumExactApps != 1 {
		t.Fatalf("NumExactApps = %d, want 1", p.NumExactApps)
	}
	if got := syscall.UTF16ToString(p.ExactApps[0][:]); got != exact[0] {
		t.Fatalf("exact[0] = %q, want %q", got, exact[0])
	}
}

// TestWFPPolicyABISize locks the Go wfpPolicy size to the C DSSE_POLICY (dsse_wfp.h, #pragma pack(1)) v2 layout.
// A drift here means the driver IOCTL would misparse the policy (silent bypass/enforcement bugs or a rejected
// SET_POLICY). v2 = v1 (1816) + NumExactApps(4) + ExactApps(16*260*2=8320) = 10140.
func TestWFPPolicyABISize(t *testing.T) {
	const want = 10140
	if got := unsafe.Sizeof(wfpPolicy{}); got != uintptr(want) {
		t.Fatalf("sizeof(wfpPolicy) = %d, want %d — Go/C ABI drift vs DSSE_POLICY (keep dsse_wfp.h in lockstep)", got, want)
	}
}

func TestBuildWFPPolicyAlwaysBypassesSelfImage(t *testing.T) {
	cfg := captureConfig{
		localPort:  18099,
		bypassApps: []string{"automation"},
		selfImage:  "DSSE-Steer.exe", // mixed case on purpose -> must be lowercased
	}
	p := buildWFPPolicy(cfg)
	if p.NumApps != 2 {
		t.Fatalf("NumApps = %d, want 2 (self + automation)", p.NumApps)
	}
	// self is added FIRST so it survives even a full app list.
	if got := nulString(p.Apps[0][:]); got != "dsse-steer.exe" {
		t.Fatalf("app[0] = %q, want dsse-steer.exe (self, lowercased, added first)", got)
	}
	if got := nulString(p.Apps[1][:]); got != "automation" {
		t.Fatalf("app[1] = %q, want automation", got)
	}
}

func TestBypassDestWholeHostWildcard(t *testing.T) {
	// A bare IP (no port) is a whole-host exception => AddrPort with port 0 => driver matches any port.
	aps := parseAddrPorts([]string{"10.10.0.10"})
	if len(aps) != 1 {
		t.Fatalf("parseAddrPorts(bare IP) len = %d, want 1", len(aps))
	}
	if aps[0].Port() != 0 {
		t.Fatalf("bare-IP bypass port = %d, want 0 (wildcard)", aps[0].Port())
	}
	if got := aps[0].Addr().String(); got != "10.10.0.10" {
		t.Fatalf("bare-IP bypass addr = %s, want 10.10.0.10", got)
	}
	p := buildWFPPolicy(captureConfig{localPort: 18099, bypassDests: aps})
	if p.NumDests != 1 || p.Dests[0].Family != afInet || p.Dests[0].Port != 0 {
		t.Fatalf("wildcard dest rule wrong: num=%d fam=%d port=%d", p.NumDests, p.Dests[0].Family, p.Dests[0].Port)
	}
	if [4]byte{p.Dests[0].Addr[0], p.Dests[0].Addr[1], p.Dests[0].Addr[2], p.Dests[0].Addr[3]} != [4]byte{10, 10, 0, 10} {
		t.Fatalf("wildcard dest addr = %v, want 10.10.0.10", p.Dests[0].Addr[:4])
	}
}

func nulString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

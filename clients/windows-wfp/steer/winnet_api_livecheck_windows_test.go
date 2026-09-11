//go:build windows

// winnet_api_livecheck_windows_test.go — LIVE, opt-in checks that the in-process Win32 DNS API primitives work
// on the real box, and CRUCIALLY that they work from SESSION 0 (where powershell.exe/netsh.exe failed with
// 0xC0000142). These are gated behind env vars so `go test` never mutates a developer's DNS by accident; the
// compiled test binary (`go test -c`) is run once interactively and once as a SYSTEM scheduled task (session 0)
// to prove the session-0 fix. Read-only check: DSSE_WINNET_SELFTEST=1. Reversible write round-trip:
// DSSE_WINNET_WRITETEST=1 (sets the egress IPv4 iface static to its current servers, verifies, then resets it to
// automatic/DHCP — a no-op on a DHCP box, restoring the original state).
package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Session-0 probe: fixed trigger/result paths so the compiled test binary can be driven by a SYSTEM scheduled
// task (session 0) with no shell to pass env vars or redirect stdout — the point is to prove the in-process API
// works where powershell.exe/netsh.exe/cmd.exe fail to even launch (0xC0000142).
const (
	s0TriggerPath = `C:\Windows\Temp\dsse_winnet_s0.trigger`
	s0ResultPath  = `C:\Windows\Temp\dsse_winnet_s0.result`
)

// TestWinnetSession0 runs the read + reversible write checks and writes a PASS/FAIL report to a fixed file, so a
// session-0 SYSTEM task can prove the API works there. Skipped unless the trigger file exists.
func TestWinnetSession0(t *testing.T) {
	if _, err := os.Stat(s0TriggerPath); err != nil {
		t.Skip("session-0 trigger file absent; skipping")
	}
	var b strings.Builder
	whoami := os.Getenv("USERNAME")
	fmt.Fprintf(&b, "session-0 winnet API probe (running as %s)\n", whoami)

	state, err := enumInterfaceDNS([]string{"127.0.0.1", "::1"})
	if err != nil {
		fmt.Fprintf(&b, "FAIL enum: %v\n", err)
		_ = os.WriteFile(s0ResultPath, []byte(b.String()), 0o600)
		t.Fatalf("enum: %v", err)
	}
	fmt.Fprintf(&b, "PASS enum: %d entry(ies)\n", len(state))
	for _, e := range state {
		fmt.Fprintf(&b, "  iface=%s fam=%s egress=%v servers=%s\n", e.IfIndex, e.Family, e.Egress, e.Servers)
	}

	// reversible write round-trip on the egress IPv4 iface (static-set same servers -> verify -> reset to DHCP)
	var target ifaceDNS
	for _, s := range state {
		if s.Family == "IPv4" && s.Egress && s.Servers != "" && !strings.Contains(s.Servers, "127.0.0.1") {
			target = s
			break
		}
	}
	if target.IfIndex != "" {
		idx := idxU32(target.IfIndex)
		if err := setInterfaceDNS(idx, "IPv4", target.Servers); err != nil {
			fmt.Fprintf(&b, "FAIL setInterfaceDNS(static): %v\n", err)
		} else if err := setInterfaceDNS(idx, "IPv4", ""); err != nil {
			fmt.Fprintf(&b, "FAIL setInterfaceDNS(reset): %v\n", err)
		} else {
			flushDNSCache()
			fmt.Fprintf(&b, "PASS write round-trip on iface %s (static-set + reset-to-DHCP, no child process)\n", target.IfIndex)
		}
	} else {
		fmt.Fprintf(&b, "SKIP write round-trip: no egress IPv4 iface with real servers\n")
	}
	_ = os.WriteFile(s0ResultPath, []byte(b.String()), 0o600)
}

func TestWinnetEnumReadOnly(t *testing.T) {
	if os.Getenv("DSSE_WINNET_SELFTEST") != "1" {
		t.Skip("set DSSE_WINNET_SELFTEST=1 to run the live read-only API check")
	}
	got, err := enumInterfaceDNS([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("enumInterfaceDNS: %v", err)
	}
	egress := 0
	for _, e := range got {
		t.Logf("iface=%s fam=%s egress=%v servers=%s", e.IfIndex, e.Family, e.Egress, e.Servers)
		if e.Egress {
			egress++
		}
	}
	t.Logf("RESULT enum ok: %d entry(ies), %d egress — GetAdaptersAddresses+GetBestInterfaceEx worked (no child process)", len(got), egress)
	if len(got) == 0 {
		t.Fatalf("no DNS entries found — API returned empty on a connected box")
	}
}

func TestWinnetWriteRoundTrip(t *testing.T) {
	if os.Getenv("DSSE_WINNET_WRITETEST") != "1" {
		t.Skip("set DSSE_WINNET_WRITETEST=1 to run the live reversible write round-trip")
	}
	state, err := enumInterfaceDNS([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("enum: %v", err)
	}
	var target ifaceDNS
	found := false
	for _, s := range state {
		if s.Family == "IPv4" && s.Egress && s.Servers != "" && !strings.Contains(s.Servers, "127.0.0.1") {
			target = s
			found = true
			break
		}
	}
	if !found {
		t.Skip("no egress IPv4 interface with real servers to round-trip")
	}
	idx := idxU32(target.IfIndex)
	orig := target.Servers
	t.Logf("round-trip target iface=%s orig_servers=%s", target.IfIndex, orig)

	// 1. WRITE: set static to the same servers (exercises SetInterfaceDnsSettings + GUID conversion).
	if err := setInterfaceDNS(idx, "IPv4", orig); err != nil {
		t.Fatalf("setInterfaceDNS(static) failed: %v", err)
	}
	// 2. VERIFY the write took.
	after, _ := enumInterfaceDNS([]string{"127.0.0.1"})
	gotServers := ""
	for _, s := range after {
		if s.IfIndex == target.IfIndex && s.Family == "IPv4" {
			gotServers = s.Servers
		}
	}
	if normalizeServers(gotServers) != normalizeServers(orig) {
		t.Fatalf("after static set, servers=%q want %q", gotServers, orig)
	}
	// 3. RESET to automatic (DHCP) — restores the original state on a DHCP box.
	if err := setInterfaceDNS(idx, "IPv4", ""); err != nil {
		t.Fatalf("setInterfaceDNS(reset) failed: %v", err)
	}
	flushDNSCache()
	t.Logf("RESULT write round-trip ok on iface %s: static-set + verify + reset-to-DHCP all succeeded (no child process)", target.IfIndex)
}

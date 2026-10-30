//go:build windows

// winnet_api_livecheck_windows_test.go — LIVE, opt-in checks that the in-process Win32 DNS API primitives work
// on the real box, and CRUCIALLY that they work from SESSION 0 (where powershell.exe/netsh.exe failed with
// 0xC0000142). Read-only checks require explicit opt-in. The write check requires DSSE_WINNET_WRITETEST=1 and
// an API-confirmed automatic-DNS interface; a static-DNS interface must never be reset to DHCP by a test.
package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"
)

// Session-0 probe result path. Both the environment opt-in and trigger are required so a stale trigger file
// cannot make an ordinary go test touch the machine.
const (
	s0TriggerPath = `C:\Windows\Temp\dsse_winnet_s0.trigger`
	s0ResultPath  = `C:\Windows\Temp\dsse_winnet_s0.result`
)

// TestWinnetSession0 reads DNS without changing it and writes a report for a separately invoked SYSTEM task.
func TestWinnetSession0(t *testing.T) {
	if os.Getenv("DSSE_WINNET_S0_SELFTEST") != "1" {
		t.Skip("set DSSE_WINNET_S0_SELFTEST=1 for the session-0 read-only probe")
	}
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

	_ = os.WriteFile(s0ResultPath, []byte(b.String()), 0o600)
}

// GetInterfaceDnsSettings distinguishes an automatic DNS interface from one with an authored static server.
// enumInterfaceDNS reports only effective servers, which cannot make this distinction. Treat any uncertainty
// or profile-specific server as static and leave it untouched.
func automaticIPv4DNS(ifIndex uint32) (bool, error) {
	guid, err := interfaceGUID(ifIndex)
	if err != nil {
		return false, err
	}
	settings := dnsInterfaceSettings{Version: dnsInterfaceSettingsVersion1}
	get := iphlpapi.NewProc("GetInterfaceDnsSettings")
	if r, _, _ := get.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&settings))); r != 0 {
		return false, fmt.Errorf("GetInterfaceDnsSettings(if=%d): status %d", ifIndex, r)
	}
	defer iphlpapi.NewProc("FreeInterfaceDnsSettings").Call(uintptr(unsafe.Pointer(&settings)))
	return dnsSettingsAreAutomatic(settings), nil
}

func dnsSettingsAreAutomatic(settings dnsInterfaceSettings) bool {
	const dnsSettingProfileNameServer = 0x0200
	return settings.Flags&(dnsSettingNameServer|dnsSettingProfileNameServer) == 0 &&
		settings.NameServer == nil && settings.ProfileNameServer == nil
}

func TestWinnetWriteProbeRequiresAutomaticDNS(t *testing.T) {
	static := uint16('1')
	for _, settings := range []dnsInterfaceSettings{
		{Flags: dnsSettingNameServer},
		{Flags: 0x0200},
		{NameServer: &static},
		{ProfileNameServer: &static},
	} {
		if dnsSettingsAreAutomatic(settings) {
			t.Fatal("static or profile DNS was classified as automatic")
		}
	}
	if !dnsSettingsAreAutomatic(dnsInterfaceSettings{}) {
		t.Fatal("no authored DNS servers must be classified as automatic")
	}
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
	automatic, err := automaticIPv4DNS(idx)
	if err != nil {
		t.Fatalf("cannot prove the interface uses automatic DNS: %v", err)
	}
	if !automatic {
		t.Skip("interface has static or profile DNS; the test must not reset it to DHCP")
	}
	t.Logf("round-trip target iface=%s orig_servers=%s", target.IfIndex, orig)

	// Register recovery before the write; even an API error could follow a partial change.
	t.Cleanup(func() {
		if err := setInterfaceDNS(idx, "IPv4", ""); err != nil {
			t.Errorf("restore automatic DNS failed: %v", err)
			return
		}
		flushDNSCache()
		if restored, err := automaticIPv4DNS(idx); err != nil || !restored {
			t.Errorf("automatic DNS restore not verified: restored=%t error=%v", restored, err)
		}
	})
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
	t.Logf("RESULT write verified on iface %s; cleanup will restore automatic DNS", target.IfIndex)
}

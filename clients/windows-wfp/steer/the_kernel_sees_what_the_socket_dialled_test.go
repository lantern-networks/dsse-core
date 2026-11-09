package main

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestAnIPv4ExclusionAlsoReachesTheDriverInTheFormADualStackSocketUses(t *testing.T) {
	native, mapped := kernelDestinations(parseAddrPorts([]string{"57.180.243.182:443", "[2001:db8::1]:443", "127.0.0.1:18090"}))
	if len(native) != 3 {
		t.Fatalf("native = %v; every authored rule must stay as it is", native)
	}
	want := map[netip.AddrPort]bool{
		netip.MustParseAddrPort("[::ffff:57.180.243.182]:443"): true,
		netip.MustParseAddrPort("[::ffff:127.0.0.1]:18090"):    true,
	}
	if len(mapped) != len(want) {
		t.Fatalf("mapped = %v; want one IPv4-mapped rule per IPv4 rule and none for IPv6", mapped)
	}
	for _, m := range mapped {
		if !want[m] {
			t.Fatalf("unexpected mapped rule %v", m)
		}
	}
	// An authored mapped rule is not added twice.
	_, again := kernelDestinations(parseAddrPorts([]string{"57.180.243.182:443", "[::ffff:57.180.243.182]:443"}))
	if len(again) != 0 {
		t.Fatalf("mapped = %v; the mapped form was already authored", again)
	}
}

func TestTheWinDivertMatcherTreatsAMappedAddressAsTheIPv4ItCarries(t *testing.T) {
	rules := parseAddrPorts([]string{"57.180.243.182:443", "10.0.0.5"})
	cases := []struct {
		dst  string
		port uint16
		want bool
	}{
		{"57.180.243.182", 443, true},
		{"::ffff:57.180.243.182", 443, true},
		{"::ffff:57.180.243.182", 80, false},
		{"::ffff:10.0.0.5", 3389, true}, // a bare host excludes every port
		{"57.180.243.183", 443, false},
	}
	for _, c := range cases {
		if got := destinationExcluded(rules, netip.MustParseAddr(c.dst), c.port); got != c.want {
			t.Errorf("%s:%d excluded=%t, want %t", c.dst, c.port, got, c.want)
		}
	}
}

func TestAnApplicationPathIsComparedTheWayTheDriverSeesIt(t *testing.T) {
	cases := map[string]string{
		`C:\Program Files\Git\usr\bin\ssh.exe`:     `\program files\git\usr\bin\ssh.exe`,
		`\\?\C:\Program Files\Git\usr\bin\ssh.exe`: `\program files\git\usr\bin\ssh.exe`,
		`d:/tools/putty.exe`:                       `\tools\putty.exe`,
		`\git\usr\bin\ssh.exe`:                     `\git\usr\bin\ssh.exe`,
		`  Automation `:                            `automation`,
		`subject:Lantern Networks`:                 `subject:lantern networks`, // typed forms are not paths
	}
	for in, want := range cases {
		if got := kernelAppSubstring(in); got != want {
			t.Errorf("kernelAppSubstring(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBothBackendsUseTheDriversForm: the helpers above are only worth something if the code that talks to the
// driver calls them. Go happily compiles a helper nothing uses.
func TestBothBackendsUseTheDriversForm(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	policy := read("capture_wfp_policy.go")
	for _, call := range []string{"kernelDestinations(cfg.effectiveDests())", "kernelAppSubstring(sub)"} {
		if !strings.Contains(policy, call) {
			t.Errorf("the WFP policy writer does not call %s", call)
		}
	}
	if !strings.Contains(read("capture_windivert.go"), "destinationExcluded(c.cfg.effectiveDests(), dstIP, dstPort)") {
		t.Error("the WinDivert matcher does not compare through destinationExcluded")
	}
}

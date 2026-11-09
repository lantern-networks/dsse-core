// the_kernel_sees_what_the_socket_dialled.go — the destination and application exclusions, in the form the
// callout driver actually compares against. Portable Go (no build tag) so the rules unit-test anywhere; the
// WFP policy writer and the WinDivert matcher both go through here.
//
// ★★★ POWERSHELL REACHED THE CONSOLE THROUGH THE SWG AND GOT 502; CHROME, IN THE SAME MINUTE, WENT STRAIGHT
// THERE (2026-11-08, acceptance C, third walk — C18). The entrance's address was excluded, as
// 57.180.243.182:443, and the steer log showed PowerShell's connection arriving as [::ffff:57.180.243.182]:443.
// .NET opens dual-stack sockets, so an IPv4 connect from it is classified at the IPv6 layer with the address
// written as IPv4-mapped IPv6. The driver compares an IPv6 rule byte for byte and looks at IPv4 rules only at
// the IPv4 layer, so the exclusion never matched and the flow was steered into the inspection path, which then
// refused to send it to the deployment's own internal address. Chrome uses an IPv4 socket and matched.
//
// The driver is not changed (it is the signed 0.4.0 driver); the agent hands it the mapped form as well.
//
// ★★ AN APPLICATION EXCLUSION TYPED AS C:\… NEVER MATCHED EITHER (the same walk). The driver matches an
// application by a substring of the connecting process's image path, and the path it sees is the NT device
// path (\device\harddiskvolume3\program files\…) — no drive letter in it anywhere. An administrator who pasted
// the path Explorer shows them excluded nothing. The drive letter is dropped before the rule is handed over,
// so "C:\Program Files\Git\usr\bin\ssh.exe" matches as "\program files\git\usr\bin\ssh.exe". The volume is
// not something the driver can see, so the rule matches that path on any volume; that is said in the
// administration guide.

package main

import (
	"net/netip"
	"strings"
)

// kernelDestinations splits the destination exclusions into the rules as authored and the extra IPv4-mapped
// IPv6 rules a dual-stack socket needs. native is the effective set unchanged; mapped holds, for every IPv4
// rule, ::ffff:a.b.c.d with the same port, skipping any that native already contains.
func kernelDestinations(dests []netip.AddrPort) (native, mapped []netip.AddrPort) {
	native = append([]netip.AddrPort(nil), dests...)
	have := make(map[netip.AddrPort]bool, len(dests))
	for _, d := range dests {
		have[d] = true
	}
	for _, d := range dests {
		if !d.IsValid() || !d.Addr().Is4() {
			continue
		}
		m := netip.AddrPortFrom(netip.AddrFrom16(d.Addr().As16()), d.Port())
		if have[m] {
			continue
		}
		have[m] = true
		mapped = append(mapped, m)
	}
	return native, mapped
}

// destinationExcluded is the userspace form of the same comparison, for the WinDivert backend: an IPv4 rule
// matches the address whether the packet carries it as IPv4 or as IPv4-mapped IPv6, and the other way round.
func destinationExcluded(rules []netip.AddrPort, dst netip.Addr, port uint16) bool {
	dst = dst.Unmap()
	for _, d := range rules {
		if d.Addr().Unmap() == dst && (d.Port() == 0 || d.Port() == port) {
			return true
		}
	}
	return false
}

// kernelAppSubstring is an image-path exclusion as the driver compares it: lower case, and without a leading
// drive letter (or the \\?\ prefix in front of one), because the driver sees NT device paths.
func kernelAppSubstring(rule string) string {
	s := strings.ToLower(strings.TrimSpace(rule))
	s = strings.TrimPrefix(s, `\\?\`)
	if len(s) >= 3 && s[0] >= 'a' && s[0] <= 'z' && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		s = `\` + s[3:]
	}
	return strings.ReplaceAll(s, "/", `\`)
}

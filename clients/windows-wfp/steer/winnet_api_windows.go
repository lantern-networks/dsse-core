//go:build windows

// winnet_api_windows.go — in-process Win32 API primitives for the DNS-over-tunnel resolver takeover and the
// NCSI probe policy, replacing the powershell.exe/netsh.exe shell-outs those paths used to do.
//
// WHY (root cause, verified on-device 2026-07-01): the shipping agent runs as a Windows SERVICE in SESSION 0.
// On this class of box the session-0 non-interactive window station's desktop heap is exhausted/unavailable, so
// creating ANY child process from the service — powershell.exe, netsh.exe, even cmd.exe — fails at DLL init with
// exit status 0xC0000142 (STATUS_DLL_INIT_FAILED). The DNS-repoint and NCSI-suppress steps therefore silently
// failed under the service (`dns_resolver: egress dns state: exit status 0xc0000142 ... DNS left on the system
// resolver — it would leak`), defeating the DNS-over-tunnel leak-prevention. A session-1 interactive run worked,
// masking the bug. The robust fix is to STOP shelling out entirely and drive the OS via in-process API calls,
// which need no child process, no desktop heap, and no session context — so they work identically in session 0.
//
// These primitives mirror exactly what the old scripts did:
//   - Set-DnsClientServerAddress -InterfaceIndex i -ServerAddresses X   -> SetInterfaceDnsSettings (iphlpapi)
//   - Set-DnsClientServerAddress -ResetServerAddresses                  -> SetInterfaceDnsSettings NameServer=NULL
//   - Get-DnsClientServerAddress + Get-NetRoute (egress)                -> GetAdaptersAddresses + GetBestInterfaceEx
//   - Clear-DnsClientCache                                              -> DnsFlushResolverCache (dnsapi)
package main

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// iphlpapi is already declared (as a LazyDLL) in procbypass_windows.go; reuse that handle for new procs.
	procConvertInterfaceIndexToLuid = iphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToGuid  = iphlpapi.NewProc("ConvertInterfaceLuidToGuid")
	procSetInterfaceDnsSettings     = iphlpapi.NewProc("SetInterfaceDnsSettings")

	dnsapi                    = syscall.NewLazyDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

const (
	afUnspec = 0 // afInet(2)/afInet6(23) are declared in capture_wfp.go — reuse them.

	// GetAdaptersAddresses: keep DNS servers, drop the noise we don't parse.
	gaaFlags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME

	ifOperStatusUp = 1

	// DNS_INTERFACE_SETTINGS (windns.h)
	dnsInterfaceSettingsVersion1 = 1
	dnsSettingIPv6               = 0x0001
	dnsSettingNameServer         = 0x0002
)

// dnsInterfaceSettings mirrors the C DNS_INTERFACE_SETTINGS (version 1). Field order/size must match the ABI:
// ULONG Version; ULONG64 Flags; PWSTR Domain/NameServer/SearchList; ULONG x4; PWSTR ProfileNameServer.
type dnsInterfaceSettings struct {
	Version             uint32
	_                   uint32 // padding so Flags is 8-byte aligned (matches C struct layout)
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

// interfaceGUID resolves an interface index to its GUID (SetInterfaceDnsSettings keys on the GUID, not the index).
func interfaceGUID(ifIndex uint32) (windows.GUID, error) {
	var luid uint64
	if r, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(ifIndex), uintptr(unsafe.Pointer(&luid))); r != 0 {
		return windows.GUID{}, fmt.Errorf("ConvertInterfaceIndexToLuid(%d): status %d", ifIndex, r)
	}
	var guid windows.GUID
	if r, _, _ := procConvertInterfaceLuidToGuid.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&guid))); r != 0 {
		return windows.GUID{}, fmt.Errorf("ConvertInterfaceLuidToGuid: status %d", r)
	}
	return guid, nil
}

// setInterfaceDNS points one interface/family at the given name servers (comma-separated). An empty serversCSV
// resets that family to DHCP-provided (automatic) DNS. `family` is "IPv4" or "IPv6" (mirrors resolverEntry.Family).
func setInterfaceDNS(ifIndex uint32, family, serversCSV string) error {
	guid, err := interfaceGUID(ifIndex)
	if err != nil {
		return err
	}
	flags := uint64(dnsSettingNameServer)
	if family == "IPv6" {
		flags |= dnsSettingIPv6
	}
	s := dnsInterfaceSettings{
		Version: dnsInterfaceSettingsVersion1,
		Flags:   flags,
	}
	// NameServer NULL => reset to DHCP; non-NULL => set static list. Normalize whitespace to a comma list.
	if csv := normalizeServers(serversCSV); csv != "" {
		p, err := windows.UTF16PtrFromString(csv)
		if err != nil {
			return err
		}
		s.NameServer = p
	}
	// GUID is 16 bytes => passed by reference under the x64 ABI; pass a pointer to our copy.
	r, _, _ := procSetInterfaceDnsSettings.Call(uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&s)))
	if r != 0 {
		return fmt.Errorf("SetInterfaceDnsSettings(if=%d fam=%s): status %d", ifIndex, family, r)
	}
	return nil
}

// normalizeServers turns a "a,b" or "a b" server string into a clean comma-separated list (dropping blanks).
func normalizeServers(s string) string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return strings.Join(out, ",")
}

// flushDNSCache clears the resolver cache (ipconfig /flushdns equivalent). Best-effort: a stale cache only delays
// the repoint taking effect, so a failure here is non-fatal.
func flushDNSCache() {
	procDnsFlushResolverCache.Call()
}

// enumInterfaceDNS reports every interface/family that currently has DNS servers set, mirroring the old
// egressDNSState() PowerShell (Get-DnsClientServerAddress + Get-NetRoute). Egress = the family's best default
// route interface (GetBestInterfaceEx to a public address), which is what the takeover follows across link
// switches. Only families with a proxy listener (per `bound`) are reported.
func enumInterfaceDNS(bound []string) ([]ifaceDNS, error) {
	wantV4, wantV6 := false, false
	for _, l := range bound {
		if fam, _ := familyParams(l); fam == "IPv6" {
			wantV6 = true
		} else {
			wantV4 = true
		}
	}
	adapters, err := getAdapters()
	if err != nil {
		return nil, err
	}
	bestV4, bestV6 := bestEgressIfIndex()

	// Accumulate DNS servers per (ifIndex, family) so an adapter listing several servers collapses to one CSV.
	type key struct {
		idx uint32
		fam string
	}
	acc := map[key][]string{}
	order := []key{}
	for a := adapters; a != nil; a = a.Next {
		if a.OperStatus != ifOperStatusUp {
			continue
		}
		for dns := a.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip, fam := sockaddrIP(dns.Address.Sockaddr)
			if ip == "" {
				continue
			}
			idx := a.IfIndex
			if fam == "IPv6" {
				idx = a.Ipv6IfIndex
			}
			if idx == 0 {
				continue
			}
			k := key{idx, fam}
			if _, ok := acc[k]; !ok {
				order = append(order, k)
			}
			acc[k] = append(acc[k], ip)
		}
	}

	var res []ifaceDNS
	for _, k := range order {
		if (k.fam == "IPv4" && !wantV4) || (k.fam == "IPv6" && !wantV6) {
			continue
		}
		egress := (k.fam == "IPv4" && k.idx == bestV4) || (k.fam == "IPv6" && k.idx == bestV6)
		res = append(res, ifaceDNS{
			Family:  k.fam,
			IfIndex: fmt.Sprintf("%d", k.idx),
			Servers: strings.Join(acc[k], ","),
			Egress:  egress,
		})
	}
	return res, nil
}

// getAdapters calls GetAdaptersAddresses with a growing buffer and returns the head of the adapter list.
func getAdapters() (*windows.IpAdapterAddresses, error) {
	size := uint32(15 * 1024)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(afUnspec, gaaFlags, 0, head, &size)
		if err == nil {
			return head, nil
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue // size now holds the required length; retry
		}
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer kept overflowing")
}

// bestEgressIfIndex returns the default-route interface index for IPv4 and IPv6 (0 if none), via GetBestInterfaceEx
// to a public address per family. This is the API analog of `Get-NetRoute -DestinationPrefix 0.0.0.0/0 / ::/0`.
func bestEgressIfIndex() (v4, v6 uint32) {
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}, &v4); err != nil {
		v4 = 0
	}
	var six windows.SockaddrInet6
	copy(six.Addr[:], net.ParseIP("2001:4860:4860::8888").To16())
	if err := windows.GetBestInterfaceEx(&six, &v6); err != nil {
		v6 = 0
	}
	return v4, v6
}

// sockaddrIP extracts the printable IP and family ("IPv4"/"IPv6") from a raw sockaddr (a DNS server address).
func sockaddrIP(raw *syscall.RawSockaddrAny) (ip, family string) {
	if raw == nil {
		return "", ""
	}
	switch raw.Addr.Family {
	case afInet:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
		return net.IP(sa.Addr[:]).String(), "IPv4"
	case afInet6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
		return net.IP(sa.Addr[:]).String(), "IPv6"
	}
	return "", ""
}

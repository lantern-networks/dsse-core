//go:build windows

// device_posture_windows.go — per-device signals reported on the steer-mux CONNECT (per-connection ≈ per-device,
// NOT per-flow): the device OS string and posture (disk encryption + firewall). The Edge keys these by the
// verified transport device identity and renders them in the Devices / posture view. Everything here is an agent
// CLAIM (a dashboard signal + trust floor, not proof) and non-secret (an OS string + two booleans). Fail-safe:
// any signal that cannot be read is omitted (the Edge shows it as unknown), never guessed. Collected in-process
// (registry / WMI) — the service runs in session 0 and must not shell out.

package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

func init() { deviceConnectHeaders = collectDeviceConnectHeaders }

var (
	postureMu     sync.Mutex
	postureCache  string
	postureExpiry time.Time
)

const postureTTL = 60 * time.Second

// collectDeviceConnectHeaders assembles the per-device signal headers, cached briefly (read once per mux
// connection; posture rarely changes). A non-empty result is cached; a transient all-empty read is not, so it
// retries next time.
func collectDeviceConnectHeaders() string {
	postureMu.Lock()
	defer postureMu.Unlock()
	if postureCache != "" && time.Now().Before(postureExpiry) {
		return postureCache
	}
	var b strings.Builder
	if os := osDescription(); os != "" {
		fmt.Fprintf(&b, "X-Dsse-Device-OS: %s\r\n", os)
	}
	enc := diskEncryptionStatus()
	fw := firewallStatus()
	if enc != "" {
		fmt.Fprintf(&b, "X-Dsse-Posture-Encryption: %s\r\n", enc)
	}
	if fw != "" {
		fmt.Fprintf(&b, "X-Dsse-Posture-Firewall: %s\r\n", fw)
	}
	if enc != "" || fw != "" {
		b.WriteString("X-Dsse-Posture-Source: windows_collector\r\n")
	}
	out := b.String()
	if out != "" {
		postureCache = out
		postureExpiry = time.Now().Add(postureTTL)
	}
	return out
}

// osDescription returns a short OS string like "Windows 11 24H2" from the registry. ProductName still reads
// "Windows 10" on Windows 11, so the 10/11 split is derived from the build number; DisplayVersion is the "24H2"
// feature-update tag.
func osDescription() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	build := 0
	if s, _, e := k.GetStringValue("CurrentBuildNumber"); e == nil {
		build, _ = strconv.Atoi(s)
	}
	name := "Windows"
	switch {
	case build >= 22000:
		name = "Windows 11"
	case build > 0:
		name = "Windows 10"
	}
	if disp, _, e := k.GetStringValue("DisplayVersion"); e == nil && disp != "" {
		return name + " " + disp
	}
	if build > 0 {
		return fmt.Sprintf("%s (build %d)", name, build)
	}
	return ""
}

// firewallStatus reports "on" if ANY firewall profile is enabled, "off" if every readable profile is disabled,
// and "" (unknown) if none is readable. Registry read avoids COM and the session-0 no-child-process constraint.
func firewallStatus() string {
	readAny := false
	for _, p := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+p, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, e := k.GetIntegerValue("EnableFirewall")
		k.Close()
		if e != nil {
			continue
		}
		readAny = true
		if v == 1 {
			return "on"
		}
	}
	if readAny {
		return "off"
	}
	return ""
}

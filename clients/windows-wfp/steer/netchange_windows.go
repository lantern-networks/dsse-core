//go:build windows

// netchange_windows.go — react to a network change the MOMENT Windows reports it, instead of waiting for the
// periodic DNS-reconcile poll (~15s) or the Edge-unreachable timeout. A Wi-Fi roam / Wi-Fi<->wired switch /
// VPN up-down / new DHCP lease all fire an IP-address-change notification; we block on it via iphlpapi
// NotifyAddrChange and, on each change, immediately re-converge the DNS takeover onto the now-active interface
// and refresh the fail-open upstream from that interface's resolver. This is what makes a network switch fast
// and deterministic rather than a ragged 15-30s settle.
package main

import (
	"time"
)

// iphlpapi is declared in procbypass_windows.go; reuse it for the address-change notification.
var procNotifyAddrChange = iphlpapi.NewProc("NotifyAddrChange")

// watchNetworkChanges blocks on Windows IP-address-change notifications and calls onChange (coalesced) for each.
// NotifyAddrChange(NULL,NULL) is synchronous: it blocks until the next address change and returns NO_ERROR(0).
// A short coalescing delay absorbs the burst of events a single roam emits so onChange runs once on the settled
// config. Stops when `stop` is closed (the final blocked call ends when the process exits).
func watchNetworkChanges(stop <-chan struct{}, onChange func()) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		// Blocks here until an interface address changes (add/remove, DHCP renew, link up/down, roam).
		r, _, _ := procNotifyAddrChange.Call(0, 0)
		select {
		case <-stop:
			return
		default:
		}
		if r != 0 {
			// Unexpected (non-NO_ERROR) return — back off briefly so a failing call can't hot-loop.
			time.Sleep(2 * time.Second)
			continue
		}
		// Coalesce the burst a roam emits, then act on the settled state (converge reads the live config).
		time.Sleep(1500 * time.Millisecond)
		onChange()
	}
}

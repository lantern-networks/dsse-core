//go:build windows

// dns_resolver_windows.go — point the system resolver at the local DNS-over-tunnel proxy so DNS rides the (T)
// tunnel and NO plaintext DNS leaves the endpoint (the LAN/ISP never see domain names). This is the Windows
// analog of the macOS agent setup pointing the system resolver at its localhost DNS proxy: the proxy itself
// (startDNSProxy) mirrors the macOS DsseDNSTunnelProxy, and this file is the "agent setup repoints the
// resolver" half that macOS does outside its NE. We snapshot each active interface's IPv4 DNS servers
// (persisted to disk so restore survives a service restart/crash), set them to the proxy loopback address,
// and restore them on clean stop.
//
// Crash note: a clean service stop runs the restore (defer). A force-kill skips it, leaving DNS pointed at the
// loopback — which still resolves as long as the proxy is up (the SCM auto-restarts the service and re-binds
// the proxy). The persisted snapshot lets a later clean stop still restore the real servers. To restore by
// hand: `Set-DnsClientServerAddress -InterfaceIndex <i> -ServerAddresses <a,b>` (or `-ResetServerAddresses`).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// idxU32 parses a decimal interface index string (as stored in resolverEntry/ifaceDNS) to uint32.
func idxU32(s string) uint32 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	return uint32(n)
}

type resolverEntry struct {
	IfIndex  string `json:"ifIndex"`
	Family   string `json:"family"`   // "IPv4" | "IPv6" (PowerShell AddressFamily)
	Loopback string `json:"loopback"` // what to set this iface's DNS to (127.0.0.1 or ::1)
	Servers  string `json:"servers"`  // comma-separated prior DNS servers (for restore)
}

type resolverSnapshot struct {
	Entries []resolverEntry `json:"entries"`
}

// resolverBackupPath stores the pre-takeover DNS config next to the binary so restore survives a restart.
func resolverBackupPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dsse_dns_resolver_backup.json"
	}
	return filepath.Join(filepath.Dir(exe), "dsse_dns_resolver_backup.json")
}

// familyParams maps a bound loopback IP to the PowerShell AddressFamily and the IPv default-route prefix used
// to scope the takeover to egress interfaces only.
func familyParams(loopback string) (family, routePrefix string) {
	if strings.Contains(loopback, ":") {
		return "IPv6", "::/0"
	}
	return "IPv4", "0.0.0.0/0"
}

// applyDNS sets each entry's interface DNS to addrFor(entry) via the in-process SetInterfaceDnsSettings API
// (no child process — works in session 0 where powershell.exe/netsh.exe fail with 0xC0000142), then flushes the
// cache. addrFor returns the loopback proxy IP (takeover) or the captured real servers (restore).
func applyDNS(entries []resolverEntry, addrFor func(resolverEntry) string) error {
	if len(entries) == 0 {
		return nil
	}
	var firstErr error
	for _, e := range entries {
		if err := setInterfaceDNS(idxU32(e.IfIndex), e.Family, addrFor(e)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	flushDNSCache()
	return firstErr
}

// resolverManager owns the DNS-takeover set and keeps it tracking the default-route interface(s) across
// network switches (Wi-Fi <-> wired, VPN up/down, new DHCP lease). The startup takeover is a one-shot snapshot
// of the egress interfaces at boot; without reconciliation, switching the active link to an interface that was
// NOT egress at boot leaves that interface's DNS on its real servers — so traffic on the new link resolves
// directly and BYPASSES the steered/tunnelled DNS. (That is exactly why a Wi-Fi->wired switch "fixed" a stuck
// box before: the wired link was never taken over, so it quietly bypassed steering — undesirable.) reconcile()
// re-applies the takeover to whatever is currently the default-route interface, so DNS follows the active link.
//
// `bound` is the set of loopback addresses the proxy is actually listening on (e.g. ["127.0.0.1","::1"]); only
// those families are ever taken over. The captured pre-takeover servers are persisted so a clean stop (and the
// --mode recover path) restores them — and the manager, not a startup-captured closure, is the single source of
// truth, so interfaces adopted later by reconcile() are restored too.
type resolverManager struct {
	mu      sync.Mutex
	bound   []string          // loopback addresses with a live listener
	loopFor map[string]string // family ("IPv4"/"IPv6") -> loopback to point at
	entries []resolverEntry   // authoritative taken-over set (keyed by ifIndex|family)
	backup  string
}

func newResolverManager(bound []string) *resolverManager {
	loopFor := map[string]string{}
	for _, l := range bound {
		fam, _ := familyParams(l)
		loopFor[fam] = l
	}
	return &resolverManager{bound: bound, loopFor: loopFor, backup: resolverBackupPath()}
}

func (m *resolverManager) persist() {
	if data, err := json.MarshalIndent(resolverSnapshot{Entries: m.entries}, "", "  "); err == nil {
		if err := os.WriteFile(m.backup, data, 0o600); err != nil {
			fmt.Printf("dns_resolver: WARNING could not persist DNS backup to %s: %v\n", m.backup, err)
		}
	}
}

// start loads any persisted backup (the captured originals, needed to recover an interface that is currently on
// the loopback after a crash) and then converges DNS to the desired state. Returns the captured upstream
// servers (for the --fail-open fallback).
func (m *resolverManager) start() ([]string, error) {
	m.mu.Lock()
	var snap resolverSnapshot
	if b, err := os.ReadFile(m.backup); err == nil && json.Unmarshal(b, &snap) == nil && len(snap.Entries) > 0 {
		fmt.Printf("dns_resolver: loaded persisted DNS backup (%d interface(s)) from %s\n", len(snap.Entries), m.backup)
		m.entries = snap.Entries
	}
	m.mu.Unlock()
	if _, err := m.converge(); err != nil {
		return nil, err
	}
	fmt.Printf("dns_resolver: system DNS pointed at the local proxy on the default-route interface(s) — DNS rides the (T) tunnel (no plaintext leak, IPv4+IPv6)\n")
	return m.upstreams(), nil
}

// converge drives DNS to the desired state in ONE pass: every CURRENT default-route (egress) interface is
// pointed at the loopback proxy, and every interface we previously took over that is NO LONGER egress is
// restored to its real servers. This is what makes DNS follow a Wi-Fi<->wired switch — the newly-active link is
// taken over and the link that went idle is handed back its own resolver (so an idle Wi-Fi isn't stuck on a
// loopback that only resolves over a tunnel for traffic it isn't carrying). Idempotent and quiet in steady
// state. Returns true if it changed anything (so the caller can refresh the fail-open upstream list).
func (m *resolverManager) converge() (changed bool, err error) {
	state, err := egressDNSState(m.bound)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	captured := map[string]resolverEntry{}
	for _, e := range m.entries {
		captured[e.IfIndex+"|"+e.Family] = e
	}
	toLoopback, toRestore, keep := planConverge(state, m.loopFor, captured)
	if len(toLoopback) == 0 && len(toRestore) == 0 {
		m.entries = keep // keep the tracked set in sync even when no DNS write is needed
		return false, nil
	}
	if len(toLoopback) > 0 {
		if err := applyDNS(toLoopback, func(e resolverEntry) string { return e.Loopback }); err != nil {
			fmt.Printf("dns_resolver: converge takeover apply failed: %v\n", err)
		}
	}
	if len(toRestore) > 0 {
		if err := applyDNS(toRestore, func(e resolverEntry) string { return e.Servers }); err != nil {
			fmt.Printf("dns_resolver: converge restore apply failed: %v\n", err)
		}
	}
	m.entries = keep
	m.persist()
	fmt.Printf("dns_resolver: network change — %d interface(s) taken over (now egress), %d restored (no longer egress); DNS follows the active default-route link\n", len(toLoopback), len(toRestore))
	return true, nil
}

// reconcile is the periodic driver of converge (one tick of the default-route follower).
func (m *resolverManager) reconcile() (bool, error) { return m.converge() }

// restoreToAutomatic resets every taken-over interface to AUTOMATIC (DHCP-sourced) DNS — not the captured
// static servers — flushes the cache, deletes the backup, and clears the tracked set. Used on DISARM: disarm
// means steering failed and the box is going native, and it may now be on a DIFFERENT network than when we
// captured (a Wi-Fi roam to another SSID/subnet) — so the OLD static servers would be unreachable and leave DNS
// dead. Resetting to automatic lets the CURRENT network's DHCP resolver take over, which is what makes a network
// switch recover instead of staying dark. On re-arm, converge re-captures fresh from the live config.
func (m *resolverManager) restoreToAutomatic() {
	if err := resetAllResolvers(); err != nil {
		fmt.Printf("dns_resolver: reset-to-automatic failed: %v\n", err)
	}
	m.mu.Lock()
	n := len(m.entries)
	m.entries = nil // re-arm's converge will re-capture from the (possibly new) network's DHCP DNS
	m.mu.Unlock()
	_ = os.Remove(m.backup)
	fmt.Printf("dns_resolver: reset %d interface(s) to automatic DNS — the native network's resolver is now in effect\n", n)
}

// restore returns every taken-over interface to its captured servers and deletes the backup (clean stop).
func (m *resolverManager) restore() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := applyDNS(m.entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		fmt.Printf("dns_resolver: restore failed: %v\n", err)
	}
	_ = os.Remove(m.backup)
	fmt.Printf("dns_resolver: system DNS restored on %d interface(s)\n", len(m.entries))
}

// upstreams returns the current captured upstream resolver(s) for the --fail-open fallback (refreshed as
// converge adopts new interfaces, so fail-open resolution matches whatever link is now active).
func (m *resolverManager) upstreams() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return upstreamServers(m.entries)
}

// planConverge is the pure decision behind converge(). Given the current per-interface DNS state, the loopback
// per family, and the set of interfaces we previously captured, it returns: the interfaces to point at the
// loopback (current egress not already on loopback), the interfaces to restore to their real servers (previously
// captured, no longer egress, currently on loopback), and the new tracked set (the egress interfaces only).
func planConverge(state []ifaceDNS, loopFor map[string]string, captured map[string]resolverEntry) (toLoopback, toRestore, keep []resolverEntry) {
	cur := map[string]ifaceDNS{}
	egress := map[string]bool{}
	for _, s := range state {
		if _, ok := loopFor[s.Family]; !ok {
			continue // family with no proxy listener — never touch it
		}
		key := s.IfIndex + "|" + s.Family
		cur[key] = s
		if s.Egress {
			egress[key] = true
		}
	}
	// 1. Every current egress interface should be on the loopback.
	for key := range egress {
		s := cur[key]
		loop := loopFor[s.Family]
		e, known := captured[key]
		if !known {
			if s.Servers == loop {
				continue // already on loopback but we lost its original servers — leave it, no restore target recorded
			}
			e = resolverEntry{IfIndex: s.IfIndex, Family: s.Family, Loopback: loop, Servers: s.Servers}
		}
		e.Loopback = loop
		keep = append(keep, e)
		if s.Servers != loop {
			toLoopback = append(toLoopback, e)
		}
	}
	// 2. Anything we captured that is no longer egress: restore it to its real servers (only if it's currently
	//    still on the loopback) and drop it from the tracked set.
	for key, e := range captured {
		if egress[key] {
			continue
		}
		if s, ok := cur[key]; !ok || s.Servers == loopFor[e.Family] {
			toRestore = append(toRestore, e)
		}
	}
	return toLoopback, toRestore, keep
}

// egressDNSState reports every interface/family that has DNS servers set: its family, ifIndex, comma-joined
// servers, and whether it currently owns a default route (is an egress interface). The reconcile loop uses this
// to find default-route interfaces not yet pointed at the loopback proxy. Backed by the in-process
// GetAdaptersAddresses + GetBestInterfaceEx API (no child process — session-0 safe).
func egressDNSState(bound []string) ([]ifaceDNS, error) {
	return enumInterfaceDNS(bound)
}

type ifaceDNS struct {
	Family  string
	IfIndex string
	Servers string
	Egress  bool
}

// upstreamServers flattens the snapshot's per-interface DNS servers into a unique list (preserving order) for
// the --fail-open path to forward to when the Edge is unreachable. These are the REAL resolvers the box used
// before the takeover (e.g. 192.0.2.1, the lab DC), so fail-open resolution matches the box's environment.
func upstreamServers(entries []resolverEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, s := range strings.Split(e.Servers, ",") {
			s = strings.TrimSpace(s)
			if s == "" || s == "127.0.0.1" || s == "::1" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// restoreResolverFromBackup restores the system DNS servers from the persisted backup WITHOUT a running proxy —
// the standalone recovery path used by `--mode recover` after an unclean exit (force-kill / crash / WFP BSOD)
// left DNS pointed at the now-dead loopback proxy. Returns the number of interfaces restored. If no backup
// exists (clean state, or it was already consumed), it returns (0, nil) and the caller falls back to
// resetAllResolvers so a wedged box still recovers to automatic DNS.
func restoreResolverFromBackup() (int, error) {
	backup := resolverBackupPath()
	b, err := os.ReadFile(backup)
	if err != nil {
		return 0, nil // no backup -> nothing to restore from here
	}
	var snap resolverSnapshot
	if json.Unmarshal(b, &snap) != nil || len(snap.Entries) == 0 {
		return 0, nil
	}
	if err := applyDNS(snap.Entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		return 0, fmt.Errorf("restore from backup: %w", err)
	}
	_ = os.Remove(backup)
	return len(snap.Entries), nil
}

// resetAllResolvers returns every interface to automatic (DHCP/RA-sourced) DNS and flushes the cache. This is
// the no-backup fallback for `--mode recover`: even with no snapshot to restore exact servers, it pulls the
// resolver off any dead loopback so name resolution works again. Set-DnsClientServerAddress -ResetServerAddresses
// is a no-op on interfaces already automatic, so this is safe to run broadly.
func resetAllResolvers() error {
	// Enumerate both families, find interfaces currently pointed at a loopback proxy, and reset those to automatic
	// (DHCP) DNS via SetInterfaceDnsSettings with a NULL name server — all in-process (session-0 safe).
	state, err := enumInterfaceDNS([]string{"127.0.0.1", "::1"})
	if err != nil {
		return err
	}
	var firstErr error
	for _, s := range state {
		onLoopback := false
		for _, srv := range strings.Split(s.Servers, ",") {
			if srv = strings.TrimSpace(srv); srv == "127.0.0.1" || srv == "::1" {
				onLoopback = true
			}
		}
		if !onLoopback {
			continue
		}
		if err := setInterfaceDNS(idxU32(s.IfIndex), s.Family, ""); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	flushDNSCache()
	return firstErr
}

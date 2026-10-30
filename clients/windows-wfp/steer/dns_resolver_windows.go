//go:build windows

// dns_resolver_windows.go — point the system resolver at the local DNS-over-tunnel proxy so DNS rides the (T)
// tunnel and NO plaintext DNS leaves the endpoint (the LAN/ISP never see domain names). This is the Windows
// analog of the macOS agent setup pointing the system resolver at its localhost DNS proxy: the proxy itself
// (startDNSProxy) mirrors the macOS DsseDNSTunnelProxy, and this file is the "agent setup repoints the
// resolver" half that macOS does outside its NE. We snapshot each active interface's DNS servers
// (persisted to disk so restore survives a service restart/crash), set them to the proxy loopback address,
// and restore them on clean stop.
//
// Crash note: a clean service stop runs the restore (defer). A force-kill skips it, leaving DNS pointed at the
// loopback — which still resolves as long as the proxy is up (the SCM auto-restarts the service and re-binds
// the proxy). The persisted snapshot lets a later clean stop still restore the real servers. To restore by
// hand: `Set-DnsClientServerAddress -InterfaceIndex <i> -ServerAddresses <a,b>` (or `-ResetServerAddresses`).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	// backupData is the exact last version read or published by this manager.
	// Mismatch checks detect stale writers but are not a cross-process CAS.
	backupData []byte
}

func newResolverManager(bound []string) *resolverManager {
	loopFor := map[string]string{}
	for _, l := range bound {
		fam, _ := familyParams(l)
		loopFor[fam] = l
	}
	return &resolverManager{bound: bound, loopFor: loopFor, backup: resolverBackupPath()}
}

func decodeResolverBackup(data []byte) ([]resolverEntry, error) {
	var snap resolverSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("invalid DNS backup: %w", err)
	}
	if len(snap.Entries) == 0 {
		return nil, errors.New("invalid DNS backup: no captured interfaces")
	}
	seen := make(map[string]bool, len(snap.Entries))
	for _, e := range snap.Entries {
		loop := net.ParseIP(e.Loopback)
		if idxU32(e.IfIndex) == 0 || (e.Family != "IPv4" && e.Family != "IPv6") ||
			strings.TrimSpace(e.Servers) == "" || loop == nil || !loop.IsLoopback() ||
			(e.Family == "IPv4" && loop.To4() == nil) ||
			(e.Family == "IPv6" && loop.To4() != nil) {
			return nil, errors.New("invalid DNS backup: malformed interface")
		}
		key := e.IfIndex + "|" + e.Family
		if seen[key] {
			return nil, errors.New("invalid DNS backup: duplicate interface")
		}
		seen[key] = true
	}
	return snap.Entries, nil
}

// publishSnapshot writes a complete new file alongside the backup and then
// publishes it in one filesystem operation. First publication is no-replace:
// a stale or concurrently created original must never be silently overwritten.
// Later versions refuse an already-observed mismatch with the last version
// this manager read. Recovery must stop the service before running: a separate
// process could still change the file between this check and Rename.
func (m *resolverManager) publishSnapshot(entries []resolverEntry) error {
	if len(entries) == 0 {
		return errors.New("refusing to publish an empty DNS backup")
	}
	data, err := json.MarshalIndent(resolverSnapshot{Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	if _, err := decodeResolverBackup(data); err != nil {
		return err
	}
	if m.backupData != nil {
		current, err := os.ReadFile(m.backup)
		if err != nil || !bytes.Equal(current, m.backupData) {
			return errors.New("DNS backup changed or disappeared; refusing replacement")
		}
		if bytes.Equal(data, current) {
			return nil
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.backup), ".dsse-dns-backup-*")
	if err != nil {
		return fmt.Errorf("prepare DNS backup: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("protect DNS backup: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write DNS backup: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync DNS backup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close DNS backup: %w", err)
	}
	if m.backupData == nil {
		if err := os.Link(tmp.Name(), m.backup); err != nil {
			return fmt.Errorf("publish new DNS backup without replacement: %w", err)
		}
	} else if err := os.Rename(tmp.Name(), m.backup); err != nil {
		return fmt.Errorf("replace DNS backup atomically: %w", err)
	}
	m.backupData = data
	return nil
}

func (m *resolverManager) removeSnapshot() error {
	if m.backupData == nil {
		if _, err := os.Stat(m.backup); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("DNS backup exists without manager ownership")
	}
	current, err := os.ReadFile(m.backup)
	if err != nil || !bytes.Equal(current, m.backupData) {
		return errors.New("DNS backup changed or disappeared; refusing removal")
	}
	if err := os.Remove(m.backup); err != nil {
		return fmt.Errorf("remove restored DNS backup: %w", err)
	}
	m.backupData = nil
	return nil
}

// start loads any persisted backup (the captured originals, needed to recover an interface that is currently on
// the loopback after a crash) and then converges DNS to the desired state. Returns the captured upstream
// servers (for the --fail-open fallback).
func (m *resolverManager) start() ([]string, error) {
	m.mu.Lock()
	err := withDNSBackupLock(m.backup, func() error {
		if b, err := os.ReadFile(m.backup); err == nil {
			entries, err := decodeResolverBackup(b)
			if err != nil {
				return err // preserve an unreadable original; never overwrite it
			}
			fmt.Printf("dns_resolver: loaded persisted DNS backup (%d interface(s)) from %s\n", len(entries), m.backup)
			m.entries = entries
			m.backupData = bytes.Clone(b)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read DNS backup: %w", err)
		}
		return nil
	})
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
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
	m.mu.Lock()
	defer m.mu.Unlock()
	err = withDNSBackupLock(m.backup, func() error {
		var inner error
		changed, inner = m.convergeLocked()
		return inner
	})
	return changed, err
}

func (m *resolverManager) convergeLocked() (changed bool, err error) {
	state, err := egressDNSState(m.bound)
	if err != nil {
		return false, err
	}
	captured := map[string]resolverEntry{}
	for _, e := range m.entries {
		captured[e.IfIndex+"|"+e.Family] = e
	}
	toLoopback, toRestore, keep := planConverge(state, m.loopFor, captured)
	if len(toLoopback) == 0 && len(toRestore) == 0 {
		// An interface can already have left loopback (for example after an
		// external network reconfiguration). Do not forget its in-memory
		// original while a stale backup is still on disk.
		if len(keep) != len(m.entries) {
			if len(keep) == 0 {
				if err := m.removeSnapshot(); err != nil {
					return false, err
				}
			} else if err := m.publishSnapshot(keep); err != nil {
				return false, err
			}
		}
		m.entries = keep
		return false, nil
	}
	// Include every original that may be changed in a crash-recoverable backup
	// BEFORE touching any interface. A write failure leaves system DNS alone.
	pending := append([]resolverEntry(nil), m.entries...)
	seen := make(map[string]bool, len(pending))
	for _, e := range pending {
		seen[e.IfIndex+"|"+e.Family] = true
	}
	for _, e := range append(append([]resolverEntry(nil), toLoopback...), toRestore...) {
		key := e.IfIndex + "|" + e.Family
		if !seen[key] {
			pending = append(pending, e)
			seen[key] = true
		}
	}
	if err := m.publishSnapshot(pending); err != nil {
		return false, fmt.Errorf("DNS backup required before resolver change: %w", err)
	}
	m.entries = pending // also retain originals in memory if an OS write fails
	var applyErr error
	if len(toLoopback) > 0 {
		if err := applyDNS(toLoopback, func(e resolverEntry) string { return e.Loopback }); err != nil {
			applyErr = fmt.Errorf("DNS takeover apply: %w", err)
		}
	}
	if len(toRestore) > 0 {
		if err := applyDNS(toRestore, func(e resolverEntry) string { return e.Servers }); err != nil {
			if applyErr == nil {
				applyErr = fmt.Errorf("DNS restore apply: %w", err)
			}
			// Retain the original resolver values until a later successful restore.
			// Some interfaces may already have been restored; the next pass drops those.
			keep = append(keep, toRestore...)
		}
	}
	if applyErr != nil {
		return true, applyErr
	}
	if err := verifyResolverEntries(append(toLoopback, toRestore...), func(e resolverEntry) string {
		for _, taken := range toLoopback {
			if taken.IfIndex == e.IfIndex && taken.Family == e.Family {
				return e.Loopback
			}
		}
		return e.Servers
	}); err != nil {
		return true, fmt.Errorf("DNS change is not confirmed: %w", err)
	}
	// Only now may restored interfaces leave the backup. The pre-change
	// snapshot remains intact if the final publication/removal fails.
	if len(keep) == 0 {
		if err := m.removeSnapshot(); err != nil {
			return true, err
		}
	} else if err := m.publishSnapshot(keep); err != nil {
		return true, err
	}
	m.entries = keep
	fmt.Printf("dns_resolver: network change — %d interface(s) taken over (now egress), %d restored (no longer egress); DNS follows the active default-route link\n", len(toLoopback), len(toRestore))
	return true, nil
}

// reconcile is the periodic driver of converge (one tick of the default-route follower).
func (m *resolverManager) reconcile() (bool, error) { return m.converge() }

func canonicalDNSList(s string) string {
	var servers []string
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if ip := net.ParseIP(strings.TrimSpace(item)); ip != nil {
			servers = append(servers, ip.String())
		} else if item != "" {
			servers = append(servers, strings.ToLower(strings.TrimSpace(item)))
		}
	}
	return strings.Join(servers, ",")
}

// A successful SetInterfaceDnsSettings call alone does not prove that the
// original was restored. Keep the recovery copy until the OS readback agrees.
func verifyResolverEntries(entries []resolverEntry, expected func(resolverEntry) string) error {
	if len(entries) == 0 {
		return nil
	}
	var families []string
	for _, e := range entries {
		families = append(families, e.Loopback)
	}
	state, err := enumInterfaceDNS(families)
	if err != nil {
		return err
	}
	actual := make(map[string]string, len(state))
	for _, s := range state {
		actual[s.IfIndex+"|"+s.Family] = canonicalDNSList(s.Servers)
	}
	for _, e := range entries {
		key := e.IfIndex + "|" + e.Family
		want := canonicalDNSList(expected(e))
		if got, ok := actual[key]; !ok || got != want {
			return fmt.Errorf("resolver readback mismatch for interface %s family %s", e.IfIndex, e.Family)
		}
	}
	return nil
}

func verifyNoResolverLoopback(loopbacks []string) error {
	state, err := enumInterfaceDNS(loopbacks)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(loopbacks))
	for _, loop := range loopbacks {
		wanted[canonicalDNSList(loop)] = true
	}
	for _, s := range state {
		for _, srv := range strings.Split(canonicalDNSList(s.Servers), ",") {
			if wanted[srv] {
				return fmt.Errorf("resolver still points at loopback on interface %s family %s", s.IfIndex, s.Family)
			}
		}
	}
	return nil
}

// restoreToAutomatic resets every taken-over interface to AUTOMATIC (DHCP-sourced) DNS — not the captured
// static servers — flushes the cache, deletes the backup, and clears the tracked set. Used on DISARM: disarm
// means steering failed and the box is going native, and it may now be on a DIFFERENT network than when we
// captured (a Wi-Fi roam to another SSID/subnet) — so the OLD static servers would be unreachable and leave DNS
// dead. Resetting to automatic lets the CURRENT network's DHCP resolver take over, which is what makes a network
// switch recover instead of staying dark. On re-arm, converge re-captures fresh from the live config.
func (m *resolverManager) restoreToAutomatic() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return withDNSBackupLock(m.backup, m.restoreToAutomaticLocked)
}

func (m *resolverManager) restoreToAutomaticLocked() error {
	if err := resetAllResolvers(); err != nil {
		// Keep the persisted originals and tracked interfaces for recovery. A
		// partial reset must not be reported as a verified native DNS posture.
		return fmt.Errorf("reset DNS to automatic: %w", err)
	}
	if err := verifyNoResolverLoopback(append([]string{"127.0.0.1", "::1"}, m.bound...)); err != nil {
		return fmt.Errorf("automatic DNS readback is unverified: %w", err)
	}
	n := len(m.entries)
	if err := m.removeSnapshot(); err != nil {
		return err
	}
	m.entries = nil // re-arm's converge will re-capture from the (possibly new) network's DHCP DNS
	fmt.Printf("dns_resolver: reset %d interface(s) to automatic DNS — the native network's resolver is now in effect\n", n)
	return nil
}

// restore returns every taken-over interface to its captured servers. A failed
// write or readback retains the backup for standalone recovery.
func (m *resolverManager) restore() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := withDNSBackupLock(m.backup, m.restoreLocked); err != nil {
		fmt.Printf("dns_resolver: restore failed, backup retained: %v\n", err)
	}
}

func (m *resolverManager) restoreLocked() error {
	if len(m.entries) == 0 {
		return nil
	}
	if err := applyDNS(m.entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := verifyResolverEntries(m.entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		return fmt.Errorf("restore is unverified: %w", err)
	}
	if err := m.removeSnapshot(); err != nil {
		return fmt.Errorf("restored DNS but backup retained: %w", err)
	}
	fmt.Printf("dns_resolver: system DNS restored on %d interface(s)\n", len(m.entries))
	m.entries = nil
	return nil
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
	return restoreResolverAt(resolverBackupPath())
}

func restoreResolverAt(backup string) (int, error) {
	var restored int
	err := withDNSBackupLock(backup, func() error {
		var err error
		restored, err = restoreResolverAtLocked(backup)
		return err
	})
	return restored, err
}

func restoreResolverAtLocked(backup string) (int, error) {
	b, err := os.ReadFile(backup)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil // no backup -> caller may reset to automatic
		}
		return 0, fmt.Errorf("read DNS backup: %w", err)
	}
	entries, err := decodeResolverBackup(b)
	if err != nil {
		return 0, err // never discard an unreadable original
	}
	if err := applyDNS(entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		return 0, fmt.Errorf("restore from backup: %w", err)
	}
	if err := verifyResolverEntries(entries, func(e resolverEntry) string { return e.Servers }); err != nil {
		return 0, fmt.Errorf("restore from backup unverified: %w", err)
	}
	m := &resolverManager{backup: backup, backupData: b}
	if err := m.removeSnapshot(); err != nil {
		return 0, err
	}
	return len(entries), nil
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

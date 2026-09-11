//go:build windows

// procbypass_windows.go — application-identity (AppID) bypass for steer-all safety. Mirrors the macOS
// Network Extension's app-based exclusion: never steer traffic from excluded applications (the Automation
// CLI/desktop, the steering agent itself, and any admin-allowlisted app), so steer-all can never break
// their connectivity. The Windows AppID analog is the process IMAGE PATH (stable per install; signing
// subject / MSIX package family name are production refinements).
//
// Ownership resolution uses the OS TCP table (GetExtendedTcpTable, OWNER_PID): the redirect loop maps a
// captured flow's ephemeral local port -> owning PID -> image path, and passes the flow through untouched
// when the app is excluded. This needs no WinDivert SOCKET layer and naturally covers already-open
// connections (so Automation's existing API sockets are protected immediately).
package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandleK               = kernel32.NewProc("CloseHandle")

	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	processQueryLimitedInformation = 0x1000
	afINet                         = 2
	afINet6                        = 23
	tcpTableOwnerPidAll            = 5
)

// processImagePath resolves a PID to its full executable image path (the Windows AppID analog).
func processImagePath(pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	h, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return "", false
	}
	defer procCloseHandleK.Call(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ok, _, _ := procQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf[:size]), true
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// tcpPortOwners returns a map of TCP local port -> owning PID from the OS TCP tables, merging IPv4 AND
// IPv6. IPv6 is essential under steer-all: Chrome and most dual-stack clients connect over IPv6, and
// without the IPv6 owner table every IPv6 flow's owner is unresolved -> fail-open passthrough -> the v6
// flow we just learned to capture is never actually steered. Ephemeral ports rarely collide across
// families; on collision the first owner seen is kept.
func tcpPortOwners() (map[uint16]uint32, error) {
	owners := map[uint16]uint32{}
	// MIB_TCPROW_OWNER_PID (IPv4): 6 DWORDs = 24 bytes [state, localAddr, localPort(off 8), remoteAddr,
	// remotePort, owningPid(off 20)]; localPort is network byte order in the low 2 bytes.
	if err := readTCPOwners(owners, afINet, 24, 8, 20); err != nil {
		return nil, err
	}
	// MIB_TCP6ROW_OWNER_PID (IPv6): 56 bytes [localAddr[16], localScopeId, localPort(off 20), remoteAddr[16],
	// remoteScopeId, remotePort, state, owningPid(off 52)]. Best effort: if IPv6 is disabled, keep IPv4.
	_ = readTCPOwners(owners, afINet6, 56, 20, 52)
	return owners, nil
}

// readTCPOwners reads the GetExtendedTcpTable OWNER_PID table for one address family and merges
// localPort -> owningPid into owners. rowSize/portOff/pidOff describe that family's row layout.
func readTCPOwners(owners map[uint16]uint32, af uintptr, rowSize, portOff, pidOff int) error {
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, af, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, tcpTableOwnerPidAll, 0)
	if ret != 0 {
		return fmt.Errorf("GetExtendedTcpTable(af=%d) failed: %d", af, ret)
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	for i := uint32(0); i < n; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		localPort := uint16(buf[off+portOff])<<8 | uint16(buf[off+portOff+1]) // network byte order
		pid := *(*uint32)(unsafe.Pointer(&buf[off+pidOff]))
		if _, exists := owners[localPort]; !exists {
			owners[localPort] = pid
		}
	}
	return nil
}

// appBypass decides, per ephemeral local port, whether the owning application must never be steered.
// Matching is by image-path substring (case-insensitive) -- the AppID analog -- e.g. "automation" matches
// both the CLI (automation.exe) and the desktop app (Automation.exe). The agent's own image is always bypassed.
// portBypass is a cached per-port decision tagged with the PID it was decided for, so a recycled ephemeral port
// (the old owner closed, a DIFFERENT process reused the port number) is detected on the next lookup and the stale
// decision is discarded rather than returned (fail-open review #29: a stale bypass=true would pass a new flow
// through unsteered).
type portBypass struct {
	pid      uint32
	excluded bool
}

type appBypass struct {
	mu           sync.Mutex
	appSubs      []string              // lowercased exclusion identifiers (substring | publisher: | signed:)
	selfPath     string                // this agent's own image path (always bypassed)
	portDecision map[uint16]portBypass // cached per-port bypass decision, keyed AND validated by owning pid
	pidDecision  map[uint32]bool       // cached per-pid bypass decision
	sigCache     map[string]sigResult  // cached Authenticode lookup per image path (WinVerifyTrust is ~ms)
	owners       map[uint16]uint32     // cached port->pid table
	lastRefresh  time.Time
	refreshEvery time.Duration
	now          func() time.Time
	logged       map[uint16]bool // ports already logged as bypassed (avoid log spam)
}

// sigResult memoises one Authenticode lookup for an image path. All strings are lowercased for case-insensitive
// matching ("" if unsigned/unreadable).
type sigResult struct {
	valid      bool
	publisher  string // signer display name (publisher: rules)
	org        string // Subject Organization O= (subject: rules — the Team-ID analog)
	thumbprint string // leaf cert SHA-256 hex (thumbprint: rules — strongest exact pin)
}

// cachedSignature returns (and memoises) the Authenticode validity + signer identity for an image path. Caller
// holds the same synchronization as pidDecision (b.mu in the hot path; single-thread in bypass-observe).
func (b *appBypass) cachedSignature(path string) sigResult {
	if r, ok := b.sigCache[path]; ok {
		return r
	}
	sig := imageSignature(path)
	r := sigResult{valid: sig.valid, publisher: strings.ToLower(sig.publisher), org: strings.ToLower(sig.org), thumbprint: strings.ToLower(sig.thumbprint)}
	b.sigCache[path] = r
	return r
}

// matchAppRule decides whether ONE exclusion identifier matches a process image. Forms (strongest first):
//
//	thumbprint:<sha256> — bypass only if validly signed AND the leaf signing cert SHA-256 == <sha256> (exact pin,
//	                      the strongest identity; rotates on cert renewal — pair with subject: as the durable rule).
//	subject:<org>       — bypass only if validly signed AND the signer Subject Organization (O=) == <org> (exact).
//	                      The practical macOS-Team-ID analog: stable across app versions and the org's certs.
//	publisher:<name>    — bypass only if validly signed AND the signer display name CONTAINS <name> (looser).
//	signed:<exe>        — bypass only if validly signed AND the image basename == <exe> (no signer binding — weak).
//	<substring>         — legacy image-PATH substring (backward compatible; spoofable, kept for existing rules).
//
// ON THE WFP BACKEND the signature forms cost more than a substring, because the kernel callout matches image
// paths and cannot evaluate Authenticode. Userspace verifies and pushes exact NT paths into the driver's
// table; the driver holds a creating process for up to 60ms so that decision lands before its first flow.
// The guarantee is therefore "decided before the first instruction, OR the hold times out and the first flow
// is steered" — it never falls the wrong way, and stage-0 learning converges after that one flow.
//
// This used to say signature forms only reached LONG-LIVED processes, and use a substring for anything
// short-lived. That was true until 2026-08-06 (discovery was a 30s scan of running processes, so a
// five-second process was never sampled and `signed:winget.exe` enforced nothing while reporting itself
// effective). It is fixed — sticky verified paths, learn-on-steer, and the process-creation hold. Prefer a
// path substring only when it is equally precise: the kernel matches it at classify time with no round trip.
//
// rule + base + lowerPath are all lowercased; signature identity (org/thumbprint/publisher) is lowercased too.
func (b *appBypass) matchAppRule(rule, lowerPath, base string) bool {
	switch {
	case strings.HasPrefix(rule, "thumbprint:"):
		want := strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(rule, "thumbprint:")), ":", "")
		if want == "" {
			return false
		}
		sig := b.cachedSignature(lowerPath)
		return sig.valid && sig.thumbprint != "" && sig.thumbprint == want
	case strings.HasPrefix(rule, "subject:"):
		want := strings.TrimSpace(strings.TrimPrefix(rule, "subject:"))
		if want == "" {
			return false
		}
		sig := b.cachedSignature(lowerPath)
		return sig.valid && sig.org != "" && sig.org == want
	case strings.HasPrefix(rule, "publisher:"):
		want := strings.TrimSpace(strings.TrimPrefix(rule, "publisher:"))
		if want == "" {
			return false
		}
		sig := b.cachedSignature(lowerPath)
		return sig.valid && strings.Contains(sig.publisher, want)
	case strings.HasPrefix(rule, "signed:"):
		want := strings.TrimSpace(strings.TrimPrefix(rule, "signed:"))
		return want != "" && base == want && b.cachedSignature(lowerPath).valid
	default:
		return strings.Contains(lowerPath, rule)
	}
}

// logOncePort reports true the first time a bypassed port should be logged.
func (b *appBypass) logOncePort(port uint16) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.logged == nil {
		b.logged = map[uint16]bool{}
	}
	if b.logged[port] {
		return false
	}
	b.logged[port] = true
	return true
}

func newAppBypass(appSubs []string) *appBypass {
	lowered := make([]string, 0, len(appSubs))
	for _, s := range appSubs {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			lowered = append(lowered, s)
		}
	}
	selfPath, _ := processImagePath(uint32(os.Getpid()))
	b := &appBypass{
		appSubs:      lowered,
		selfPath:     strings.ToLower(selfPath),
		portDecision: map[uint16]portBypass{},
		pidDecision:  map[uint32]bool{},
		sigCache:     map[string]sigResult{},
		owners:       map[uint16]uint32{},
		refreshEvery: 250 * time.Millisecond,
		now:          time.Now,
	}
	b.refreshOwners(true)
	return b
}

// setAppSubs replaces the dynamic bypass substrings (e.g. the verified, server-signed steer-exclusion set
// applied additively over the --bypass-app baseline) and clears the per-pid/per-port decision caches so
// the new set takes effect on the next flow. selfPath stays always-bypassed independently. Safe to call
// from another goroutine: it takes b.mu, the same lock bypassReason holds for the decision path.
func (b *appBypass) setAppSubs(subs []string) {
	lowered := make([]string, 0, len(subs))
	for _, s := range subs {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			lowered = append(lowered, s)
		}
	}
	b.mu.Lock()
	b.appSubs = lowered
	b.pidDecision = map[uint32]bool{}
	b.portDecision = map[uint16]portBypass{}
	b.mu.Unlock()
}

func (b *appBypass) pidBypassed(pid uint32) bool {
	if d, ok := b.pidDecision[pid]; ok {
		return d
	}
	path, ok := processImagePath(pid)
	d := false
	if ok {
		lower := strings.ToLower(path)
		base := strings.ToLower(baseName(path))
		if b.selfPath != "" && lower == b.selfPath {
			d = true
		} else {
			for _, sub := range b.appSubs {
				if b.matchAppRule(sub, lower, base) {
					d = true
					break
				}
			}
		}
	}
	b.pidDecision[pid] = d
	return d
}

func (b *appBypass) refreshOwners(force bool) {
	if !force && b.now().Sub(b.lastRefresh) < b.refreshEvery {
		return
	}
	if owners, err := tcpPortOwners(); err == nil {
		b.owners = owners
		b.lastRefresh = b.now()
	}
}

// bypassReason reports whether the flow with this client ephemeral source port must NOT be steered, and
// why (appid_excluded | owner_unresolved). Resolved decisions are cached per port; on a cache miss the OS
// TCP table is (force-)refreshed so a just-opened flow is resolved promptly. An owner that still cannot be
// resolved is FAIL-OPEN: passed through (never steered) and NOT cached, so it re-resolves on the next
// packet -- a brand-new flow (e.g. Automation's api.anthropic.com:443) is never strangled by a resolution race.
// See appBypassDecision (procbypass.go) for the rationale.
func (b *appBypass) bypassReason(srcPort uint16) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Resolve the CURRENT owner first so a cached decision can be validated against it. Force a fresh table read
	// only on a miss so a just-opened flow is resolved on its first packet.
	pid, ok := b.owners[srcPort]
	if !ok {
		b.refreshOwners(true)
		pid, ok = b.owners[srcPort]
	}
	if !ok {
		// Unknown owner (the flow that held this port is gone / not yet in the table): fail-open passthrough, do
		// NOT cache, and drop any stale decision so a recycled port can't return it (retry on the next packet).
		delete(b.portDecision, srcPort)
		return appBypassDecision(false, false)
	}
	// Cache hit ONLY when the decision was made for the SAME owning pid. If the pid differs, the ephemeral port
	// was recycled to a different process (fail-open review #29) — discard the stale decision and re-resolve.
	if d, ok := b.portDecision[srcPort]; ok && d.pid == pid {
		return appBypassDecision(true, d.excluded)
	}
	excluded := b.pidBypassed(pid)
	b.portDecision[srcPort] = portBypass{pid: pid, excluded: excluded}
	return appBypassDecision(true, excluded)
}

// runBypassObserve prints the current TCP table as port -> pid -> image and which entries would be
// bypassed by the given app rules. Read-only; used to confirm excluded apps (e.g. automation) are
// identifiable before enabling steer-all.
func runBypassObserve(appSubs []string) error {
	b := newAppBypass(appSubs)
	owners, err := tcpPortOwners()
	if err != nil {
		return err
	}
	fmt.Printf("bypass-observe: %d tcp ports; bypass_apps=%v (self=%s)\n", len(owners), b.appSubs, baseName(b.selfPath))
	seen := map[uint32]bool{}
	for _, pid := range owners {
		if seen[pid] {
			continue
		}
		seen[pid] = true
		path, _ := processImagePath(pid)
		mark := ""
		if b.pidBypassed(pid) {
			mark = "  <== BYPASS"
		}
		fmt.Printf("pid=%d image=%s%s\n", pid, baseName(path), mark)
	}
	return nil
}

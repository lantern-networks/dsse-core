//go:build windows

// capture_wfp_appid_windows.go — Phase 2 of Windows AppID parity (docs/windows_steer_exclusion_appid_parity_analysis.md):
// make SIGNATURE-based steer exclusions (subject:/thumbprint:/publisher:/signed:) actually ENFORCE on the
// production WFP kernel backend. The kernel callout can only match the connecting flow's ALE_APP_ID (image path),
// not verify Authenticode in-kernel. So userspace does the crypto: it enumerates running processes, verifies each
// image's signer identity against the active signature rules, and pushes the EXACT NT device paths of the matches
// into the driver's verified-exact-APP_ID table. The kernel then bypasses a flow whose APP_ID matches one exactly.
// Identity is owned by userspace (verified); enforcement is the kernel's (exact path) — the macOS-Team-ID model
// adapted to a kernel data plane.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32AppID                = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32AppID.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32AppID.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32AppID.NewProc("Process32NextW")
)

const (
	th32csSnapProcess     = 0x00000002
	processNameNative     = 0x00000001 // QueryFullProcessImageNameW: return the \Device\HarddiskVolumeN\... form
	invalidHandleValueU   = ^uintptr(0)
	exactAppResolveEvery  = 30 * time.Second // re-scan running processes for signature matches this often
	exactAppReverifyEvery = 5 * time.Minute  // drop the signature cache this often so a swapped binary is re-checked (TOCTOU bound)
)

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// enumPIDs returns the PIDs of all running processes (Toolhelp snapshot). Best-effort: empty on failure.
func enumPIDs() []uint32 {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == invalidHandleValueU {
		return nil
	}
	defer procCloseHandleK.Call(snap)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []uint32
	if r, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe))); r == 0 {
		return nil
	}
	for {
		if pe.ProcessID != 0 {
			out = append(out, pe.ProcessID)
		}
		if r, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe))); r == 0 {
			break
		}
	}
	return out
}

// processImagePathNT resolves a PID to its NT device-path image (\Device\HarddiskVolumeN\...), the same form WFP
// reports as ALE_APP_ID — so an exact compare in the kernel is apples-to-apples. "" if unavailable.
func processImagePathNT(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandleK.Call(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ok, _, _ := procQueryFullProcessImageNameW.Call(h, processNameNative, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// --- learn-on-steer -------------------------------------------------------------------------------------
//
// A periodic scan can only ever see processes that happen to be alive when it runs, which is why
// `signed:winget.exe` enforced nothing: winget lives about five seconds and the scan runs every thirty.
// A STEERED FLOW is a strictly better discovery signal — at that instant the process is guaranteed alive,
// and it is provably interesting because it is the exact thing the rule was supposed to prevent.

// steeredApp carries the two path forms of a process whose flow is being steered. Both are resolved INLINE on
// the flow path because the process may exit microseconds later; only the (millisecond) Authenticode check is
// deferred to the resolver goroutine.
type steeredApp struct{ win32, nt string }

// exactAppLearnCh is the resolver's inbox, published only while a resolver is running. nil => the hook below
// costs one atomic load and returns, so a deployment with no signature rules pays nothing.
var exactAppLearnCh atomic.Pointer[chan steeredApp]

func init() {
	noteSteeredPID = func(pid uint32) {
		// Check the RULE flag first, not just the inbox. The resolver publishes its channel on every WFP
		// deployment, so gating on the channel alone meant every steered flow resolved two process paths for
		// an inbox with nothing to match them against. Cheap, but pure waste, and the steer_mux comment
		// claiming this was a no-op without signature rules was simply not true as written.
		if !sigRulesActive.Load() || pid == 0 {
			return
		}
		chp := exactAppLearnCh.Load()
		if chp == nil {
			return
		}
		win32, ok := processImagePath(pid)
		if !ok || win32 == "" {
			return
		}
		nt := processImagePathNT(pid)
		if nt == "" {
			return
		}
		select {
		case *chp <- steeredApp{win32: win32, nt: nt}:
		default: // inbox full: drop it. The periodic scan is the backstop; a flow must never wait on this.
		}
	}
}

// --- the verified set -----------------------------------------------------------------------------------

// verifiedApp is one image userspace has verified against a signature-form exclusion. Both path forms are
// kept: Authenticode verification needs the Win32 path, the kernel compares the NT device path to ALE_APP_ID.
type verifiedApp struct {
	win32    string
	nt       string
	lastSeen time.Time
}

// verifiedAppStore is the STICKY set of verified images. It deliberately does NOT track which processes are
// currently running. The previous implementation rebuilt the pushed set from live processes on every tick,
// so a verified path EVAPORATED the moment its process exited — meaning even a lucky catch bought nothing and
// the next launch of the same binary was steered again. Membership is a property of the IMAGE, not of any
// process, so it is retained until the rule set changes or re-verification rejects it.
type verifiedAppStore struct {
	mu   sync.Mutex
	apps map[string]verifiedApp // key: lowercased NT path
}

func newVerifiedAppStore() *verifiedAppStore {
	return &verifiedAppStore{apps: map[string]verifiedApp{}}
}

func (s *verifiedAppStore) add(a verifiedApp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[strings.ToLower(a.nt)] = a
}

// touch refreshes recency without re-running the crypto, and reports whether the entry was already known.
func (s *verifiedAppStore) touch(nt string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(nt)
	a, ok := s.apps[key]
	if !ok {
		return false
	}
	a.lastSeen = now
	s.apps[key] = a
	return true
}

// keep drops the entries pred rejects. pred runs OUTSIDE the store lock (it does Authenticode work and takes
// the matcher's lock) to keep the two locks from ever nesting.
//
// It DELETES the rejected keys rather than replacing the map with the survivors, and that distinction is the
// whole point. Replacement discards anything added between the snapshot and the write — and the writers are
// real: the process-creation hold path and learn-on-steer both add() from other goroutines, while this runs
// on every rule change and every 5-minute re-verification, whose duration is N x WinVerifyTrust and can reach
// seconds with a cold CRL. A binary decided at process creation during a sweep would lose its entry moments
// after it was pushed to the kernel — the same "wiped 60ms after it reached the kernel" failure that was
// already fixed once, resurrected through a different door. Caught in the macOS-side review, not by a test.
//
// An entry added mid-sweep escapes this round of re-verification, which is correct: it was verified moments
// ago, and the next sweep covers it.
func (s *verifiedAppStore) keep(pred func(verifiedApp) bool) {
	s.mu.Lock()
	all := make([]verifiedApp, 0, len(s.apps))
	for _, a := range s.apps {
		all = append(all, a)
	}
	s.mu.Unlock()
	var rejected []string
	for _, a := range all {
		if !pred(a) {
			rejected = append(rejected, strings.ToLower(a.nt))
		}
	}
	if len(rejected) == 0 {
		return
	}
	s.mu.Lock()
	for _, k := range rejected {
		delete(s.apps, k)
	}
	s.mu.Unlock()
}

// sigRulesActive reports whether any signature-form rule is in force. Read on the flow path, so it must stay
// a single atomic load: without it every steered flow paid two OpenProcess calls to resolve paths for a
// learn-on-steer inbox that had nothing to match them against. The resolver is the only writer.
var sigRulesActive atomic.Bool

// list returns the NT paths to push, capped at wfpMaxExactApps by dropping the LEAST RECENTLY SEEN first (the
// kernel table is a fixed 16 entries), then sorted so an unchanged set compares equal and skips a re-push.
//
// Truncation is REPORTED, never silent. Past the cap some binary begins a cycle of hold -> steer -> relearn,
// and without a line saying so there is nothing to explain it — "no silent caps" is this codebase's own rule
// and it was being broken here. Raising the cap needs DSSE_MAX_EXACT_APPS and the Go mirror to move together
// with a POLICY_VERSION bump; the log comes first so the condition is at least visible.
func (s *verifiedAppStore) list() []string {
	s.mu.Lock()
	all := make([]verifiedApp, 0, len(s.apps))
	for _, a := range s.apps {
		all = append(all, a)
	}
	s.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].lastSeen.After(all[j].lastSeen) })
	if len(all) > wfpMaxExactApps {
		dropped := all[wfpMaxExactApps:]
		names := make([]string, 0, len(dropped))
		for _, a := range dropped {
			names = append(names, baseName(a.win32))
		}
		fmt.Fprintf(os.Stderr, "steer_capture: %d signature-verified app(s) exceed the kernel's %d-entry table; dropping the least recently seen: %s — they will be held and re-learned on each launch until the set shrinks\n",
			len(dropped), wfpMaxExactApps, strings.Join(names, ", "))
		all = all[:wfpMaxExactApps]
	}
	out := make([]string, 0, len(all))
	for _, a := range all {
		out = append(out, a.nt)
	}
	sort.Strings(out)
	return out
}

// verifyAgainstRules reports whether this image satisfies any signature-form rule. rb carries the Authenticode
// cache and the matcher; matchAppRule verifies and memoises the signature.
func verifyAgainstRules(rb *appBypass, sigRules []string, win32 string) bool {
	if len(sigRules) == 0 || win32 == "" {
		return false
	}
	lower := strings.ToLower(win32)
	base := strings.ToLower(baseName(win32))
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for _, rule := range sigRules {
		if rb.matchAppRule(rule, lower, base) {
			return true
		}
	}
	return false
}

// scanRunningIntoStore ADDS newly verified running processes to the store. It is now only the backstop for the
// learn-on-steer path (and the way long-lived processes are picked up at startup); it never removes anything.
func scanRunningIntoStore(rb *appBypass, sigRules []string, store *verifiedAppStore, now time.Time) {
	if len(sigRules) == 0 {
		return
	}
	for _, pid := range enumPIDs() {
		win32, ok := processImagePath(pid)
		if !ok || win32 == "" {
			continue
		}
		nt := processImagePathNT(pid)
		if nt == "" {
			continue
		}
		if store.touch(nt, now) { // already verified: refresh recency, skip the crypto
			continue
		}
		if verifyAgainstRules(rb, sigRules, win32) {
			store.add(verifiedApp{win32: win32, nt: nt, lastSeen: now})
		}
	}
}

// signatureRules filters an effective exclusion set down to the signature-based forms (the only ones this
// resolver enforces; substring rules are already pushed directly to the kernel as substrings).
func signatureRules(effective []string) []string {
	var out []string
	for _, r := range effective {
		if isSignatureRule(r) {
			out = append(out, strings.ToLower(strings.TrimSpace(r)))
		}
	}
	return out
}

// runExactAppResolver periodically resolves the verified exact-APP_ID bypass set and, when it changes, re-pushes
// the kernel policy so signature exclusions take effect on the WFP backend. effectiveRules() returns the current
// signature-form rules (recomputed each tick so a live exclusion-sync change is picked up). Stops with stop.
func runExactAppResolver(stop <-chan struct{}, cfg captureConfig, effectiveRules func() []string, resolveEvery, reverifyEvery time.Duration) {
	if cfg.verifiedExactApps == nil {
		return
	}
	if resolveEvery <= 0 {
		resolveEvery = exactAppResolveEvery
	}
	if reverifyEvery <= 0 {
		reverifyEvery = exactAppReverifyEvery
	}
	rb := newAppBypass(nil) // dedicated signature cache + matcher (no owner table needed)
	store := newVerifiedAppStore()
	learn := make(chan steeredApp, 64)
	exactAppLearnCh.Store(&learn)
	defer exactAppLearnCh.Store(nil)

	var lastRules []string
	var lastReverify time.Time

	// sortedRules keeps the change detection below from firing on mere ordering differences.
	sortedRules := func() []string {
		r := append([]string(nil), effectiveRules()...)
		sort.Strings(r)
		return r
	}

	publish := func() {
		next := store.list()
		prev := cfg.verifiedExactApps.Load()
		if prev != nil && sameStrings(*prev, next) {
			return
		}
		cfg.verifiedExactApps.Store(&next)
		if err := pushPolicy(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "wfp: re-push verified exact-app bypass: %v\n", err)
			return
		}
		fmt.Printf("steer_capture: verified exact-app bypass updated -> %d signature-verified app path(s) enforced on the WFP backend\n", len(next))
	}

	sweep := func(now time.Time) {
		rules := sortedRules()
		sigRulesActive.Store(len(rules) > 0) // gates the flow-path hook and the process-creation hold
		if !sameStrings(rules, lastRules) {
			// A rule changed. RE-VERIFY rather than reset: dropping everything would also discard entries that
			// still satisfy rules which did not change — including one learned from a flow moments earlier,
			// which is exactly what happened the first time this was tested (an unrelated rule was added and
			// wiped a just-learned entry 60ms after it was pushed). Re-verification handles both directions:
			// an added rule keeps existing entries, a removed one drops whatever no longer matches.
			store.keep(func(a verifiedApp) bool { return verifyAgainstRules(rb, rules, a.win32) })
			lastRules = rules
		}
		if now.Sub(lastReverify) >= reverifyEvery {
			rb.mu.Lock()
			rb.sigCache = map[string]sigResult{}
			rb.mu.Unlock()
			// Bound TOCTOU: a binary swapped on disk must lose its bypass. Re-verify what is held rather than
			// dropping it — an app that merely is not running right now must KEEP its entry, because that
			// evaporation is precisely the defect this store exists to fix.
			store.keep(func(a verifiedApp) bool { return verifyAgainstRules(rb, rules, a.win32) })
			lastReverify = now
		}
		scanRunningIntoStore(rb, rules, store, now)
		publish()
	}

	// Process-creation notification: the only signal that arrives BEFORE the app's first flow. Events are
	// funnelled into the same inbox as learn-on-steer so there is one verification path, not two. A process
	// that exits before we resolve it still verifies, because the driver hands us the NT image path.
	// The driver holds the creating process until this callback returns, so everything here runs SYNCHRONOUSLY
	// and the release is deferred to the earliest possible moment. Async would defeat the point: the whole
	// reason to hold is that the verdict must be in the kernel's table before the process's first instruction.
	// Fast paths (already-known image, no signature rules, not ours) release in microseconds.
	go runProcEventWatcher(stop, func() uint32 {
		active := len(sortedRules()) > 0
		// Refresh here as well as in sweep: this runs on every long-poll (<=2s), whereas sweep is on the 30s
		// ticker, and a rule that arrives just after a sweep would otherwise leave learn-on-steer switched off
		// for most of a minute.
		sigRulesActive.Store(active)
		if !active {
			return 0 // no signature-form rule: never make a launch wait
		}
		return procHoldMs
	}, func(pid uint32, nt string, release func()) {
		defer release()
		win32 := win32PathForProcEvent(pid, nt)
		if win32 == "" {
			return
		}
		// Prefer the NT path resolved from the LIVE process over the driver's string. Both name the same
		// image, but PS_CREATE_NOTIFY_INFO.ImageFileName can arrive in the `\??\C:\...` form while ALE_APP_ID
		// — what the kernel actually compares — is always `\Device\HarddiskVolumeN\...`. Pushing the former
		// stores a second key for one image: it never matches a flow, and it burns one of the sixteen slots.
		// Measured 2026-08-06: one curl invocation produced two entries this way.
		if live := processImagePathNT(pid); live != "" {
			nt = live
		} else if strings.HasPrefix(nt, `\??\`) {
			// The process is already gone and the driver gave the DOS form. Say so rather than push a key that
			// silently cannot match; learn-on-steer will still catch this image on its next flow.
			fmt.Printf("steer_capture: process-notify gave a DOS-form path for an exited process (%s); skipping the exact push, learn-on-steer will catch it\n", baseName(nt))
			return
		}
		now := monotonicNow()
		if store.touch(nt, now) {
			return // already enforced in the kernel: release immediately, no crypto, no push
		}
		if !verifyAgainstRules(rb, sortedRules(), win32) {
			return // not covered by any signature rule
		}
		store.add(verifiedApp{win32: win32, nt: nt, lastSeen: now})
		publish() // pushes the exact-APP_ID table BEFORE the deferred release lets the process run
		fmt.Printf("steer_capture: decided %s at process creation, before its first flow\n", baseName(win32))
	})

	sweep(monotonicNow()) // immediate first resolve
	t := time.NewTicker(resolveEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			sweep(monotonicNow())
		case a := <-learn:
			now := monotonicNow()
			if store.touch(a.nt, now) {
				continue // already enforced; this flow simply predates the push reaching the kernel
			}
			if verifyAgainstRules(rb, sortedRules(), a.win32) {
				store.add(verifiedApp{win32: a.win32, nt: a.nt, lastSeen: now})
				fmt.Printf("steer_capture: learned a signature-verified app from a steered flow -> %s (it was missing from the kernel's exact table; every later flow bypasses)\n", baseName(a.win32))
				publish()
			}
		}
	}
}

// monotonicNow is time.Now wrapped for clarity (the resolver only diffs durations, never wall-clock).
func monotonicNow() time.Time { return time.Now() }

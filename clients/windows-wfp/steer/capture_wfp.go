//go:build windows

// capture_wfp.go — P1 skeleton of the PRODUCTION capture backend on WFP (see
// ). It implements the same SteeringCapture seam as the WinDivert
// backend, so the edge-steering layer and the supervisor () are unchanged.
//
// Datapath (vs WinDivert's packet copy/reinject): a kernel WFP callout at ALE_CONNECT_REDIRECT_V4/V6
// classifies each NEW connection at connect-time -- where the PID/app identity is known ATOMICALLY (no
// AppID race) -- and either lets it go direct (bypass) or redirects it to this local proxy, stashing the
// ORIGINAL destination + identity in the WFP "redirect context". This userspace proxy accepts the
// redirected connection and reads that context back via WSAIoctl, so it never needs conntrack to recover
// the original destination.
//
// STATUS: P1 = userspace half + the driver<->userspace contract. The kernel callout driver (P2) and its
// signing/load (P3, needs Secure Boot off here) are not done yet, so newWFPCapture fails cleanly until the
// driver device is present. The WSAIoctl/struct details are validated end-to-end at P3.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/wfpstate"
)

var (
	ws2_32       = syscall.NewLazyDLL("ws2_32.dll")
	procWSAIoctl = ws2_32.NewProc("WSAIoctl")
)

// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT reads back the context the callout associated with this
// redirected socket. Per the Windows SDK mstcpip.h it is _WSAIOW(IOC_VENDOR, 221) -- NOT _WSAIORW(IOC_WS2,..).
// _WSAIOW(t,n) = IOC_IN(0x80000000) | t | n ; IOC_VENDOR = 0x18000000 ; 221 = 0xDD  ->  0x980000DD.
// (The previous 0xC8000000|37 was a wrong guess; the OS returned WSAEOPNOTSUPP for that unknown code.)
const sioQueryWFPConnectionRedirectContext = 0x80000000 | 0x18000000 | 221

const (
	afInet  = 2
	afInet6 = 23
)

// wfpRedirectContext is the fixed-layout per-flow record the kernel callout writes into the WFP redirect
// context at connect-time, and this proxy reads back after accepting the redirected connection. It MUST
// stay byte-for-byte in lockstep with the driver. Addresses are network byte order (as in the IP header);
// scalar fields (Family, OrigDstPort, ProcessID) are NATIVE order -- both sides are the same little-endian
// host, so the driver writes native and userspace reads native (no swap).
type wfpRedirectContext struct {
	Version     uint32   // contract version (currently 1)
	Family      uint32   // afInet (2) / afInet6 (23)
	OrigDstAddr [16]byte // original destination, network order; first 4 bytes used for IPv4
	OrigDstPort uint16   // original destination port, native order
	_           uint16   // pad
	ProcessID   uint32   // owning PID resolved at connect-time (identity is race-free under WFP)
}

const wfpRedirectContextVersion = 1

// origDst decodes the original destination from the context into a netip.AddrPort.
func (c wfpRedirectContext) origDst() (netip.AddrPort, bool) {
	switch c.Family {
	case afInet:
		var a4 [4]byte
		copy(a4[:], c.OrigDstAddr[:4])
		return netip.AddrPortFrom(netip.AddrFrom4(a4), c.OrigDstPort), true
	case afInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(c.OrigDstAddr), c.OrigDstPort), true
	default:
		return netip.AddrPort{}, false
	}
}

// queryRedirectContext reads the WFP redirect context off an accepted (redirected) socket fd.
func queryRedirectContext(fd uintptr) (wfpRedirectContext, error) {
	var ctx wfpRedirectContext
	var bytesRet uint32
	ret, _, callErr := procWSAIoctl.Call(
		fd,
		uintptr(uint32(sioQueryWFPConnectionRedirectContext)),
		0, 0,
		uintptr(unsafe.Pointer(&ctx)),
		unsafe.Sizeof(ctx),
		uintptr(unsafe.Pointer(&bytesRet)),
		0, 0,
	)
	if ret != 0 {
		return ctx, fmt.Errorf("WSAIoctl(QUERY_WFP_CONNECTION_REDIRECT_CONTEXT): %v", callErr)
	}
	if ctx.Version != wfpRedirectContextVersion {
		return ctx, fmt.Errorf("wfp redirect context version %d (want %d)", ctx.Version, wfpRedirectContextVersion)
	}
	return ctx, nil
}

// wfpCapture is the WFP-backed SteeringCapture. It accepts connections the kernel callout redirected to the
// local proxy and recovers each flow's original destination from the redirect context. Policy (which apps/
// dests to bypass) lives in the driver and is pushed via DeviceIoControl (pushPolicy); the driver decides
// redirect-vs-direct at connect-time, so this proxy only ever sees flows that are meant to be steered.
type wfpCapture struct {
	cfg       captureConfig
	ln4       net.Listener
	ln6       net.Listener
	flows     chan SteeredFlow
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	errMu     sync.Mutex
	termErr   error
	// ownerHandle is held open for exactly as long as this capture is accepting redirected connections. Its
	// close — whether from Close() below or from the OS reaping handles when this process dies however it
	// dies — is what tells the driver the listener behind the redirect is gone. See armPolicyOwner.
	ownerHandle syscall.Handle
}

func (c *wfpCapture) Backend() string           { return "wfp" }
func (c *wfpCapture) Flows() <-chan SteeredFlow { return c.flows }

func (c *wfpCapture) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.termErr
}

func (c *wfpCapture) setTermErr(err error) {
	if err == nil {
		return
	}
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.termErr == nil {
		c.termErr = err
	}
}

func (c *wfpCapture) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.ln4 != nil {
			c.ln4.Close()
		}
		if c.ln6 != nil {
			c.ln6.Close()
		}
		// Clear the policy and CHECK it cleared. This used to be a bare best-effort removePolicy() whose
		// result was discarded — and a disarm that silently failed is not a smaller problem than no disarm at
		// all, it is the same black hole with a log line saying everything is fine.
		if v := removePolicyVerified(); !v.Verified {
			fmt.Printf("steer_disarm: WARNING the WFP redirect may still be armed after shutdown: %s\n", v.Reason)
		}
		// Release ownership last, so the state read above still saw an owner and the driver's own
		// close-handler has nothing left to do. On any path that is NOT a clean shutdown this line never
		// runs, and that is precisely the case the handle exists for.
		if c.ownerHandle != 0 && c.ownerHandle != syscall.InvalidHandle {
			syscall.CloseHandle(c.ownerHandle)
			c.ownerHandle = syscall.InvalidHandle
		}
	})
	return nil
}

// newWFPCapture pushes the bypass policy to the kernel driver, opens the local proxy listeners, and starts
// accepting redirected flows. It fails cleanly if the driver device is absent (P2/P3 not yet deployed).
func newWFPCapture(cfg captureConfig) (*wfpCapture, error) {
	if !cfg.steerAll {
		return nil, fmt.Errorf("wfp backend currently supports --steer-all only")
	}
	// Enable the verified exact-APP_ID bypass channel (Phase 2): a shared, atomically-swappable set the resolver
	// populates so signature exclusions enforce on this kernel backend. Set BEFORE the first push so every
	// pushPolicy (initial, exclusion re-push, resolver re-push) serialises the same shared table.
	if cfg.verifiedExactApps == nil {
		cfg.verifiedExactApps = &atomic.Pointer[[]string]{}
	}
	// Hand the driver the connect-time policy: the local proxy port to redirect to, the never-redirect app
	// image substrings and destination exclusions. Under WFP the owner is known at classify time, so the
	// bypass is race-free and fail-CLOSED is safe (unknown owner cannot happen mid-connect).
	if err := pushPolicy(cfg); err != nil {
		return nil, fmt.Errorf("wfp: push policy to driver (is the callout driver installed/loaded?): %w", err)
	}
	ln4, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.localPort))))
	if err != nil {
		return nil, fmt.Errorf("wfp: listen 127.0.0.1:%d: %w", cfg.localPort, err)
	}
	var ln6 net.Listener
	if l6, err6 := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(int(cfg.localPort)))); err6 == nil {
		ln6 = l6
	}
	c := &wfpCapture{
		cfg:         cfg,
		ln4:         ln4,
		ln6:         ln6,
		flows:       make(chan SteeredFlow),
		done:        make(chan struct{}),
		ownerHandle: syscall.InvalidHandle,
	}
	// Claim ownership of the redirect policy now that the listeners behind it exist. Deliberately AFTER the
	// listeners: the handle's meaning is "someone is accepting redirected connections", and arming it before
	// there was anything to accept them would make it say something untrue for the width of the window.
	//
	// A failure here is NOT fatal. The agent steers correctly without it; what is lost is the automatic
	// disarm when this process dies unexpectedly — the pre-existing behaviour, and on a driver that predates
	// IOCTL_DSSE_ARM_OWNER it is the only possible behaviour. Refusing to steer over it would turn a missing
	// safety net into the very outage the net is for. It is logged loudly instead, because a fail-open
	// endpoint silently running without its disarm path is exactly the kind of quiet regression that gets
	// discovered during an incident.
	if h, err := armPolicyOwner(cfg.disarmOnAgentExit); err != nil {
		fmt.Printf("steer_capture: WARNING could not claim WFP policy ownership (%v) — if this agent dies "+
			"unexpectedly the driver will keep redirecting and the box will refuse connections until "+
			"`dsse-steer --mode recover` runs. Is the loaded driver older than DSSE_OWNER_ARM?\n", err)
	} else {
		c.ownerHandle = h
		fmt.Printf("steer_capture: WFP policy ownership claimed disarm_on_agent_exit=%t (posture: %s)\n",
			cfg.disarmOnAgentExit, wfpstate.PostureLabel(cfg.disarmOnAgentExit))
	}
	fmt.Printf("steer_capture backend=wfp target=ALL-outbound-tcp -> loopback:%d (v6=%t) bypass_apps=%v bypass_dests=%v (connect-time classify; race-free)\n",
		cfg.localPort, ln6 != nil, cfg.bypassApps, cfg.effectiveDests())
	// Signature-based exclusions (subject:/thumbprint:/publisher:/signed:) cannot be evaluated in-kernel (the
	// callout matches image paths only, no Authenticode). They are NOT pushed as substrings (which would never
	// match). Instead the exact-app resolver below verifies them in userspace and pushes the VERIFIED processes'
	// exact NT APP_IDs to the driver's exact table — so they DO enforce on the WFP backend, with crypto identity.
	effApps := cfg.bypassApps
	if cfg.exclusions != nil {
		effApps = cfg.exclusions.effective()
	}
	if n := signatureRuleCount(effApps); n > 0 {
		fmt.Printf("wfp: %d signature-based exclusion(s) — enforced via verified exact-APP_ID push (userspace verifies the signer; the kernel bypasses the exact image path)\n", n)
	}
	// Live signed steer-exclusions: re-push the kernel policy (which buildWFPPolicy builds from the latest
	// effective set) whenever the sync applies a new verified set. Registering here also means a
	// supervisor-recreated capture re-pushes the latest set on its next apply.
	if cfg.exclusions != nil {
		cfg.exclusions.register(func([]string) {
			if err := pushPolicy(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "wfp: re-push signed exclusions to driver: %v\n", err)
			}
		})
	}
	// Live destination bypasses: the Edge slot is filled (or corrected) by the pin refresher, which may resolve
	// LATER than arm time. Same re-push as the signed exclusions above -- buildWFPPolicy reads the live set --
	// and registering here means a supervisor-recreated capture also picks up whatever the refresher has found
	// since the previous one armed.
	if cfg.dests != nil {
		cfg.dests.register(func(now []netip.AddrPort) {
			if err := pushPolicy(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "wfp: re-push destination bypasses to driver: %v\n", err)
				return
			}
			fmt.Printf("steer_capture: destination bypasses updated -> %v\n", now)
		})
	}

	// Exact-APP_ID resolver: verify signature-form exclusions against running processes and push the matches'
	// exact NT paths to the kernel so they enforce on the WFP backend (Phase 2). Recomputes the signature rules
	// each tick so a live exclusion-sync change is honored. Stops when the capture closes.
	if cfg.verifiedExactApps != nil {
		effectiveRules := func() []string {
			eff := cfg.bypassApps
			if cfg.exclusions != nil {
				eff = cfg.exclusions.effective()
			}
			return signatureRules(eff)
		}
		go runExactAppResolver(c.done, cfg, effectiveRules, exactAppResolveEvery, exactAppReverifyEvery)
	}
	c.wg.Add(1)
	go c.acceptLoop(ln4)
	if ln6 != nil {
		c.wg.Add(1)
		go c.acceptLoop(ln6)
	}
	go func() { c.wg.Wait(); close(c.flows) }()
	if cfg.timeout > 0 {
		time.AfterFunc(cfg.timeout, func() { c.Close() })
	}
	return c, nil
}

// acceptLoop accepts redirected connections and surfaces each as a SteeredFlow whose OrigDst comes from the
// WFP redirect context (no conntrack needed). The family is implicit in the recovered address.
func (c *wfpCapture) acceptLoop(ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !c.isClosing() {
				c.setTermErr(fmt.Errorf("wfp accept: %w", err))
			}
			return
		}
		origDst, pid, err := recoverOrigDst(conn)
		if err != nil {
			fmt.Printf("wfp: recover orig dst failed: %v\n", err)
			conn.Close()
			continue
		}
		select {
		case c.flows <- SteeredFlow{OrigDst: origDst, Conn: conn, PID: pid}:
		case <-c.done:
			conn.Close()
			return
		}
	}
}

func (c *wfpCapture) isClosing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// recoverOrigDst reads the original destination AND the owning connect-time PID from a redirected connection's
// WFP context. The PID lets the steerer attribute the flow to the logged-in OS user (see osUserForPID).
func recoverOrigDst(conn net.Conn) (netip.AddrPort, uint32, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, 0, fmt.Errorf("not a TCPConn")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	var ctx wfpRedirectContext
	var ctlErr error
	if cerr := raw.Control(func(fd uintptr) { ctx, ctlErr = queryRedirectContext(fd) }); cerr != nil {
		return netip.AddrPort{}, 0, cerr
	}
	if ctlErr != nil {
		return netip.AddrPort{}, 0, ctlErr
	}
	ap, ok := ctx.origDst()
	if !ok {
		return netip.AddrPort{}, 0, fmt.Errorf("wfp context has no usable original destination (family=%d)", ctx.Family)
	}
	return ap, ctx.ProcessID, nil
}

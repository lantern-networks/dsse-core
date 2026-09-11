//go:build windows

// capture_windivert.go — the WinDivert implementation of SteeringCapture (W2). All WinDivert/OS-specific
// code lives here, behind the SteeringCapture interface, so the edge-steering layer (steer_edge.go) and
// the pure packet logic (steer_core.go) never depend on WinDivert. Replacing this file with a Wintun or
// WFP implementation of the same interface requires no change above the seam.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	winDivertLayerNetwork = 0
	winDivertFlagSniff    = 1
)

// WINDIVERT_ADDRESS flag bits live in byte 10 of the address struct (after Timestamp[0:8], Layer[8],
// Event[9]). Byte 11 is Reserved1; Network.IfIdx/SubIfIdx follow at bytes 16/20.
const (
	addrFlagsByte    = 10
	flagSniffed      = 1 << 0
	flagOutbound     = 1 << 1
	flagLoopback     = 1 << 2
	flagImpostor     = 1 << 3
	flagIPv6         = 1 << 4
	flagIPChecksum   = 1 << 5
	flagTCPChecksum  = 1 << 6
	winDivertAddrLen = 96
)

type winDivertAPI struct {
	open *syscall.LazyProc
	recv *syscall.LazyProc
	send *syscall.LazyProc
}

func newWinDivertAPI() *winDivertAPI {
	dll := syscall.NewLazyDLL("WinDivert.dll")
	return &winDivertAPI{
		open: dll.NewProc("WinDivertOpen"),
		recv: dll.NewProc("WinDivertRecv"),
		send: dll.NewProc("WinDivertSend"),
	}
}

func (api *winDivertAPI) openHandle(filter string, flags uintptr) (syscall.Handle, error) {
	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := api.open.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		uintptr(0),
		flags,
	)
	if handle == 0 || handle == ^uintptr(0) {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WinDivertOpen failed")
	}
	return syscall.Handle(handle), nil
}

func (api *winDivertAPI) recvPacket(handle syscall.Handle, packet, addr []byte) (int, error) {
	var readLen uint32
	ok, _, callErr := api.recv.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&readLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ok == 0 {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WinDivertRecv failed")
	}
	return int(readLen), nil
}

func (api *winDivertAPI) sendPacket(handle syscall.Handle, packet, addr []byte) error {
	var sendLen uint32
	ok, _, callErr := api.send.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ok == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("WinDivertSend failed")
	}
	return nil
}

func addrFlag(addr []byte, bit byte) bool { return addr[addrFlagsByte]&bit != 0 }
func addrSetFlag(addr []byte, bit byte, on bool) {
	if on {
		addr[addrFlagsByte] |= bit
	} else {
		addr[addrFlagsByte] &^= bit
	}
}

func addrIfIdx(addr []byte) (uint32, uint32) {
	ifIdx := uint32(addr[16]) | uint32(addr[17])<<8 | uint32(addr[18])<<16 | uint32(addr[19])<<24
	subIf := uint32(addr[20]) | uint32(addr[21])<<8 | uint32(addr[22])<<16 | uint32(addr[23])<<24
	return ifIdx, subIf
}

func addrSetIfIdx(addr []byte, ifIdx, subIf uint32) {
	addr[16], addr[17], addr[18], addr[19] = byte(ifIdx), byte(ifIdx>>8), byte(ifIdx>>16), byte(ifIdx>>24)
	addr[20], addr[21], addr[22], addr[23] = byte(subIf), byte(subIf>>8), byte(subIf>>16), byte(subIf>>24)
}

// markInjectChecksums tells WinDivert our (steer_core-recomputed) checksums are valid so it does not
// recalculate, and clears the sniff/impostor markers on the outgoing address.
func markInjectChecksums(addr []byte) {
	addrSetFlag(addr, flagSniffed, false)
	addrSetFlag(addr, flagImpostor, false)
	addrSetFlag(addr, flagIPChecksum, true)
	addrSetFlag(addr, flagTCPChecksum, true)
}

// loopbackInject configures the address to re-inject a 127.0.0.1<->127.0.0.1 packet on the loopback
// pseudo-interface (IfIdx 1), which Windows delivers up to the local terminator socket. Empirically a
// loopback packet carries Outbound=1, Loopback=1, IfIdx=1 (see observe mode template flags=0xe7).
func loopbackInject(addr []byte) {
	addrSetFlag(addr, flagOutbound, true)
	addrSetFlag(addr, flagLoopback, true)
	addrSetIfIdx(addr, 1, 0)
	markInjectChecksums(addr)
}

// inboundInject configures the address to re-inject a rewritten return packet inbound on the original
// real interface so the app's socket (src=orig-src, dst=orig-target) receives it.
func inboundInject(addr []byte, ifIdx, subIf uint32) {
	addrSetFlag(addr, flagOutbound, false)
	addrSetFlag(addr, flagLoopback, false)
	addrSetIfIdx(addr, ifIdx, subIf)
	markInjectChecksums(addr)
}

// tcpFlagsStringAt renders the TCP control flags (and payload length) of a TCP packet whose TCP header
// starts at tcpOff, for tracing which packet types traverse the steer NAT (family-agnostic).
func tcpFlagsStringAt(packet []byte, tcpOff int) string {
	if tcpOff+14 > len(packet) {
		return "?"
	}
	flags := packet[tcpOff+13]
	dataOff := int(packet[tcpOff+12]>>4) * 4
	payload := len(packet) - tcpOff - dataOff
	names := []string{}
	for _, f := range []struct {
		bit  byte
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x01, "FIN"}, {0x04, "RST"}} {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, "|") + fmt.Sprintf("(payload=%d)", payload)
}

func directionString(addr []byte) string {
	d := "inbound"
	if addrFlag(addr, flagOutbound) {
		d = "outbound"
	}
	if addrFlag(addr, flagLoopback) {
		d += "/loopback"
	}
	if addrFlag(addr, flagImpostor) {
		d += "/impostor"
	}
	return d
}

// outboundFilter matches the app -> target packets we redirect (observe mode).
func outboundFilter(cfg captureConfig) string {
	return fmt.Sprintf("outbound and tcp and ip.DstAddr == %s and tcp.DstPort == %d", netip.AddrFrom4(cfg.targetIP), cfg.targetPort)
}

// redirectFilter builds the WinDivert capture filter: the app->target(s) outbound clause plus the
// terminator->app return clause (loopback, src 127.0.0.1:localPort). In steer-all mode the outbound
// clause is ALL outbound TCP minus loopback, DNS, and the never-steer destinations (edge endpoint etc.)
// -- pushing those exclusions into the filter so they are dropped before capture (cheap + race-free).
func redirectFilter(cfg captureConfig) string {
	// Return clauses: the loopback terminator -> app packets, matched by family so they are captured and
	// rewritten back. IPv4 always; IPv6 only in steer-all (the v6 terminator exists only then).
	ret4 := fmt.Sprintf("(ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == %d)", cfg.localPort)
	if cfg.steerAll {
		// steer-all captures ALL outbound TCP (v4 and v6): the base clause has no ip-family restriction, so
		// it matches both. Destination exclusions use De Morgan (WinDivert cannot negate a group):
		// not(addr==d and port==p) => (addr!=d or port!=p). Excluded dests are IPv4 (edge/Automation API).
		clauses := []string{"outbound", "loopback == 0", "tcp.DstPort != 53"}
		for _, d := range cfg.bypassDests {
			if d.Addr().Is4() {
				// IPv4-only dest exclusion. The leading `ipv6 or` is essential: on an IPv6 packet `ip.DstAddr`
				// is absent (evaluates false), so without it a v6 packet whose port equals an excluded port
				// (e.g. the Automation API's 443) would make `(ip.DstAddr != X or tcp.DstPort != P)` == false and
				// drop ALL IPv6:443 from capture. `ipv6 or ...` makes the v4 exclusion never apply to v6.
				clauses = append(clauses, fmt.Sprintf("(ipv6 or ip.DstAddr != %s or tcp.DstPort != %d)", d.Addr(), d.Port()))
			}
		}
		outbound := strings.Join(clauses, " and ")
		ret6 := fmt.Sprintf("(ipv6.SrcAddr == ::1 and tcp.SrcPort == %d)", cfg.localPort)
		return fmt.Sprintf("tcp and ((%s) or %s or %s)", outbound, ret4, ret6)
	}
	outbound := fmt.Sprintf("outbound and ip.DstAddr == %s and tcp.DstPort == %d", netip.AddrFrom4(cfg.targetIP), cfg.targetPort)
	return fmt.Sprintf("tcp and ((%s) or %s)", outbound, ret4)
}

// winDivertCapture is the WinDivert-backed SteeringCapture. It opens a redirect handle + a local
// terminator listener, runs the packet-NAT loop and the accept loop, and surfaces each terminated flow
// (with its recovered original destination) on flows.
type winDivertCapture struct {
	cfg       captureConfig
	api       *winDivertAPI
	handle    syscall.Handle
	bypass    *appBypass
	ln4       net.Listener // IPv4 loopback terminator (127.0.0.1:localPort)
	ln6       net.Listener // IPv6 loopback terminator ([::1]:localPort); nil if IPv6 is unavailable
	ct        *conntrack
	flows     chan SteeredFlow
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	errMu     sync.Mutex
	termErr   error // terminal backend error (nil if stopped cleanly); surfaced via Err()
}

// isClosing reports whether Close() has been called (used to distinguish a clean stop from a failure when
// the packet/accept loops unwind on a closed handle/listener).
func (c *winDivertCapture) isClosing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// setTermErr records the first terminal error (only if we are not already shutting down cleanly).
func (c *winDivertCapture) setTermErr(err error) {
	if err == nil || c.isClosing() {
		return
	}
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.termErr == nil {
		c.termErr = err
	}
}

// Err returns the terminal backend error, or nil if the capture stopped cleanly (Close/timeout).
func (c *winDivertCapture) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.termErr
}

// newWinDivertCapture opens the listener + WinDivert redirect handle and starts the packet and accept
// loops. The returned capture surfaces flows on Flows() until its timeout elapses or Close is called.
func newWinDivertCapture(cfg captureConfig) (*winDivertCapture, error) {
	ln4, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cfg.localPort))))
	if err != nil {
		return nil, fmt.Errorf("listen terminator 127.0.0.1:%d: %w", cfg.localPort, err)
	}
	// IPv6 loopback terminator for steer-all (Chrome and most dual-stack clients connect over IPv6). Best
	// effort: if IPv6 is unavailable we keep the v4 terminator and steer only v4 (no hard failure).
	var ln6 net.Listener
	if cfg.steerAll {
		if l6, err6 := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(int(cfg.localPort)))); err6 == nil {
			ln6 = l6
		} else {
			fmt.Fprintf(os.Stderr, "steer_capture ipv6 terminator unavailable (v4-only): %v\n", err6)
		}
	}
	api := newWinDivertAPI()
	filter := redirectFilter(cfg)
	handle, err := api.openHandle(filter, 0) // flags=0: divert (not sniff)
	if err != nil {
		ln4.Close()
		if ln6 != nil {
			ln6.Close()
		}
		return nil, fmt.Errorf("open WinDivert redirect handle (filter=%q): %w", filter, err)
	}
	c := &winDivertCapture{
		cfg:    cfg,
		api:    api,
		handle: handle,
		bypass: newAppBypass(cfg.bypassApps),
		ln4:    ln4,
		ln6:    ln6,
		ct:     newConntrack(2 * time.Minute),
		flows:  make(chan SteeredFlow),
		done:   make(chan struct{}),
	}
	// Live signed steer-exclusions: seed the appBypass with the latest effective set (so a supervisor restart
	// keeps the server exclusions) and register setAppSubs as the live updater the sync drives.
	if cfg.exclusions != nil {
		c.bypass.setAppSubs(cfg.exclusions.effective())
		cfg.exclusions.register(c.bypass.setAppSubs)
	}
	// AppID bypass (steer-all safety): the packet loop resolves each flow's owning app via the OS TCP
	// table and never steers excluded apps (Automation, the agent itself). newAppBypass pre-seeds from the
	// current table so already-open connections (e.g. Automation's API sockets) are protected immediately.
	target := cfg.targetAddrPort().String()
	if cfg.steerAll {
		target = "ALL-outbound-tcp"
	}
	fmt.Printf("steer_capture backend=windivert target=%s -> loopback:%d (v6=%t) bypass_apps=%v bypass_dests=%v (dns+loopback always)\n", target, cfg.localPort, ln6 != nil, cfg.bypassApps, cfg.effectiveDests())
	go c.packetLoop()
	// One accept loop per loopback terminator; flows is closed only after both have exited.
	c.wg.Add(1)
	go c.acceptLoop(c.ln4, false)
	if c.ln6 != nil {
		c.wg.Add(1)
		go c.acceptLoop(c.ln6, true)
	}
	go func() { c.wg.Wait(); close(c.flows) }()
	if cfg.timeout > 0 {
		time.AfterFunc(cfg.timeout, func() { c.Close() })
	}
	return c, nil
}

func (c *winDivertCapture) Flows() <-chan SteeredFlow { return c.flows }
func (c *winDivertCapture) Backend() string           { return "windivert" }

// steerBypassReason returns a non-empty reason when a captured app->target packet must NOT be steered.
// Destination checks (edge endpoint / DNS / loopback) are race-free (no process lookup) and take
// precedence -- this is what stops the agent's own brand-new edge connection from looping. The AppID owner
// check (Automation, self) handles the rest and is FAIL-OPEN: an as-yet-unresolved owner is passed through
// (reason=owner_unresolved), never steered, so a resolution race can't strangle a brand-new flow.
func (c *winDivertCapture) steerBypassReason(srcPort, dstPort uint16, dstIP netip.Addr) string {
	if dstPort == 53 {
		return "dns"
	}
	if dstIP.IsLoopback() {
		return "loopback"
	}
	// effectiveDests, so a late Edge resolution is honoured here too. NOTE the WinDivert FILTER STRING a few
	// hundred lines up is still built once at open, so on this backend a late destination stops the flow from
	// being steered but does not stop it from being captured. The wfp backend, which is what ships, re-pushes
	// the whole rule set and has no such split.
	for _, d := range c.cfg.effectiveDests() {
		if d.Addr() == dstIP && (d.Port() == 0 || d.Port() == dstPort) { // port 0 = bypass all ports to this dest
			return "excluded_dest"
		}
	}
	if bypass, reason := c.bypass.bypassReason(srcPort); bypass {
		return reason
	}
	return ""
}

// parsedFlow is a family-agnostic view of a captured TCP packet for the steer NAT.
type parsedFlow struct {
	v6      bool
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
	tcpOff  int
}

// parseFlow parses an IPv4 or IPv6 TCP packet into the family-agnostic parsedFlow (ok=false => pass through).
func parseFlow(packet []byte) (parsedFlow, bool) {
	if len(packet) < 1 {
		return parsedFlow{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		p, ok := parseIPv4TCP(packet)
		if !ok {
			return parsedFlow{}, false
		}
		return parsedFlow{srcIP: netip.AddrFrom4(p.srcIP), dstIP: netip.AddrFrom4(p.dstIP), srcPort: p.srcPort, dstPort: p.dstPort, tcpOff: p.tcpOff}, true
	case 6:
		p, ok := parseIPv6TCP(packet)
		if !ok {
			return parsedFlow{}, false
		}
		return parsedFlow{v6: true, srcIP: netip.AddrFrom16(p.srcIP), dstIP: netip.AddrFrom16(p.dstIP), srcPort: p.srcPort, dstPort: p.dstPort, tcpOff: p.tcpOff}, true
	}
	return parsedFlow{}, false
}

// setFlowSource / setFlowDestination rewrite the packet's src/dst address+port for the right family.
func setFlowSource(packet []byte, v6 bool, addr netip.Addr, port uint16) error {
	if v6 {
		return setSource6(packet, addr.As16(), port)
	}
	return setSource(packet, addr.As4(), port)
}

func setFlowDestination(packet []byte, v6 bool, addr netip.Addr, port uint16) error {
	if v6 {
		return setDestination6(packet, addr.As16(), port)
	}
	return setDestination(packet, addr.As4(), port)
}

func (c *winDivertCapture) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		syscall.CloseHandle(c.handle)
		c.ln4.Close()
		if c.ln6 != nil {
			c.ln6.Close()
		}
	})
	return nil
}

// acceptLoop accepts each redirected flow on one loopback terminator (v4 or v6), recovers its original
// destination from conntrack (keyed by ephemeral source port + family), and surfaces it as a SteeredFlow.
// Each loop signals wg.Done on exit; flows is closed once all loops have exited (see newWinDivertCapture).
func (c *winDivertCapture) acceptLoop(ln net.Listener, v6 bool) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed (timeout/Close)
		}
		srcPort := remotePort(conn.RemoteAddr())
		entry, ok := c.ct.lookup(flowKey{port: srcPort, v6: v6}, time.Now())
		if !ok {
			fmt.Fprintf(os.Stderr, "capture: no conntrack for src_port=%d v6=%t\n", srcPort, v6)
			conn.Close()
			continue
		}
		fmt.Printf("steer_origdst_resolved method=network_rewrite src_port=%d dst_port=%d v6=%t\n", srcPort, entry.origDstPort, v6)
		flow := SteeredFlow{OrigDst: entry.origDstAddr(), Conn: conn}
		select {
		case c.flows <- flow:
		case <-c.done:
			conn.Close()
			return
		}
	}
}

// packetLoop is the WinDivert recv/rewrite/send loop. App->target packets are rewritten to
// 127.0.0.1:localPort (src also set to loopback) and re-injected on the loopback interface to the
// terminator; terminator->app packets are rewritten back (src=target, dst=orig src) and injected inbound
// on the original real interface so the app's socket matches.
func (c *winDivertCapture) packetLoop() {
	packet := make([]byte, 65535)
	addr := make([]byte, winDivertAddrLen)
	loop4 := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	loop6 := netip.AddrFrom16([16]byte{15: 1}) // ::1
	targetIP := netip.AddrFrom4(c.cfg.targetIP)
	for {
		n, err := c.api.recvPacket(c.handle, packet, addr)
		if err != nil {
			// Clean shutdown (Close/timeout) closed the handle -> isClosing() true, this is a no-op. An
			// unexpected failure (driver reload, handle death) is recorded and tears the capture down so
			// Flows() closes and a supervisor can observe Err() and recreate the backend.
			c.setTermErr(fmt.Errorf("windivert recv: %w", err))
			if !c.isClosing() {
				go c.Close()
			}
			return
		}
		// NOTE: we do NOT skip impostor-flagged packets. Windows marks the app's post-handshake packets
		// (ACK/data) impostor once the flow was seeded by our injected SYN-ACK, so skipping them would
		// strand all application data. Re-capture loops are instead prevented structurally: our injected
		// packets (loopback forward -> terminator, inbound return target->app) never match the redirect
		// filter, so they are not seen again.
		f, ok := parseFlow(packet[:n])
		if !ok {
			_ = c.api.sendPacket(c.handle, packet[:n], addr)
			continue
		}
		loopAddr := loop4
		if f.v6 {
			loopAddr = loop6
		}

		outbound := addrFlag(addr, flagOutbound)
		isReturn := f.srcIP == loopAddr && f.srcPort == c.cfg.localPort
		// In steer-all every captured outbound packet (that isn't the return path) is a steer candidate;
		// in single-target mode only the configured target is. The filter already excludes loopback/DNS/
		// edge for steer-all; the code bypass below is defense-in-depth.
		isToTarget := outbound && !isReturn
		if !c.cfg.steerAll {
			isToTarget = outbound && f.dstIP == targetIP && f.dstPort == c.cfg.targetPort
		}

		// Steer-all safety: never steer (a) the edge endpoint / DNS / loopback (race-free destination
		// check -- critically prevents the agent's own brand-new edge connection from being steered into
		// a loop), or (b) a flow owned by an excluded app (Automation, the agent itself). Bypassed flows are
		// passed through untouched so their connectivity is never affected.
		if isToTarget {
			if reason := c.steerBypassReason(f.srcPort, f.dstPort, f.dstIP); reason != "" {
				if c.bypass.logOncePort(f.srcPort) {
					fmt.Printf("steer_bypass src_port=%d dst_port=%d reason=%s v6=%t\n", f.srcPort, f.dstPort, reason, f.v6)
				}
				_ = c.api.sendPacket(c.handle, packet[:n], addr)
				continue
			}
		}

		switch {
		case isToTarget:
			// steer-all must only adopt NEW connections (we saw their SYN). Mid-stream packets of a
			// pre-existing connection have no conntrack entry -- passing them through avoids RST-ing
			// connections that were already established when steer-all started.
			if c.cfg.steerAll {
				flags := packet[f.tcpOff+13]
				isSYN := flags&0x02 != 0 && flags&0x10 == 0
				if !isSYN {
					if _, known := c.ct.lookup(flowKey{port: f.srcPort, v6: f.v6}, time.Now()); !known {
						_ = c.api.sendPacket(c.handle, packet[:n], addr)
						continue
					}
				}
			}
			ifIdx, subIf := addrIfIdx(addr)
			c.ct.put(flowKey{port: f.srcPort, v6: f.v6}, natEntry{
				origSrc:     f.srcIP,
				origDst:     f.dstIP,
				origDstPort: f.dstPort,
				ifIdx:       ifIdx,
				subIf:       subIf,
			}, time.Now())
			if err := setFlowSource(packet[:n], f.v6, loopAddr, f.srcPort); err != nil {
				_ = c.api.sendPacket(c.handle, packet[:n], addr)
				continue
			}
			if err := setFlowDestination(packet[:n], f.v6, loopAddr, c.cfg.localPort); err != nil {
				continue
			}
			loopbackInject(addr)
			if err := c.api.sendPacket(c.handle, packet[:n], addr); err != nil {
				fmt.Fprintf(os.Stderr, "reinject to terminator (src_port=%d v6=%t): %v\n", f.srcPort, f.v6, err)
			} else {
				fmt.Printf("steer_redirect_out src_port=%d dst_port=%d v6=%t -> loopback:%d bytes=%d flags=%s\n", f.srcPort, f.dstPort, f.v6, c.cfg.localPort, n, tcpFlagsStringAt(packet[:n], f.tcpOff))
			}
		case isReturn:
			e, ok := c.ct.lookup(flowKey{port: f.dstPort, v6: f.v6}, time.Now())
			if !ok {
				_ = c.api.sendPacket(c.handle, packet[:n], addr) // unknown return flow; pass through
				continue
			}
			if err := setFlowSource(packet[:n], f.v6, e.origDst, e.origDstPort); err != nil {
				continue
			}
			if err := setFlowDestination(packet[:n], f.v6, e.origSrc, f.dstPort); err != nil {
				continue
			}
			inboundInject(addr, e.ifIdx, e.subIf)
			if err := c.api.sendPacket(c.handle, packet[:n], addr); err != nil {
				fmt.Fprintf(os.Stderr, "reinject to app (dst_port=%d v6=%t): %v\n", f.dstPort, f.v6, err)
			} else {
				fmt.Printf("steer_return_in dst_port=%d src=%s bytes=%d flags=%s\n", f.dstPort, e.origDstAddr(), n, tcpFlagsStringAt(packet[:n], f.tcpOff))
			}
		default:
			fmt.Printf("steer_passthrough dir=%s src_port=%d dst_port=%d bytes=%d flags=%s\n", directionString(addr), f.srcPort, f.dstPort, n, tcpFlagsStringAt(packet[:n], f.tcpOff))
			_ = c.api.sendPacket(c.handle, packet[:n], addr)
		}
	}
}

// runObserveWinDivert sniffs the target flow without rewriting, logging each packet's 5-tuple and
// address flags. This validates capture and reveals the real WINDIVERT_ADDRESS flags/IfIdx (used to
// derive the loopback-inject template) before enabling redirect. WinDivert-specific debug aid.
func runObserveWinDivert(cfg captureConfig) error {
	api := newWinDivertAPI()
	handle, err := api.openHandle(outboundFilter(cfg), uintptr(winDivertFlagSniff))
	if err != nil {
		return fmt.Errorf("open WinDivert sniff handle: %w", err)
	}
	defer syscall.CloseHandle(handle)
	deadline := time.AfterFunc(cfg.timeout, func() { syscall.CloseHandle(handle) })
	defer deadline.Stop()

	fmt.Printf("steer observe: target=%s capture_backend=windivert\n", cfg.targetAddrPort())
	packet := make([]byte, 65535)
	addr := make([]byte, winDivertAddrLen)
	for {
		n, err := api.recvPacket(handle, packet, addr)
		if err != nil {
			return nil // handle closed on timeout
		}
		p, ok := parseIPv4TCP(packet[:n])
		if !ok {
			continue
		}
		ifIdx, subIf := addrIfIdx(addr)
		fmt.Printf("steer_flow_captured dir=%s src_port=%d dst_port=%d bytes=%d flags=0x%02x ifidx=%d subif=%d\n",
			directionString(addr), p.srcPort, p.dstPort, n, addr[addrFlagsByte], ifIdx, subIf)
	}
}

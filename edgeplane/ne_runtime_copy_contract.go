// NE runtime-copy contract types shared between the composition root's NE family
// and edgeplane's connector-aware dialer. Moved verbatim from cmd/edge (Phase 3
// step 5a, advisory).
package edgeplane

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	swg "github.com/lantern-networks/dsse-core/swg"
)

type NetworkExtensionRuntimeCopyTCPRoute struct {
	TransportServerName string `json:"-"` // trusted outer TLS entrance, not client JSON
	Host                string
	Port                int
	// The tunnel handler sets SNI by peeking at the ClientHello; empty means it was not obtained. On a
	// connect-by-IP flow (Chrome, IPv6) Host is an address while the SNI is still a hostname, so any decision
	// that needs a name uses this.
	SNI string
	// DeviceIdentity carries the verified (T) transport mTLS device identity of the steered flow from the
	// CONNECT /steer handler down to the in-process decrypt-all forward, so the egress handler can bind a
	// federated-auth grant to the DEVICE (not just the tenant). Empty when not a transport-authenticated flow.
	DeviceIdentity string
	// OSUser is the logged-in OS user that ORIGINATED this flow, reported PER-FLOW by the endpoint agent (the NE
	// reads the flow's sourceAppAuditToken -> UID -> username). Unlike DeviceIdentity (one per tunnel/device), a
	// device can be shared by several users, so this is the only per-user signal that says WHO acted. Carried to
	// the egress decision as req.UserID. Empty when the agent did not report it.
	OSUser    string
	AuthOwner AuthOwner
	// SourceApp is the app/process that ORIGINATED this flow, reported per-flow by the endpoint agent (macOS
	// signing identifier / Windows image identity) in the steer OPEN frame ("a="). Distinguishes a human in a
	// browser from a CLI / script / AI agent hitting the assistant. Carried to the access log as ai_app metadata.
	SourceApp string
	// TenantID carries the flow's tenant from the steer/admission layer down to leaf minting, so the
	// interception engine signs the per-SNI leaf under THAT tenant's root when per-tenant isolation is on
	// (blast-radius containment). Empty => the default fleet root (today's behavior).
	TenantID string
	// TunnelSourceIP is the mTLS transport peer address the EDGE OBSERVES for this flow's endpoint↔edge tunnel —
	// a trust-boundary fact, NOT a value the agent self-reports (which is spoofable). Recorded as the access
	// log's source_ip so audit reflects the real network origin, not a synthetic placeholder. Empty when
	// unavailable (falls back to the placeholder).
	TunnelSourceIP string
	// BuiltBy names the handler that assembled this route.
	//
	// ★★★ SEVERAL CHANNELS, ONE FLOW, AND NO WAY TO TELL THEIR DIALS APART (2026-09-01). A device uses the
	// mux, the runtime-copy tunnel, and the session and round-trip endpoints, and each builds its own route.
	// When one of them lost the organization, every log line about the failure read like every other, and the
	// only distinguishing evidence was which Edge node happened to serve it. Naming the builder costs a
	// string and ends the guessing.
	BuiltBy string
}

type NetworkExtensionRuntimeCopyTCPDialer interface {
	OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error)
}

type NetworkExtensionRuntimeCopyNetDialer struct{}

func (NetworkExtensionRuntimeCopyNetDialer) OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	dialHost := networkExtensionRuntimeCopyDialHost(route)
	// ★★★ A STEERED DEVICE MUST NOT BE ABLE TO DIAL WHAT ONLY THIS NODE CAN REACH (2026-08-31, reproduced on
	// a real Mac against a running deployment). See a_steered_device_cannot_dial_the_nodes_own_identity_test.go.
	//
	// ★★★ AND THE ADDRESS IT CONNECTS TO IS THE ONE THAT WAS CHECKED (2026-11-07, security review S2). The guard
	// hands back the addresses it vetted and the socket is opened to those, never to the name again — a
	// resolver that answers differently to the check and to the dial no longer gets a second answer. The
	// socket-level Control and the post-connect check are the same two lines the connector dialer already has.
	// See a_steered_flow_dials_the_address_it_was_checked_against_test.go.
	addrs, err := swg.VetEgressDestination(ctx, dialHost)
	if err != nil {
		return nil, fmt.Errorf("this flow was refused before it was dialled: %w", err)
	}
	candidates := addrs[:0:0]
	hasIPv6 := EdgeHasIPv6Egress()
	for _, ip := range addrs {
		if ip.To4() == nil && !hasIPv6 {
			continue // this node cannot egress IPv6; the name may still have an IPv4 answer
		}
		candidates = append(candidates, ip)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no IPv6 egress for IPv6-literal destination without SNI")
	}
	return dialVettedAddresses(ctx, candidates, route.Port)
}

// vettedDial opens one guarded TCP connection. A test replaces it to make one attempt hang.
var vettedDial = func(ctx context.Context, network, address string) (net.Conn, error) {
	return swg.GuardDialContext((&net.Dialer{Control: swg.EgressControl}).DialContext)(ctx, network, address)
}

// connectionAttemptDelay is how long one attempt gets to itself before the next address is started as well
// (RFC 8305 §5, the value Go's own dialer uses). Attempts overlap; the first to connect wins and the rest
// are cancelled.
const connectionAttemptDelay = 300 * time.Millisecond

// dialVettedAddresses connects to the first of the vetted addresses that answers, racing them the way
// net.Dialer races a name's answers: the addresses are interleaved by family so an unanswering IPv6 route does
// not hold a working IPv4 one back (review R3), each attempt is started connectionAttemptDelay after the one
// before it, and no address is ever resolved — only what the guard vetted is dialled.
func dialVettedAddresses(ctx context.Context, candidates []net.IP, port int) (io.ReadWriteCloser, error) {
	ordered := interleaveByFamily(candidates)
	address := func(ip net.IP) string { return net.JoinHostPort(ip.String(), strconv.Itoa(port)) }
	if len(ordered) == 1 {
		conn, err := vettedDial(ctx, "tcp", address(ordered[0]))
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	type outcome struct {
		conn net.Conn
		err  error
	}
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()
	results := make(chan outcome, len(ordered))
	started := 0
	finished := 0
	// ★ EVERY ATTEMPT HAS AN OWNER (re-review RR4). An attempt that connects after the race has been decided —
	// a near-simultaneous second answer, or one that lands after the caller gave up — is nobody's socket
	// unless something waits for it. The reaper takes the attempts still in flight when this returns and
	// closes whatever they produce.
	defer func() {
		outstanding := started - finished
		if outstanding <= 0 {
			return
		}
		go func() {
			for i := 0; i < outstanding; i++ {
				if r := <-results; r.conn != nil {
					_ = r.conn.Close()
				}
			}
		}()
	}()
	start := func() {
		ip := ordered[started]
		started++
		go func() {
			conn, err := vettedDial(raceCtx, "tcp", address(ip))
			results <- outcome{conn: conn, err: err}
		}()
	}
	start()
	timer := time.NewTimer(connectionAttemptDelay)
	defer timer.Stop()
	var last error
	for finished < len(ordered) {
		select {
		case r := <-results:
			finished++
			if r.err == nil {
				cancelRace()
				return r.conn, nil
			}
			last = r.err
			if started < len(ordered) {
				// A refusal frees the slot at once: start the next address without waiting out the delay.
				start()
				timer.Reset(connectionAttemptDelay)
			}
		case <-timer.C:
			if started < len(ordered) {
				start()
				timer.Reset(connectionAttemptDelay)
			}
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return nil, last
		}
	}
	return nil, last
}

// interleaveByFamily orders the addresses so the two families alternate, IPv6 first when present, which is
// what makes a dead route in one family cost at most one attempt delay.
func interleaveByFamily(addrs []net.IP) []net.IP {
	var v6, v4 []net.IP
	for _, ip := range addrs {
		if ip.To4() == nil {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	out := make([]net.IP, 0, len(addrs))
	for len(v6) > 0 || len(v4) > 0 {
		if len(v6) > 0 {
			out = append(out, v6[0])
			v6 = v6[1:]
		}
		if len(v4) > 0 {
			out = append(out, v4[0])
			v4 = v4[1:]
		}
	}
	return out
}

// DialNetworkForEgress picks the dial network for an egress connection given whether the Edge can egress
// IPv6. With IPv6 egress it stays dual-stack ("tcp") so production keeps using native IPv6 unchanged.
// Without IPv6 egress it restricts to IPv4 ("tcp4") so a dual-stack name is not dialed over IPv6 first
// (which would stall on every flow); it also flags an IPv6 literal that cannot be re-resolved by name as
// unreachable so the caller can fail fast. This is self-adapting per deployment — it never strips IPv6
// where the Edge can actually use it, so it is safe as a default (not a lab-only knob).
func DialNetworkForEgress(hasIPv6Egress bool, dialHost string) (network string, unreachable bool) {
	if hasIPv6Egress {
		return "tcp", false
	}
	if ip := net.ParseIP(strings.TrimSpace(dialHost)); ip != nil && ip.To4() == nil {
		return "tcp4", true
	}
	return "tcp4", false
}

// EdgeHasIPv6Egress reports whether this Edge can actually egress IPv6.
//
// ★★★ ONE QUESTION MUST NOT HAVE TWO ANSWERS (2026-08-30, measured on this deployment). This used to list
// interface addresses and call a node v6-capable only if it held a GLOBAL, non-private v6 address. The Edge
// containers run behind NAT66: each holds a ULA (fd00::/8), which net.IP.IsPrivate reports true for, so this
// returned false — while the node's own start-up probe DIALLED IPv6 successfully and logged
// `egress_address_family ipv4=true ipv6=true`. The health answer said yes, the flow decision said no, and
// every IPv6 destination was quietly re-fetched by name over IPv4. The deployment was reporting IPv6 support
// it was refusing to use.
//
// The file that owns the start-up probe had already written the rule down — "IT IS A REACHABILITY TEST, NOT
// AN INTERFACE LIST. An interface can hold a global v6 address and still have no route off the host" — and
// this, the function that decides what actually happens to a flow, never adopted it. So now there is exactly
// one measurement: whoever dials installs the result here with SetMeasuredIPv6Egress, and this returns it.
//
// Before the first measurement lands (the seconds between process start and the first probe) this dials once
// itself rather than guessing from addresses, and it does NOT cache that first answer forever: a node that
// gains or loses IPv6 must be able to say so, which a sync.Once could never do.
var (
	edgeIPv6EgressMeasured atomic.Pointer[bool]
	edgeIPv6EgressFallback atomic.Pointer[bool]
	// edgeIPv6EgressProbe is a package var so tests can override the probe without opening a socket.
	edgeIPv6EgressProbe = detectEdgeIPv6Egress
)

// EdgeIPv6EgressProbeAddress is the address the fallback dial opens. A well-known anycast resolver on 443:
// nothing is sent, the socket reaching ESTABLISHED is the whole question.
const EdgeIPv6EgressProbeAddress = "[2606:4700:4700::1111]:443"

// SetMeasuredIPv6Egress records the result of a real egress measurement. It supersedes the fallback dial for
// the life of the process and is expected to be called again by whatever repeats the measurement.
func SetMeasuredIPv6Egress(canEgressIPv6 bool) {
	v := canEgressIPv6
	edgeIPv6EgressMeasured.Store(&v)
}

func EdgeHasIPv6Egress() bool {
	if p := edgeIPv6EgressMeasured.Load(); p != nil {
		return *p
	}
	if p := edgeIPv6EgressFallback.Load(); p != nil {
		return *p
	}
	v := edgeIPv6EgressProbe()
	edgeIPv6EgressFallback.Store(&v)
	return v
}

// detectEdgeIPv6Egress dials rather than reading interface addresses. See the note above EdgeHasIPv6Egress
// for what reading addresses cost this deployment.
func detectEdgeIPv6Egress() bool {
	c, err := net.DialTimeout("tcp6", EdgeIPv6EgressProbeAddress, 4*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// networkExtensionRuntimeCopyDialHost returns the host a raw-forward (bypass) egress actually dials.
//
// A dual-stack client — Windows, Chrome — resolves DNS itself and connects straight to an address, so
// route.Host is an IP literal. Dialling that address as given fails with "network is unreachable" wherever the
// Edge's egress has no route for that family, a container without IPv6 egress being the ordinary case, and the
// bypass flow dies. The interception path already re-resolved the hostname from the SNI or the Host before
// dialling; only the base dialer was still dialling the literal, which was the bug.
//
// So when there is an SNI — always a hostname — and route.Host is an IP literal, the SNI is returned, and the
// resolver plus happy-eyeballs can fall back to a family that is reachable. With no SNI, or a Host that is
// already a hostname, route.Host is used as before.
func networkExtensionRuntimeCopyDialHost(route NetworkExtensionRuntimeCopyTCPRoute) string {
	if sni := strings.TrimSpace(route.SNI); sni != "" && net.ParseIP(strings.TrimSpace(route.Host)) != nil {
		return sni
	}
	return route.Host
}

func NormalizeNetworkExtensionRuntimeCopyDestinationHost(raw string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
			return "", false
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if host == "" {
		return "", false
	}
	if strings.ContainsAny(host, "/\\@") || strings.Contains(host, "..") || strings.Contains(host, "*") {
		return "", false
	}
	for _, char := range host {
		if char <= 0x20 || char == 0x7f {
			return "", false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, true
	}
	if strings.Contains(host, ":") {
		return "", false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	return host, true
}

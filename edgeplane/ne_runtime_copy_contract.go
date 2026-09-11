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
	Host string
	Port int
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
	OSUser string
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
	// a real Mac against a running deployment).
	//
	// From an armed laptop, through the tunnel:
	//
	//	PUT http://169.254.169.254/latest/api/token          -> an IMDSv2 token
	//	GET .../iam/security-credentials/                    -> dsse-lab-node
	//	aws sts get-caller-identity                          -> assumed-role/dsse-lab-node/i-0c790ee5...
	//
	// The device assumed the CLOUD IDENTITY OF THE NODE CARRYING ITS TRAFFIC. Every steered device could, and
	// nothing on either side said a word — from the Edge it is an ordinary flow to an ordinary address.
	//
	// The guard for this already exists and is correct: swg.CheckEgressDestination refuses loopback,
	// link-local (which is where every cloud metadata service lives), RFC1918 and CGNAT, and the SWG's HTTP
	// path has been calling it all along — that is the 502 an administrator sees when a steered browser asks
	// for an internal address. THIS path, the transparent steer that carries everything a device sends, never
	// asked. One rule, two paths, applied to one of them.
	if err := swg.CheckEgressDestination(ctx, dialHost); err != nil {
		return nil, fmt.Errorf("this flow was refused before it was dialled: %w", err)
	}
	network, unreachable := DialNetworkForEgress(EdgeHasIPv6Egress(), dialHost)
	if unreachable {
		// IPv6-literal destination with no SNI to re-resolve, on an Edge with no IPv6 egress: there is no
		// reachable path. Fail fast so the client falls back to IPv4, instead of blocking until the OS
		// connect timeout (the cause of the "abnormally slow bypass" symptom on a single-stack Edge).
		return nil, fmt.Errorf("no IPv6 egress for IPv6-literal destination without SNI")
	}
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(dialHost, strconv.Itoa(route.Port)))
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

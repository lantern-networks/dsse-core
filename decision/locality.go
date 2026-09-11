package decision

import (
	"net"
	"net/netip"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// locality.go — is this destination inside the estate, or is it the internet?
//
// The east-west plane exists for LATERAL movement: an identity reaching another machine inside the same
// estate. Until this file existed, plane membership was decided by the service family and nothing else
// (IsEastWestProtocol), so the classifier could not tell internal from external and **every SSH on a steered
// box was lateral movement by construction** — including SSH to a public code host.
//
// Observed on win-dev-1, 2026-08-09: `ssh git@github.com` reached 20.27.177.113:22, was classified east-west,
// held for an out-of-band IdP ceremony, and dropped at 2m0s with a step-up window on the desktop for GitHub.
// The operator's model, which is the thing to implement, is simply: destinations inside the declared internal
// networks are connector-mediated, everything else is internet access — so a public address is internet
// access whatever protocol reaches it.
//
// Note what this is NOT for. Falling off the east-west plane does not mean "ungoverned": the evaluator's
// east-west branch is an `else if`, so a public-internet SSH lands on the north-bound policy plane, which is
// where the internet-facing controls live. Exfil over SSH is a real concern; it is just not lateral movement,
// and governing it on the lateral plane is what produced a two-minute stall that reads as a broken network.

// DestinationLocality says where a flow is going, as far as the Edge can tell.
type DestinationLocality int

const (
	// LocalityUnknown: the destination could not be classified — no parseable address, and no declared
	// network matched. NOT the same as "external"; see EastWestLocalityAdmits for why that matters.
	LocalityUnknown DestinationLocality = iota
	// LocalityInternal: private/loopback/link-local address space, or a destination the operator DECLARED
	// internal.
	LocalityInternal
	// LocalityPublic: a globally routable address. Internet access, whatever protocol reaches it.
	LocalityPublic
)

func (l DestinationLocality) String() string {
	switch l {
	case LocalityInternal:
		return "internal"
	case LocalityPublic:
		return "public"
	default:
		return "unknown"
	}
}

// InternalNetworks is the operator's declaration of what counts as inside the estate, on top of private
// address space.
//
// It exists because private address space is a floor, not the whole answer: a customer can route
// public-range addresses internally, and those destinations are lateral even though their addresses are
// globally routable. In this product the natural source is the connector's advertised reachable routes —
// "connector-mediated" and "internal" are the same statement — but the type takes plain CIDRs and domains so
// nothing here depends on the connector layer.
//
// The reverse override does not exist: nothing declares a private address public. An operator can extend the
// lateral plane, never shrink it below the address-class floor, because shrinking it is how a lateral-movement
// control gets quietly switched off.
type InternalNetworks struct {
	// CIDRs are declared-internal prefixes, e.g. "10.0.0.0/8", "203.0.113.0/24".
	CIDRs []string
	// Domains are declared-internal DNS suffixes. "corp.example.com" matches itself and any subdomain;
	// a leading "*." is accepted and ignored, since that is how connector FQDN routes are written.
	Domains []string
}

// Empty reports whether nothing has been declared. Used to say so in diagnostics: a deployment that has
// declared no internal networks is relying entirely on the address-class floor, which is correct for a
// flat private estate and wrong for one that routes public ranges internally — and the difference is
// invisible unless something says which case it is in.
func (n InternalNetworks) Empty() bool { return len(n.CIDRs) == 0 && len(n.Domains) == 0 }

// ClassifyDestinationLocality decides where a request is headed.
//
// Order matters: the operator's declaration is consulted FIRST, so a declared-internal destination is
// internal even when its address is globally routable. Then the address class decides. A destination with no
// usable address and no declared match is Unknown, and is deliberately NOT rounded to either answer.
func ClassifyDestinationLocality(req model.DecisionRequest, declared InternalNetworks) DestinationLocality {
	host := destinationHost(req)
	fqdn := strings.ToLower(strings.TrimSpace(req.FQDN))
	if fqdn == "" && host != "" && net.ParseIP(host) == nil {
		fqdn = strings.ToLower(host)
	}

	if fqdn != "" && declared.matchesDomain(fqdn) {
		return LocalityInternal
	}
	// The resolved address is consulted LAST: what the client asked for decides when it is an address at all,
	// and a name is only classified by what this Edge resolved it to when there is nothing else to go on.
	ip := parseIPCandidate(host, req.DestinationIP, req.DestinationResolvedIP)
	if !ip.IsValid() {
		return LocalityUnknown
	}
	if declared.matchesCIDR(ip) {
		return LocalityInternal
	}
	if isInternalAddress(ip) {
		return LocalityInternal
	}
	return LocalityPublic
}

// destinationHost pulls the host out of the request's Destination, which on the steered path is the OPEN
// authority's host portion and is frequently a bare IP (the WFP redirect recovers the ORIGINAL destination
// address, so a connect-by-name arrives here as the address it resolved to).
func destinationHost(req model.DecisionRequest) string {
	d := strings.TrimSpace(req.Destination)
	if d == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(d); err == nil {
		return strings.TrimSpace(h)
	}
	return strings.Trim(d, "[]")
}

func parseIPCandidate(values ...string) netip.Addr {
	for _, v := range values {
		v = strings.Trim(strings.TrimSpace(v), "[]")
		if v == "" {
			continue
		}
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap() // an IPv4-mapped IPv6 destination must classify as its IPv4 self
		}
	}
	return netip.Addr{}
}

// isInternalAddress is the address-class floor: everything that is not globally routable on the public
// internet. Kept explicit rather than delegating to a single stdlib predicate, because the set is a security
// boundary and "what counts as internal" should be readable in one place.
func isInternalAddress(ip netip.Addr) bool {
	switch {
	case ip.IsLoopback(), // 127.0.0.0/8, ::1 — the box itself
		ip.IsPrivate(),                 // RFC1918 and IPv6 ULA (fc00::/7)
		ip.IsLinkLocalUnicast(),        // 169.254.0.0/16, fe80::/10
		ip.IsLinkLocalMulticast(),      //
		ip.IsInterfaceLocalMulticast(), //
		ip.IsUnspecified():             // 0.0.0.0, ::
		return true
	}
	// Carrier-grade NAT (100.64.0.0/10). Not "private" to the stdlib, not routable on the public internet,
	// and used as internal space in real deployments — so a lateral hop across it must stay lateral.
	if ip.Is4() && cgnat.Contains(ip) {
		return true
	}
	return false
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func (n InternalNetworks) matchesCIDR(ip netip.Addr) bool {
	for _, c := range n.CIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue // a malformed declaration is dropped, never treated as a match-all
		}
		if p.Addr().Is4() != ip.Is4() {
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// matchesDomain matches a declared suffix against an FQDN. "corp.example.com" matches itself and any
// subdomain, but never "notcorp.example.com" — the boundary is a label boundary, not a string prefix.
func (n InternalNetworks) matchesDomain(fqdn string) bool {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	if fqdn == "" {
		return false
	}
	for _, d := range n.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.") // connector FQDN routes are written this way
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if fqdn == d || strings.HasSuffix(fqdn, "."+d) {
			return true
		}
	}
	return false
}

// EastWestLocalityAdmits reports whether a destination may be governed on the east-west plane.
//
// Public destinations are excluded — that is the whole point. Unknown destinations are ADMITTED, and that
// choice is the one worth defending: it means a request the Edge could not classify keeps its lateral-movement
// enforcement rather than silently losing it. The two mistakes are not symmetric. Wrongly treating public
// traffic as lateral produces a visible, diagnosable stall (that is how this bug was found). Wrongly treating
// lateral traffic as internet access removes per-hop authorization from a real lateral hop and produces
// nothing at all — no error, no log line, no symptom until it is used. A control that switches itself off
// when an input goes missing is the failure mode this codebase keeps finding.
//
// The cost of that choice is that a request arriving with no parseable destination still step-ups on an
// east-west protocol. That is why the classification is reported in the decision metadata: the state is
// greppable rather than mysterious.
func EastWestLocalityAdmits(locality DestinationLocality) bool {
	return locality != LocalityPublic
}

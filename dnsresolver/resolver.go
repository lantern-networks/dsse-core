package dnsresolver

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/dns"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/dnsech"

	"golang.org/x/net/dns/dnsmessage"
)

//: the Edge DNS resolver. Receives DNS queries (UDP), applies DNS policy
// (deny/observe), returns Stub IPs for protected FQDNs (deterministic steering, D3), forwards the rest
// upstream, ECH-strips the response (D2), records the FQDN->IP conntrack (D1), and audits (D4). This is
// the live wiring of the D1-D4 pieces; the device must be DNS-pinned to the Edge for it to apply.

type UpstreamDNS interface {
	// Resolve forwards a raw DNS query and returns the raw response.
	Resolve(raw []byte) ([]byte, error)
}

// defaultUpstreamAttempts is how many times a query is sent before giving up. UDP is lossy and a DNS query is
// a single datagram with no delivery guarantee, so ONE unanswered send must not become a hard resolution
// failure: on this path a failure surfaces to the endpoint agent as a 502, and its circuit breaker fails OPEN —
// a dropped packet would silently disable enforcement on the whole device. Measured in the reference lab, a
// single-shot send to a public resolver lost ~70% of queries at concurrency 8 (0% sequential), every one an
// i/o timeout. Every real resolver retries; this one did not.
const defaultUpstreamAttempts = 3

// upstreamFastProbeTimeout bounds every attempt EXCEPT the last. It exists to notice a lost datagram quickly
// (a healthy resolver answers in tens of milliseconds), not to bound how long the upstream may take: the final
// attempt gets all the remaining budget, so a slow-but-alive resolver still gets answered rather than being
// repeatedly cut off and retried.
const upstreamFastProbeTimeout = time.Second

// udpUpstreamDNS forwards queries to a configured upstream resolver over UDP, retrying lost datagrams within a
// fixed TOTAL budget (the endpoint agent has its own client timeout — retries must not push past it).
type udpUpstreamDNS struct {
	addr     string
	timeout  time.Duration // total budget across all attempts
	attempts int           // <=0 means defaultUpstreamAttempts
}

func (u udpUpstreamDNS) Resolve(raw []byte) ([]byte, error) {
	attempts := u.attempts
	if attempts <= 0 {
		attempts = defaultUpstreamAttempts
	}
	deadline := time.Now().Add(u.timeout)

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		// Splitting the budget EVENLY across attempts is wrong: it caps every attempt at budget/attempts, so an
		// upstream that is slow-but-alive (measured p95 ~3s on this lab's path) gets cut off at ~1.7s and the
		// retries burn the rest of the budget re-asking a resolver that was about to answer — the retry then
		// CAUSES the failure it exists to prevent. Instead probe quickly for a lost datagram, and give the LAST
		// attempt everything that is left so a slow answer still lands.
		perAttempt := remaining
		if attempt < attempts-1 {
			if perAttempt > upstreamFastProbeTimeout {
				perAttempt = upstreamFastProbeTimeout
			}
		}
		resp, err := u.resolveOnce(raw, perAttempt)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Only a TIMEOUT means "the datagram may have been lost" — resending can help. A refused/unreachable
		// upstream or a local socket error will fail identically on every retry, so fail fast instead of
		// burning the caller's budget.
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			return nil, err
		}
	}
	return nil, lastErr
}

// resolveOnce sends the query once on a fresh socket and waits up to timeout for the answer.
func (u udpUpstreamDNS) resolveOnce(raw []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("udp", u.addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(raw); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Policy is the Edge-side DNS ruleset (D4) + Stub IP map (D3) + ECH-strip toggle (D2). Keys are
// lowercase FQDNs without a trailing dot. deny and sinkhole entries match the named domain AND all of its
// subdomains (domain-tree semantics: a rule "evil.com" covers "evil.com" and "x.evil.com").
type Policy struct {
	deny     map[string]bool   // queried name -> NXDOMAIN (hard block).
	sinkhole map[string]string // queried name -> sinkhole IPv4 (resolve to a controlled IP instead of failing).
	stubIPv4 map[string]string // protected-app deterministic Stub IP.
	echStrip bool
	// forwardZones route an internal DNS zone (e.g. an AD domain) to a connector for resolution, because the
	// Edge cannot reach the internal DNS directly. A rule for "<zone>" also covers every subdomain, including
	// "_msdcs.<zone>" (the AD DC-locator SRV records). See docs/dns_conditional_forwarding_design.md.
	forwardZones []ForwardZone
}

// ForwardZone is a TENANT-level rule: an internal DNS zone resolves against an internal DNS server. It is NOT
// tied to a connector — WHICH connector reaches that internal DNS is decided by the Edge's connector route
// layer from the Upstream address, not hand-configured per zone.
type ForwardZone struct {
	Zone     string // matches the name or any subdomain
	Upstream string // the internal DNS server to query, e.g. "10.10.0.10:53" (also the routing key: the connector that reaches it)
}

// ConnectorDNS resolves a RAW DNS query against an internal DNS server, THROUGH whichever connector reaches
// that server (resolved by the Edge's connector route layer). nil when no connectors are wired / in the lab.
// Returns the raw DNS response bytes.
type ConnectorDNS interface {
	ResolveViaConnector(ctx context.Context, upstream string, raw []byte) ([]byte, error)
}

// dnsNameMatches reports whether a queried name is the rule domain or a subdomain of it (domain-tree).
func dnsNameMatches(qname, rule string) bool {
	rule = NormalizeQName(rule)
	return rule != "" && (qname == rule || strings.HasSuffix(qname, "."+rule))
}

// policyAction resolves the DNS-layer enforcement action for a queried name: "deny" (NXDOMAIN),
// "sinkhole" (+ the sinkhole IP), or "" (no policy -> normal resolution). Deny wins over sinkhole. Exact
// matches and subdomain matches both apply.
//
// ALL deny checks (exact AND parent-domain) run before ANY sinkhole check. The old order returned an EXACT
// sinkhole before the subdomain-deny loop, so a child sinkhole on login.evil.com beat a PARENT deny on
// evil.com — inverting the documented "deny wins" precedence and letting a broadly-denied domain tree still
// resolve (to the sinkhole) for a child name (review #27).
func (p Policy) policyAction(qname string) (action, sinkholeIP string) {
	if p.deny[qname] {
		return "deny", ""
	}
	for rule := range p.deny {
		if dnsNameMatches(qname, rule) {
			return "deny", ""
		}
	}
	if ip := p.sinkhole[qname]; ip != "" {
		return "sinkhole", ip
	}
	for rule, ip := range p.sinkhole {
		if dnsNameMatches(qname, rule) {
			return "sinkhole", ip
		}
	}
	return "", ""
}

// forwardZoneFor returns the connector forward rule for a queried name (LONGEST matching zone wins, so a more
// specific internal zone overrides a broader one). A "<zone>" rule covers the name and every subdomain,
// including "_msdcs.<zone>" (a DNS subdomain of the zone — where the AD DC-locator SRV records live).
func (p Policy) forwardZoneFor(qname string) (ForwardZone, bool) {
	best, bestLen := ForwardZone{}, -1
	for _, fz := range p.forwardZones {
		z := NormalizeQName(fz.Zone)
		if z == "" {
			continue
		}
		if (qname == z || strings.HasSuffix(qname, "."+z)) && len(z) > bestLen {
			best, bestLen = fz, len(z)
		}
	}
	return best, bestLen >= 0
}

type Resolver struct {
	tenantID  string
	upstream  UpstreamDNS
	conntrack *dns.ConntrackStore
	// connectorDNS resolves an internal forward-zone query through a connector (nil = no connectors wired;
	// a matching zone then fails closed to SERVFAIL rather than leaking the internal name to the public upstream).
	connectorDNS ConnectorDNS
	policy       Policy // startup (env-built) policy; the live policy may override it via livePolicy.
	// livePolicy holds a runtime-applied policy. When set it fully replaces
	// the static `policy`; nil means "use the env-built policy". Hot-swapped atomically so a query in flight
	// always reads one consistent ruleset.
	livePolicy atomic.Pointer[Policy]
	// generation is a monotonic counter bumped on every SetPolicy. Phase 1 config distribution folds the DNS
	// policy into the config bundle; because DNS lives in a SEPARATE store from policy.Store, the bundle's
	// overall generation is the SUM of the per-store generations (both monotonic), so any DNS change advances
	// the bundle generation and Edges re-pull. See GET /admin/config-bundle.
	generation atomic.Uint64
	// audit is called per query with non-secret enums (qname is hashed/omitted by the caller's logger).
	audit func(qname, qtype, decision string, echStripped bool)
}

// ConfigGeneration returns the monotonic DNS-policy config version (bumped on each SetPolicy).
func (r *Resolver) ConfigGeneration() uint64 {
	if r == nil {
		return 0
	}
	return r.generation.Load()
}

// CurrentPolicy returns the live (admin-applied) policy if one is set, else the static env-built policy.
func (r *Resolver) CurrentPolicy() Policy {
	if p := r.livePolicy.Load(); p != nil {
		return *p
	}
	return r.policy
}

// SetPolicy hot-applies a new ruleset. Atomic: queries in flight keep their
// snapshot. A nil-map field is normalized so reads never panic.
func (r *Resolver) SetPolicy(p Policy) {
	if p.deny == nil {
		p.deny = map[string]bool{}
	}
	if p.sinkhole == nil {
		p.sinkhole = map[string]string{}
	}
	if p.stubIPv4 == nil {
		p.stubIPv4 = map[string]string{}
	}
	r.livePolicy.Store(&p)
	r.generation.Add(1) // advance the bundle's aggregate generation so config-pulling Edges re-pull
}

func NormalizeQName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// HandleQuery runs the DNS pipeline for one raw query and returns the raw response. Pure w.r.t. the
// injected upstream/conntrack (testable). On an unparseable query it forwards as-is (fail-open).
func (r *Resolver) HandleQuery(raw []byte, now time.Time) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(raw); err != nil || len(q.Questions) == 0 {
		return r.upstream.Resolve(raw) // not a parseable single-question query; forward untouched
	}
	qname := NormalizeQName(q.Questions[0].Name.String())
	qtype := uint16(q.Questions[0].Type)
	pol := r.CurrentPolicy() // one consistent snapshot for this query (env-built or admin-applied)

	// D4: DNS-layer policy. deny -> NXDOMAIN (hard block); sinkhole -> resolve to a controlled IP so the flow
	// goes to the sinkhole (observation / block landing) instead of failing. Both match the domain + subdomains.
	switch action, sinkIP := pol.policyAction(qname); action {
	case "deny":
		r.auditOf(qname, qtype, "deny", false)
		return packResponse(q, dnsmessage.RCodeNameError, nil)
	case "sinkhole":
		if qtype == 1 { // A -> the sinkhole IP
			if a := parseIPv4(sinkIP); a != nil {
				ans := []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: *a},
				}}
				r.conntrack.Record(dns.ObservationRequest{TenantID: r.tenantID, FQDN: qname, ResolvedIPs: []string{sinkIP}, TTLSeconds: 60}, now)
				r.auditOf(qname, qtype, "sinkhole", false)
				return packResponse(q, dnsmessage.RCodeSuccess, ans)
			}
		}
		// Non-A (e.g. AAAA) on a sinkholed name -> NODATA (success, no answer) so IPv6 cannot bypass the
		// sinkhole; the client falls back to the A record (the sinkhole IP).
		r.auditOf(qname, qtype, "sinkhole", false)
		return packResponse(q, dnsmessage.RCodeSuccess, nil)
	}

	// D3: Stub IP for a protected FQDN (A queries) -> synthesize, record conntrack, no upstream.
	if qtype == 1 { // A
		if ip := pol.stubIPv4[qname]; ip != "" {
			if a := parseIPv4(ip); a != nil {
				ans := []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: *a},
				}}
				r.conntrack.Record(dns.ObservationRequest{TenantID: r.tenantID, FQDN: qname, ResolvedIPs: []string{ip}, TTLSeconds: 60}, now)
				r.auditOf(qname, qtype, "stub", false)
				return packResponse(q, dnsmessage.RCodeSuccess, ans)
			}
		}
	}

	// Forward. An internal forward-zone (e.g. an AD domain) resolves THROUGH its connector — the Edge cannot
	// reach the internal DNS directly. Fail CLOSED to SERVFAIL rather than leak the internal name to the public
	// upstream. Everything else forwards to the default upstream, as before.
	decision := "allow"
	var resp []byte
	var err error
	if fz, ok := pol.forwardZoneFor(qname); ok {
		if r.connectorDNS == nil {
			r.auditOf(qname, qtype, "forward_connector_unavailable", false)
			return packResponse(q, dnsmessage.RCodeServerFailure, nil)
		}
		resp, err = r.connectorDNS.ResolveViaConnector(context.Background(), fz.Upstream, raw)
		if err != nil {
			r.auditOf(qname, qtype, "forward_connector_error", false)
			return packResponse(q, dnsmessage.RCodeServerFailure, nil)
		}
		decision = "forward_connector"
	} else {
		resp, err = r.upstream.Resolve(raw)
		if err != nil {
			return nil, err
		}
	}
	// D2: ECH-strip.
	echStripped := false
	if pol.echStrip {
		if out, n, serr := dnsech.StripECHFromDNSResponse(resp); serr == nil && n > 0 {
			resp = out
			echStripped = true
		}
	}
	// D1: conntrack from the response's A/AAAA records.
	if ips := ExtractResolvedIPs(resp); len(ips) > 0 {
		r.conntrack.Record(dns.ObservationRequest{TenantID: r.tenantID, FQDN: qname, ResolvedIPs: ips, TTLSeconds: dns.ConntrackDefaultTTLSeconds}, now)
	}
	r.auditOf(qname, qtype, decision, echStripped)
	return resp, nil
}

// SetConnectorDNS wires the connector-mediated resolver used for internal forward zones. Safe to call once at
// setup; nil disables connector forwarding (a matching zone then fails closed to SERVFAIL).
func (r *Resolver) SetConnectorDNS(c ConnectorDNS) { r.connectorDNS = c }

func (r *Resolver) auditOf(qname string, qtype uint16, decision string, ech bool) {
	if r.audit != nil {
		r.audit(qname, dnsQTypeName(qtype), decision, ech)
	}
}

// packResponse builds a response to query q with the given rcode + answers.
func packResponse(q dnsmessage.Message, rcode dnsmessage.RCode, answers []dnsmessage.Resource) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: q.Header.ID, Response: true, OpCode: q.Header.OpCode,
			RecursionDesired: q.Header.RecursionDesired, RecursionAvailable: true, RCode: rcode,
		},
		Questions: q.Questions,
		Answers:   answers,
	}
	return resp.Pack()
}

// ExtractResolvedIPs returns the A/AAAA addresses in a DNS response.
func ExtractResolvedIPs(raw []byte) []string {
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		return nil
	}
	out := []string{}
	for _, rr := range m.Answers {
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, net.IP(b.A[:]).String())
		case *dnsmessage.AAAAResource:
			out = append(out, net.IP(b.AAAA[:]).String())
		}
	}
	return out
}

func parseIPv4(s string) *[4]byte {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		return nil
	}
	var a [4]byte
	copy(a[:], ip)
	return &a
}

func dnsQTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 65:
		return "HTTPS"
	case 64:
		return "SVCB"
	default:
		return "other"
	}
}

// ServeUDP runs the UDP DNS listener until the connection is closed. Each query is handled on its own
// goroutine. Errors are logged with non-secret enums only.
func (r *Resolver) ServeUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func(query []byte, addr net.Addr) {
			resp, herr := r.HandleQuery(query, time.Now())
			if herr != nil || len(resp) == 0 {
				return
			}
			_, _ = conn.WriteTo(resp, addr)
		}(query, addr)
	}
}

// StartUDP binds the UDP listener at addr and serves in the background. Non-fatal: a bind
// error is logged and DNS control is simply not active (the steer/SNI path still works).
func StartUDP(addr string, r *Resolver) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dns resolver listen %s: %w", addr, err)
	}
	log.Printf("edge_dns_resolver listening addr=%s ech_strip=%t stub_fqdns=%d deny_fqdns=%d", addr, r.policy.echStrip, len(r.policy.stubIPv4), len(r.policy.deny))
	go r.ServeUDP(conn)
	return conn, nil
}

// Config is the resolver's policy + upstream configuration — env-name-free. The cmd/edge glue reads the
// environment and fills this in, so no deployment-specific env names live in the OSS core.
type Config struct {
	TenantID  string
	Upstream  string            // empty => 1.1.1.1:53
	ECHStrip  bool              // strip ECH from HTTPS/SVCB answers so the Edge can see the inner SNI
	Deny      []string          // qnames to answer NXDOMAIN (hard block)
	Stub      map[string]string // fqdn => deterministic stub IPv4
	Conntrack *dns.ConntrackStore
}

// New builds an Edge DNS resolver from Config, independent of any listener (shared by the DNS-over-tunnel
// endpoint and the legacy UDP listener). Upstream defaults to 1.1.1.1:53. Always returns a usable resolver.
func New(cfg Config) *Resolver {
	pol := Policy{deny: map[string]bool{}, stubIPv4: map[string]string{}, echStrip: cfg.ECHStrip}
	for _, d := range cfg.Deny {
		if d = NormalizeQName(d); d != "" {
			pol.deny[d] = true
		}
	}
	for k, v := range cfg.Stub {
		if nk := NormalizeQName(k); nk != "" {
			pol.stubIPv4[nk] = strings.TrimSpace(v)
		}
	}
	upstream := strings.TrimSpace(cfg.Upstream)
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	return &Resolver{
		tenantID:  cfg.TenantID,
		upstream:  udpUpstreamDNS{addr: upstream, timeout: 5 * time.Second, attempts: defaultUpstreamAttempts},
		conntrack: cfg.Conntrack,
		policy:    pol,
		audit:     defaultDNSQueryAudit,
	}
}

// dnsQueryLogVerbose gates the per-query edge_dns_query log. A DNS query is a hot-path event (one per name
// lookup); at steady state this must be silent. Default OFF; the edge turns it on at -log-level=debug via
// SetDNSQueryLogVerbose.
var dnsQueryLogVerbose atomic.Bool

// SetDNSQueryLogVerbose toggles the per-query edge_dns_query log (default OFF).
func SetDNSQueryLogVerbose(on bool) { dnsQueryLogVerbose.Store(on) }

// defaultDNSQueryAudit is the shared per-query audit callback: non-secret (qtype/decision enums + ech flag only;
// qname is never logged), and gated so a quiet DNS path emits nothing.
func defaultDNSQueryAudit(qname, qtype, decision string, ech bool) {
	if dnsQueryLogVerbose.Load() {
		log.Printf("edge_dns_query qtype=%s decision=%s ech_stripped=%t", qtype, decision, ech)
	}
}

// NewWithUpstream builds a resolver with an explicit upstream + empty policy — used by the DNS-over-tunnel
// wiring and by tests that inject a fake upstream. Apply rules with SetPolicy.
func NewWithUpstream(tenantID string, upstream UpstreamDNS, conntrack *dns.ConntrackStore) *Resolver {
	return &Resolver{
		tenantID:  tenantID,
		upstream:  upstream,
		conntrack: conntrack,
		policy:    Policy{deny: map[string]bool{}, stubIPv4: map[string]string{}},
		audit:     defaultDNSQueryAudit,
	}
}

// IsEmpty reports whether a policy answers nothing: no blocks, no sinkholes, no stub addresses and no forward
// zones. ECH stripping is deliberately NOT counted — it is a flag applied to answers the policy does not itself
// produce, so a policy carrying only that flag still resolves nothing on its own.
//
// This exists so a config pull can tell "the control plane is not the DNS authority here" apart from "serve
// nothing", which are the same bytes on the wire and opposite intentions.
func (p Policy) IsEmpty() bool {
	return len(p.deny) == 0 && len(p.sinkhole) == 0 && len(p.stubIPv4) == 0 && len(p.forwardZones) == 0
}

// Summary describes a policy by counts, for logs. Names are omitted on purpose: which internal hostnames a
// tenant resolves is their topology, and a log line is a wider audience than the policy itself.
func (p Policy) Summary() string {
	return fmt.Sprintf("%d deny, %d sinkhole, %d stub, %d forward zone(s)",
		len(p.deny), len(p.sinkhole), len(p.stubIPv4), len(p.forwardZones))
}

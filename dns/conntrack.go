// Package dns holds the Edge DNS-control core: the resolution conntrack (FQDN<->IP recovery) and, over
// time, the DNS resolver and policy. These are importable, dependency-light building blocks of the data
// plane.
package dns

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// DNS resolution conntrack. A client (endpoint agent or the Edge resolver) reports "FQDN -> resolved IP(s)";
// the store records (tenant, resolved-IP) -> FQDN with a TTL, and recovers the real FQDN for a later
// connect-by-IP / non-TLS flow whose destination is only an IP. This complements SNI peek (which recovers
// FQDN only for TLS) and reduces over-steering ambiguity. Non-secret: enums + counts only, never raw payloads.

const ConntrackDefaultTTLSeconds = 300
const conntrackDefaultCapacity = 100000

// ObservationRequest is a reported "FQDN -> resolved IP(s)" observation folded into the conntrack.
type ObservationRequest struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"` // device id (optional)
	FQDN          string   `json:"fqdn"`
	ResolvedIPs   []string `json:"resolved_ips"`
	ApplicationID string   `json:"application_id"` // optional
	TTLSeconds    int      `json:"ttl_seconds"`
}

// ObservationResponse is the result of recording an ObservationRequest.
type ObservationResponse struct {
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	RecordedEntries     int    `json:"recorded_entries"`
	NoSecretAttestation bool   `json:"no_secret_attestation"`
}

type conntrackEntry struct {
	fqdn      string
	appID     string
	expiresAt time.Time
}

// ConntrackStore maps (tenant, resolved-IP) -> FQDN with a TTL and a bounded FIFO capacity.
type ConntrackStore struct {
	mu       sync.Mutex
	entries  map[string]conntrackEntry
	order    []string
	capacity int
	// byName answers the other question: which addresses this Edge gave a tenant's devices for a name. It is
	// kept apart from entries on purpose. entries holds ONE name per address — the latest asked — and several
	// names commonly share one address; an index that followed entries forgot every earlier name the moment a
	// later one was resolved to the same address.
	byName        map[string]map[string]time.Time
	nameOrder     []string
	nameAddresses int
}

// NewConntrackStore returns an empty conntrack with the default capacity.
func NewConntrackStore() *ConntrackStore {
	return &ConntrackStore{entries: map[string]conntrackEntry{}, capacity: conntrackDefaultCapacity, byName: map[string]map[string]time.Time{}}
}

func conntrackKey(tenantID, ip string) string {
	return strings.TrimSpace(tenantID) + "|" + strings.TrimSpace(ip)
}

// Record folds a DNS resolution observation into the conntrack (one entry per resolved IP) with a
// TTL, bounded FIFO. Returns the number of entries recorded.
func (s *ConntrackStore) Record(req ObservationRequest, now time.Time) int {
	return s.record(req, now, false)
}

// RecordEdgeAnswer records an answer THIS EDGE'S RESOLVER gave a tenant's devices. Besides the address-to-name
// entry every observation makes, it is remembered by name, and only these are: LookupAddresses decides where a
// named flow goes, and an observation reported from outside — a device or a connector saying "this name is at
// that address" — is not this Edge's answer and must never become one.
func (s *ConntrackStore) RecordEdgeAnswer(req ObservationRequest, now time.Time) int {
	return s.record(req, now, true)
}

func (s *ConntrackStore) record(req ObservationRequest, now time.Time, edgeAnswer bool) int {
	fqdn := strings.TrimSpace(req.FQDN)
	if fqdn == "" || len(req.ResolvedIPs) == 0 {
		return 0
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = ConntrackDefaultTTLSeconds
	}
	exp := now.Add(time.Duration(ttl) * time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, ip := range req.ResolvedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		key := conntrackKey(req.TenantID, ip)
		if _, exists := s.entries[key]; !exists {
			s.order = append(s.order, key)
		}
		s.entries[key] = conntrackEntry{fqdn: fqdn, appID: strings.TrimSpace(req.ApplicationID), expiresAt: exp}
		if edgeAnswer {
			s.indexLocked(req.TenantID, fqdn, ip, exp, now)
		}
		n++
	}
	if s.capacity > 0 {
		for len(s.entries) > s.capacity && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.entries, oldest)
		}
		s.boundNameIndexLocked()
		if len(s.order) > 2*s.capacity {
			s.order = append([]string(nil), s.order...)
		}
	}
	return n
}

func nameKey(tenantID, fqdn string) string {
	return strings.TrimSpace(tenantID) + "|" + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
}

func (s *ConntrackStore) indexLocked(tenantID, fqdn, ip string, exp, now time.Time) {
	if s.byName == nil {
		s.byName = map[string]map[string]time.Time{}
	}
	k := nameKey(tenantID, fqdn)
	set := s.byName[k]
	if set == nil {
		set = map[string]time.Time{}
		s.byName[k] = set
		s.nameOrder = append(s.nameOrder, k)
	}
	// What has lapsed for this name goes now, not when somebody next asks for it.
	for other, until := range set {
		if !now.Before(until) {
			delete(set, other)
			s.nameAddresses--
		}
	}
	if _, had := set[ip]; !had {
		s.nameAddresses++
	}
	if exp.After(set[ip]) {
		set[ip] = exp
	}
}

// boundNameIndexLocked holds the name index to the same capacity as the address entries, counted in ADDRESSES:
// a single name with many answers is as large as many names with one. The oldest names go first, and a name
// larger than the whole capacity loses addresses until it fits. The order list never outgrows the names it
// orders.
func (s *ConntrackStore) boundNameIndexLocked() {
	if s.capacity <= 0 {
		return
	}
	for s.nameAddresses > s.capacity && len(s.nameOrder) > 1 {
		oldest := s.nameOrder[0]
		s.nameOrder = s.nameOrder[1:]
		s.nameAddresses -= len(s.byName[oldest])
		delete(s.byName, oldest)
	}
	if s.nameAddresses > s.capacity && len(s.nameOrder) == 1 {
		set := s.byName[s.nameOrder[0]]
		for ip := range set {
			if s.nameAddresses <= s.capacity {
				break
			}
			delete(set, ip)
			s.nameAddresses--
		}
	}
	if len(s.nameOrder) > 2*len(s.byName)+16 {
		live := s.nameOrder[:0]
		seen := map[string]struct{}{}
		for _, k := range s.nameOrder {
			if _, ok := s.byName[k]; ok {
				if _, dup := seen[k]; !dup {
					seen[k] = struct{}{}
					live = append(live, k)
				}
			}
		}
		s.nameOrder = append([]string(nil), live...)
	}
}

// LookupAddresses returns the addresses this Edge's resolver answered a tenant's devices with for a name and
// that have not lapsed, in no particular order. An address another name was later resolved to is still an
// answer for this one. Observations reported from outside are never returned.
func (s *ConntrackStore) LookupAddresses(tenantID, fqdn string, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := nameKey(tenantID, fqdn)
	var out []string
	for ip, exp := range s.byName[k] {
		if !now.Before(exp) {
			delete(s.byName[k], ip)
			s.nameAddresses--
			continue
		}
		out = append(out, ip)
	}
	if set, ok := s.byName[k]; ok && len(set) == 0 {
		delete(s.byName, k)
		for i, name := range s.nameOrder {
			if name == k {
				s.nameOrder = append(s.nameOrder[:i], s.nameOrder[i+1:]...)
				break
			}
		}
	}
	return out
}

// LookupFQDN returns the recorded FQDN (and optional app id) for a tenant's resolved IP, if present
// and not expired.
func (s *ConntrackStore) LookupFQDN(tenantID, ip string, now time.Time) (string, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[conntrackKey(tenantID, ip)]
	if !ok || !now.Before(e.expiresAt) {
		return "", "", false
	}
	return e.fqdn, e.appID, true
}

// RecoverCertPinName correlates a cert-pinning observation against the DNS-over-tunnel conntrack to recover the
// real FQDN behind a connect-by-IP destination. It only acts when the observation is unattributed — the host is
// a raw IP literal and no SNI was seen — which is exactly the case that would otherwise become an
// investigate_only candidate. On a conntrack hit it returns the resolved FQDN, the originating IP (as evidence),
// and dnsCorrelated=true; otherwise dnsCorrelated=false and the caller records the raw observation as before.
func RecoverCertPinName(ct *ConntrackStore, tenantID, host, sni string, now time.Time) (fqdn, observedIP string, dnsCorrelated bool) {
	if ct == nil || strings.TrimSpace(sni) != "" {
		return "", "", false
	}
	ip := strings.TrimSpace(host)
	if ip == "" || net.ParseIP(ip) == nil {
		return "", "", false
	}
	if name, _, ok := ct.LookupFQDN(tenantID, ip, now); ok && strings.TrimSpace(name) != "" {
		return name, ip, true
	}
	return "", "", false
}

// EnrichDecisionRequestWithDNS recovers req.FQDN from the DNS conntrack when the flow arrived
// connect-by-IP / without SNI (req.FQDN empty and Destination is an IP literal). An explicit FQDN /
// SNI always wins (no override).
func EnrichDecisionRequestWithDNS(req model.DecisionRequest, ct *ConntrackStore, now time.Time) model.DecisionRequest {
	if ct == nil || strings.TrimSpace(req.FQDN) != "" {
		return req
	}
	ip := strings.TrimSpace(req.Destination)
	if ip == "" || net.ParseIP(ip) == nil {
		return req
	}
	if fqdn, appID, ok := ct.LookupFQDN(req.TenantID, ip, now); ok {
		req.FQDN = fqdn
		if strings.TrimSpace(req.ApplicationID) == "" && appID != "" {
			req.ApplicationID = appID
		}
	}
	return req
}

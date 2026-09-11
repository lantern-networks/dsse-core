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
}

// NewConntrackStore returns an empty conntrack with the default capacity.
func NewConntrackStore() *ConntrackStore {
	return &ConntrackStore{entries: map[string]conntrackEntry{}, capacity: conntrackDefaultCapacity}
}

func conntrackKey(tenantID, ip string) string {
	return strings.TrimSpace(tenantID) + "|" + strings.TrimSpace(ip)
}

// Record folds a DNS resolution observation into the conntrack (one entry per resolved IP) with a
// TTL, bounded FIFO. Returns the number of entries recorded.
func (s *ConntrackStore) Record(req ObservationRequest, now time.Time) int {
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
		n++
	}
	if s.capacity > 0 {
		for len(s.entries) > s.capacity && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.entries, oldest)
		}
		if len(s.order) > 2*s.capacity {
			s.order = append([]string(nil), s.order...)
		}
	}
	return n
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

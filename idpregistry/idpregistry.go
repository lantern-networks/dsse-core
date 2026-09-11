// Package idpregistry holds the per-tenant set of trusted END-USER identity providers and the resolution
// rule a policy uses to pick one. A tenant registers one or more IdP connections and marks one as the
// default; a policy may require a SPECIFIC registered IdP (by id) or fall back to the tenant default. A
// reference to an unregistered IdP resolves to not-found so the caller can fail closed (never "any IdP").
//
// This is the data + resolution core only (no OIDC transport / redirect): it is consumed by the decision
// evaluator (idp_id / issuer conditions + the required-IdP resolution) and served by the product edge's
// admin API + Console. The OIDC broker (authorize redirect, callback, token validation, grant) is layered on
// top in a later slice. See docs/idp_federated_authentication_design.md.
package idpregistry

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Valid connection types and domain-enforcement modes.
var validType = map[string]bool{"entra": true, "google": true, "okta": true, "oidc": true}
var validDomainMode = map[string]bool{"google_hd": true, "email_domain": true}

// Connection is one tenant's trusted end-user IdP: its OIDC transport coordinates, how its tokens' assurance
// and identity claims are read, and which email domains it is allowed to assert (anti-cross-tenant).
type Connection struct {
	IdPID                 string   `json:"idp_id"`
	TenantID              string   `json:"tenant_id"`
	Type                  string   `json:"type"` // entra | google | okta | oidc
	DisplayName           string   `json:"display_name,omitempty"`
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	ClientID              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret,omitempty"` // RP secret; the admin API redacts it on read
	UsePKCE               bool     `json:"use_pkce,omitempty"`
	GroupsClaim           string   `json:"groups_claim,omitempty"`
	ACRClaim              string   `json:"acr_claim,omitempty"`           // default "acr"
	AMRClaim              string   `json:"amr_claim,omitempty"`           // default "amr"
	HostedDomainClaim     string   `json:"hosted_domain_claim,omitempty"` // google "hd"
	VerifiedDomains       []string `json:"verified_domains,omitempty"`    // anti-cross-tenant: identity domain must be one of these
	DomainMode            string   `json:"domain_mode,omitempty"`         // google_hd | email_domain
	// CAPEM is the authority that issues this identity provider's TLS certificate, for a provider the public
	// web does not vouch for.
	//
	// ★★★ THERE WAS NOWHERE TO SAY IT (2026-09-03, found by putting the lab's own Keycloak behind TLS). An
	// Edge does not only redirect a browser at the provider — it calls it SERVER-SIDE, twice, for the token
	// exchange and for the signing keys. Those calls verify against the container's system roots, so an
	// identity provider on an internal authority — an on-premises Keycloak, ADFS, PingFederate, which is what
	// a great many of the organizations this product is for actually run — could not be configured at all.
	// The connection could name its endpoints and the Edge could not complete a sign-in at any of them.
	//
	// Empty means the public web's authorities, which is the Entra/Okta/Google case and stays untouched.
	CAPEM string `json:"ca_pem,omitempty"`
}

// Redacted returns a copy with the RP secret removed, for safe display on the admin API / Console.
func (c Connection) Redacted() Connection {
	c.ClientSecret = ""
	c.VerifiedDomains = append([]string(nil), c.VerifiedDomains...)
	return c
}

func normalize(c Connection) (Connection, error) {
	c.IdPID = strings.TrimSpace(c.IdPID)
	c.TenantID = strings.TrimSpace(c.TenantID)
	c.Type = strings.TrimSpace(strings.ToLower(c.Type))
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.AuthorizationEndpoint = strings.TrimSpace(c.AuthorizationEndpoint)
	c.ClientID = strings.TrimSpace(c.ClientID)
	if c.IdPID == "" {
		return Connection{}, fmt.Errorf("idp_id is required")
	}
	if !safeID(c.IdPID) {
		return Connection{}, fmt.Errorf("idp_id %q is invalid (use alphanumerics, _ or -)", c.IdPID)
	}
	if c.TenantID == "" {
		return Connection{}, fmt.Errorf("tenant_id is required")
	}
	if c.Type == "" {
		c.Type = "oidc"
	}
	if !validType[c.Type] {
		return Connection{}, fmt.Errorf("type %q is invalid (want entra|google|okta|oidc)", c.Type)
	}
	if c.Issuer == "" {
		return Connection{}, fmt.Errorf("issuer is required")
	}
	if c.AuthorizationEndpoint == "" {
		return Connection{}, fmt.Errorf("authorization_endpoint is required")
	}
	if c.ClientID == "" {
		return Connection{}, fmt.Errorf("client_id is required")
	}
	if c.DomainMode == "" {
		if c.Type == "google" {
			c.DomainMode = "google_hd"
		} else {
			c.DomainMode = "email_domain"
		}
	}
	if !validDomainMode[c.DomainMode] {
		return Connection{}, fmt.Errorf("domain_mode %q is invalid (want google_hd|email_domain)", c.DomainMode)
	}
	c.VerifiedDomains = normalizedDomains(c.VerifiedDomains)
	return c, nil
}

// Store is a per-tenant registry of end-user IdP connections plus each tenant's default. Safe for concurrent
// use; persists to a JSON state path when configured (see persistence.go) so registered IdPs survive a
// restart.
type Store struct {
	mu          sync.RWMutex
	connections map[string]map[string]Connection // tenant -> idp_id -> connection
	defaults    map[string]string                // tenant -> default idp_id
	persister   blobstore.Persister
	// generation advances on every change. The config bundle SUMS it, and an Edge applies a bundle only when
	// that sum is newer — see ConfigGeneration.
	generation uint64
}

// ★★★ THE BUNDLE CARRIES THIS REGISTRY, SO THE BUNDLE'S VERSION HAS TO MOVE WITH IT (2026-09-02, and this is
// the sixth object to need the same sentence).
//
// An Edge applies a bundle only when its version is newer. A store the version does not count changes the
// bundle's CONTENTS without changing its VERSION, and no Edge ever re-pulls: the registration appears to work
// because somebody restarted the fleet, and the DELETION never arrives at all. Measured that way here too —
// registering an identity provider reached the Edges only because the roll that shipped the code restarted
// them minutes later.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// NewStore returns an empty registry.
func NewStore() *Store {
	return &Store{connections: map[string]map[string]Connection{}, defaults: map[string]string{}}
}

// Upsert validates and stores a connection. The first connection registered for a tenant becomes its default.
func (s *Store) Upsert(c Connection) (Connection, error) {
	normalized, err := normalize(c)
	if err != nil {
		return Connection{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connections[normalized.TenantID] == nil {
		s.connections[normalized.TenantID] = map[string]Connection{}
	}
	// ★★★ THE SCREEN PROMISES THE SECRET SURVIVES A BLANK FIELD, AND THIS USED TO DELETE IT (2026-09-03,
	// measured on a live deployment while a step-up ceremony failed at the last hop).
	//
	// The client secret is write-only: the admin API redacts it on read, and the Console's edit form therefore
	// cannot round-trip it. Its placeholder says so — "Leave blank to keep current secret" — and an operator
	// editing anything else (an endpoint, a claim name, the certificate authority) leaves it blank because
	// that is what the screen tells them to do. This replaced the whole connection, so every such edit
	// SILENTLY erased the secret, and the next sign-in failed at the token exchange with the provider
	// answering "invalid_client" — three layers below the screen that had just said "Provider saved."
	//
	// Measured by doing exactly that: the endpoints were moved to TLS through the Console, the sign-in got as
	// far as the identity provider authenticating the user, and the Edge could not complete the exchange.
	//
	// ★ A WRITE-ONLY FIELD LEFT BLANK MEANS "UNCHANGED", NOT "EMPTY". Nothing else here is write-only, so
	// nothing else needs this — a blank issuer really does mean the caller wants it blank.
	if strings.TrimSpace(normalized.ClientSecret) == "" {
		if existing, ok := s.connections[normalized.TenantID][normalized.IdPID]; ok {
			normalized.ClientSecret = existing.ClientSecret
		}
	}
	s.connections[normalized.TenantID][normalized.IdPID] = normalized
	if strings.TrimSpace(s.defaults[normalized.TenantID]) == "" {
		s.defaults[normalized.TenantID] = normalized.IdPID
	}
	s.generation++
	s.persistLocked()
	return normalized, nil
}

// Get returns a connection by id for the tenant.
func (s *Store) Get(tenantID, idpID string) (Connection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.connections[strings.TrimSpace(tenantID)][strings.TrimSpace(idpID)]
	return c, ok
}

// List returns the tenant's connections, sorted by id (default first is the caller's concern via Default()).
func (s *Store) List(tenantID string) []Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Connection, 0, len(s.connections[strings.TrimSpace(tenantID)]))
	for _, c := range s.connections[strings.TrimSpace(tenantID)] {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IdPID < out[j].IdPID })
	return out
}

// Delete removes a connection. It refuses to delete the tenant's current default while other connections
// remain (set a new default first) — but allows deleting the last one. Reports whether it existed.
func (s *Store) Delete(tenantID, idpID string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	idpID = strings.TrimSpace(idpID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[tenantID][idpID]; !ok {
		return false, nil
	}
	if s.defaults[tenantID] == idpID && len(s.connections[tenantID]) > 1 {
		return false, fmt.Errorf("cannot delete the default IdP %q while others exist; set a new default first", idpID)
	}
	delete(s.connections[tenantID], idpID)
	if s.defaults[tenantID] == idpID {
		delete(s.defaults, tenantID)
	}
	s.generation++
	s.persistLocked()
	return true, nil
}

// SetDefault marks a registered connection as the tenant default. The id must already exist.
func (s *Store) SetDefault(tenantID, idpID string) error {
	tenantID = strings.TrimSpace(tenantID)
	idpID = strings.TrimSpace(idpID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[tenantID][idpID]; !ok {
		return fmt.Errorf("idp %q is not registered for the tenant", idpID)
	}
	s.defaults[tenantID] = idpID
	s.generation++
	s.persistLocked()
	return nil
}

// Default returns the tenant's default connection.
func (s *Store) Default(tenantID string) (Connection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id := s.defaults[strings.TrimSpace(tenantID)]
	if id == "" {
		return Connection{}, false
	}
	c, ok := s.connections[strings.TrimSpace(tenantID)][id]
	return c, ok
}

// Resolve picks the connection a flow must authenticate against: the policy's required IdP when set,
// otherwise the tenant default. A non-empty requiredIdPID that is NOT registered returns ok=false so the
// caller fails closed (a policy must never resolve to an unregistered/any IdP).
func (s *Store) Resolve(tenantID, requiredIdPID string) (Connection, bool) {
	requiredIdPID = strings.TrimSpace(requiredIdPID)
	if requiredIdPID != "" {
		return s.Get(tenantID, requiredIdPID)
	}
	return s.Default(tenantID)
}

func safeID(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizedDomains(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		d := strings.ToLower(strings.TrimSpace(v))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		result = append(result, d)
	}
	return result
}

// CountForTenant returns how many end-user IdP connections this registry still holds for a tenant. The default
// selection counts as one more only when it names an IdP that is gone — a dangling default is residue too.
func (s *Store) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.connections[tenantID])
	if _, ok := s.defaults[tenantID]; ok && n == 0 {
		n = 1
	}
	return n
}

// RemoveTenant erases a tenant's registered end-user IdPs and its default selection.
//
// ★ IT EXISTS BECAUSE "COMPLETELY DELETED" LEFT THEM BEHIND (2026-08-18). This registry is keyed by tenant at
// the top level, so the erasure is exact — and it was still in neither the tenant footprint nor the purge, so
// an organization's registered sign-in providers outlived the organization.
func (s *Store) RemoveTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.connections[tenantID])
	_, hadDefault := s.defaults[tenantID]
	if n == 0 && !hadDefault {
		return 0
	}
	delete(s.connections, tenantID)
	delete(s.defaults, tenantID)
	if n == 0 {
		n = 1 // the default alone was the residue
	}
	s.generation++
	s.persistLocked()
	return n
}

// ★★★ THE FLEET'S VIEW, BECAUSE AN EDGE CARRIES EVERY ORGANIZATION'S FLOWS (2026-09-02).
//
// List and Default answer about one organization, which is what an administrator's screen asks. The control
// plane publishing this registry to the Edges has to ask a different question — what does the whole
// deployment hold — and answering it by looking up the publishing node's own organization is the mistake
// this deployment has made repeatedly: a question about somebody else answered with an attribute of this
// node.

// ListAll is every organization's connections, ordered so two calls produce the same bytes.
func (s *Store) ListAll() []Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Connection{}
	for _, byTenant := range s.connections {
		for _, c := range byTenant {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].IdPID < out[j].IdPID
	})
	return out
}

// DefaultsAll is every organization's chosen default, by organization.
func (s *Store) DefaultsAll() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.defaults))
	for tenant, idp := range s.defaults {
		out[tenant] = idp
	}
	return out
}

// ReplaceAll makes this registry match the given set exactly — the operation an Edge performs when it applies
// the control plane's configuration. A connection the control plane no longer has is REMOVED here, which is
// how a deletion reaches the fleet at all.
//
// ★ IT DOES NOT GO THROUGH Upsert's VALIDATION. What arrives has already been validated where it was
// authored; re-rejecting it here would leave an Edge silently holding a different registry from every other,
// and "one node disagrees about who may sign a user in" is worse than accepting a record an older validator
// would have refused.
func (s *Store) ReplaceAll(conns []Connection, defaults map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections = map[string]map[string]Connection{}
	for _, c := range conns {
		tenant := strings.TrimSpace(c.TenantID)
		if tenant == "" || strings.TrimSpace(c.IdPID) == "" {
			continue
		}
		if s.connections[tenant] == nil {
			s.connections[tenant] = map[string]Connection{}
		}
		s.connections[tenant][strings.TrimSpace(c.IdPID)] = c
	}
	s.defaults = map[string]string{}
	for tenant, idp := range defaults {
		if strings.TrimSpace(tenant) == "" || strings.TrimSpace(idp) == "" {
			continue
		}
		s.defaults[strings.TrimSpace(tenant)] = strings.TrimSpace(idp)
	}
	s.generation++
	s.persistLocked()
}

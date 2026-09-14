package main

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

// organizationDomainsStore holds the operator-declared ORGANIZATION DOMAINS per tenant (S6,
// ): the explicit, multi-value "these domains are US" setting that DLP's
// instance-aware action (corporate vs personal) references. It is a first-class, discoverable setting — unlike the
// IdP verified_domains it supersedes (which were buried in Sign-in Providers, labelled for identity matching, and
// required an IdP to exist). Durable, per-tenant.
type organizationDomainsStore struct {
	mu        sync.RWMutex
	byTenant  map[string][]string
	persister blobstore.Persister
	dirty     bool
}

func newOrganizationDomainsStore() *organizationDomainsStore {
	return &organizationDomainsStore{byTenant: map[string][]string{}}
}

// normalizeDomain lowercases + trims a domain (and strips a leading "@" or "*." so "@Acme.com"/"*.acme.com" work).
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "@")
	d = strings.TrimPrefix(d, "*.")
	return d
}

// Domains returns a tenant's organization domains (normalized, sorted).
func (s *organizationDomainsStore) Domains(tenantID string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.byTenant[tenantID]...)
}

// normalizedOrganizationDomains normalizes, sorts and de-duplicates nonempty inputs.
func normalizedOrganizationDomains(domains []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		n := normalizeDomain(d)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (s *organizationDomainsStore) SetDomains(tenantID string, domains []string) []string {
	out := normalizedOrganizationDomains(domains)
	s.mu.Lock()
	if len(out) == 0 {
		delete(s.byTenant, tenantID)
	} else {
		s.byTenant[tenantID] = out
	}
	s.dirty = true
	s.mu.Unlock()
	return out
}

type organizationDomainsSnapshot struct {
	ByTenant map[string][]string `json:"by_tenant"`
}

// SetPersister attaches durable storage and rehydrates on boot.
func (s *organizationDomainsStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	s.persister = p
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil || len(data) == 0 {
		return err
	}
	var snap organizationDomainsSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.ByTenant != nil {
		s.byTenant = snap.ByTenant
	}
	return nil
}

func (s *organizationDomainsStore) snapshotLocked() organizationDomainsSnapshot {
	next := organizationDomainsSnapshot{ByTenant: map[string][]string{}}
	for tenant, domains := range s.byTenant {
		next.ByTenant[tenant] = append([]string(nil), domains...)
	}
	return next
}

func (s *organizationDomainsStore) saveSnapshotLocked(next organizationDomainsSnapshot) error {
	if s.persister == nil {
		return nil
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.persister.Save(raw)
}

// SetDomainsDurable saves before publishing the account-classification change.
func (s *organizationDomainsStore) SetDomainsDurable(tenant string, domains []string) ([]string, error) {
	out := normalizedOrganizationDomains(domains)
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.snapshotLocked()
	if len(out) == 0 {
		delete(next.ByTenant, tenant)
	} else {
		next.ByTenant[tenant] = out
	}
	if err := s.saveSnapshotLocked(next); err != nil {
		return nil, err
	}
	s.byTenant = next.ByTenant
	s.dirty = false
	return append([]string{}, out...), nil
}

// Periodic snapshots and admin commits share the lock to preserve save order.
func (s *organizationDomainsStore) PersistIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.persister == nil {
		return nil
	}
	if err := s.saveSnapshotLocked(s.snapshotLocked()); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// corporateDomainsResolver builds the DLP corporate-domain resolver as the UNION of the explicit organization
// domains (authoritative) and the IdP connections' verified_domains (back-compat fallback), so nothing regresses
// while the explicit setting becomes the discoverable home. Either store may be nil.
func corporateDomainsResolver(org *organizationDomainsStore, idp *idpregistry.Store) func(tenantID string) []string {
	if org == nil && idp == nil {
		return nil
	}
	return func(tenantID string) []string {
		seen := map[string]bool{}
		var out []string
		add := func(d string) {
			n := normalizeDomain(d)
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		if org != nil {
			for _, d := range org.Domains(tenantID) {
				add(d)
			}
		}
		if idp != nil {
			for _, c := range idp.List(tenantID) {
				for _, d := range c.VerifiedDomains {
					add(d)
				}
			}
		}
		return out
	}
}

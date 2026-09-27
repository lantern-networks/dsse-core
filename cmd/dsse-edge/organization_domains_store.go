package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	mu             sync.RWMutex
	byTenant       map[string][]string
	persister      blobstore.Persister
	dirty          bool
	authorityKnown bool
	pending        map[string][]string
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
	domains, _ := s.DomainsChecked(tenantID)
	return domains
}
func (s *organizationDomainsStore) DomainsChecked(tenant string) ([]string, error) {
	if err := s.RefreshShared(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.byTenant[tenant]...), nil
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
	if s.pending == nil {
		s.pending = map[string][]string{}
	}
	s.pending[tenantID] = append([]string(nil), out...)
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
	defer s.mu.Unlock()
	if p == nil {
		s.persister = nil
		s.authorityKnown = false
		return nil
	}
	raw, err := p.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		if s.authorityKnown {
			return fmt.Errorf("organization domain authority disappeared")
		}
		s.persister = p
		return nil
	}
	next, err := decodeOrganizationDomains(raw)
	if err != nil {
		return err
	}
	s.byTenant, s.persister, s.authorityKnown = next.ByTenant, p, true
	s.dirty = false
	s.pending = nil
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
	return blobstore.UnconfirmedSave(s.persister.Save(raw))
}

// SetDomainsDurable saves before publishing the account-classification change.
func (s *organizationDomainsStore) SetDomainsDurable(tenant string, domains []string) ([]string, error) {
	return s.SetDomainsContext(context.Background(), tenant, domains)
}
func (s *organizationDomainsStore) SetDomainsContext(ctx context.Context, tenant string, domains []string) ([]string, error) {
	out := normalizedOrganizationDomains(domains)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.editDomainsLocked(ctx, map[string][]string{tenant: out}); err != nil {
		return nil, err
	}
	delete(s.pending, tenant)
	s.dirty = len(s.pending) > 0
	return append([]string{}, out...), nil
}

// Periodic writers apply only explicitly changed tenants to the latest row.
func (s *organizationDomainsStore) PersistIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.persister == nil {
		return nil
	}
	if err := s.editDomainsLocked(context.Background(), s.pending); err != nil {
		return err
	}
	s.pending = nil
	s.dirty = false
	return nil
}

type domainContextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}
type domainUpdater interface {
	Update(func([]byte) ([]byte, error)) error
}

func decodeOrganizationDomains(raw []byte) (organizationDomainsSnapshot, error) {
	var next organizationDomainsSnapshot
	if err := json.Unmarshal(raw, &next); err != nil {
		return next, err
	}
	if next.ByTenant == nil {
		return next, fmt.Errorf("incomplete organization domains snapshot")
	}
	return next, nil
}
func (s *organizationDomainsStore) editDomainsLocked(ctx context.Context, edits map[string][]string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next := s.snapshotLocked()
	build := func(raw []byte) ([]byte, error) {
		if raw == nil {
			if s.authorityKnown {
				return nil, fmt.Errorf("organization domain authority disappeared")
			}
		} else {
			var err error
			next, err = decodeOrganizationDomains(raw)
			if err != nil {
				return nil, err
			}
			s.authorityKnown = true
		}
		for tenant, domains := range edits {
			if len(domains) == 0 {
				delete(next.ByTenant, tenant)
			} else {
				next.ByTenant[tenant] = append([]string(nil), domains...)
			}
		}
		return json.Marshal(next)
	}
	var err error
	switch p := s.persister.(type) {
	case domainContextUpdater:
		err = p.UpdateContext(ctx, build)
	case domainUpdater:
		err = p.Update(build)
	default:
		for tenant, domains := range edits {
			if len(domains) == 0 {
				delete(next.ByTenant, tenant)
			} else {
				next.ByTenant[tenant] = append([]string(nil), domains...)
			}
		}
		err = s.saveSnapshotLocked(next)
	}
	if err != nil {
		return err
	}
	s.byTenant = next.ByTenant
	if s.persister != nil {
		s.authorityKnown = true
	}
	return nil
}
func (s *organizationDomainsStore) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.persister.(type) {
	case domainContextUpdater, domainUpdater:
	default:
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		if s.authorityKnown {
			return fmt.Errorf("organization domain authority disappeared")
		}
		return nil
	}
	next, err := decodeOrganizationDomains(raw)
	if err != nil {
		return err
	}
	s.byTenant = next.ByTenant
	s.authorityKnown = true
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
			domains, err := org.DomainsChecked(tenantID)
			if err != nil {
				return nil
			}
			for _, d := range domains {
				add(d)
			}
		}
		if idp != nil {
			connections, _, err := idp.TenantSnapshot(tenantID)
			if err != nil {
				return nil
			}
			for _, c := range connections {
				for _, d := range c.VerifiedDomains {
					add(d)
				}
			}
		}
		return out
	}
}

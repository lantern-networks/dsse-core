package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

// ValidateTenantRestrictions checks a distributed section before any store is changed.
func ValidateTenantRestrictions(settings map[string]tenantrestriction.Setting) error {
	for id, s := range settings {
		normalized, err := tenantrestriction.Validate(id, s)
		if err != nil {
			return err
		}
		if normalized != s {
			return fmt.Errorf("SaaS restriction configuration is not canonical")
		}
	}
	return nil
}

type TenantRestrictionPatch struct {
	AllowedValue    *string `json:"allowed_value,omitempty"`
	ContextTenantID *string `json:"context_tenant_id,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

// SaveTenantRestriction commits a tenant-owned setting durably before publishing it.
// Pointer fields distinguish omitted (keep) from explicit empty (clear).
func (store *Store) SaveTenantRestriction(tenant, provider string, patch TenantRestrictionPatch) error {
	return store.SaveTenantRestrictionContext(context.Background(), tenant, provider, patch)
}

func (store *Store) SaveTenantRestrictionContext(ctx context.Context, tenant, provider string, patch TenantRestrictionPatch) error {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return fmt.Errorf("select an organization before configuring SaaS restriction")
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	return store.updateTenantRestrictionsLocked(ctx, tenant, func(next map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error) {
		s := next[provider]
		if patch.AllowedValue != nil {
			s.AllowedValue = *patch.AllowedValue
		}
		if patch.ContextTenantID != nil {
			s.ContextTenantID = *patch.ContextTenantID
		}
		if patch.Enabled != nil {
			s.Enabled = *patch.Enabled
		}
		s, err := tenantrestriction.Validate(provider, s)
		if err != nil {
			return nil, err
		}
		next[provider] = s
		return next, nil
	})
}

type atomicRuntimeStatePersister interface {
	Update(func([]byte) ([]byte, error)) error
}

func (store *Store) updateTenantRestrictionsLocked(ctx context.Context, tenant string, edit func(map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error)) error {
	if store.runtimeStatePersister == nil {
		return fmt.Errorf("%w: durable admin configuration storage is not configured", ErrPolicyPersistence)
	}
	return store.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		next, err := edit(tenantrestriction.Copy(f.SaaSTenantRestrictions[tenant]))
		if err != nil {
			return err
		}
		f.SaaSTenantRestrictions[tenant] = next
		return nil
	})
}

// Read shared SaaS state at the point it is served, including the first bundle
// after promotion. No periodic timer can guarantee that final read. Edges using
// local stores do not perform I/O here; they retain their signed configuration.
func (store *Store) RefreshTenantRestrictions() error { return store.RefreshSharedRuntime() }

func (store *Store) compileTenantRestrictionsLocked(base *decision.Evaluator) {
	if len(store.tenantRestrictions) == 0 {
		return
	}
	rules := append([]model.SWGTenantRestrictionRule(nil), base.PolicyBundle.SWGTenantRestrictionRules...)
	catalog := append([]model.SaaSCatalogEntry(nil), base.PolicyBundle.SaaSCatalog...)
	values := map[string]string{}
	tenants := make([]string, 0, len(store.tenantRestrictions))
	for tenant := range store.tenantRestrictions {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)
	for _, tenant := range tenants {
		for _, p := range tenantrestriction.Providers() {
			s, exists := store.tenantRestrictions[tenant][p.ID]
			if !exists {
				continue
			}
			rules = append(rules, tenantrestriction.Rule(tenant, p, s))
			catalog = append(catalog, tenantrestriction.Catalog(tenant, p))
			if s.AllowedValue != "" {
				values[tenantrestriction.Ref(tenant, p.ID)] = s.AllowedValue
			}
			if s.ContextTenantID != "" {
				values[tenantrestriction.Ref(tenant, p.ID)+"/context"] = s.ContextTenantID
			}
		}
	}
	base.PolicyBundle.SWGTenantRestrictionRules = rules
	base.PolicyBundle.SaaSCatalog = catalog
	base.TenantRestrictionHeaderValues = values
}

func (store *Store) CountTenantRestrictions(tenant string) int {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.tenantRestrictions[tenant])
}

func (store *Store) RemoveTenantRestrictions(tenant string) (int, error) {
	return store.RemoveTenantRestrictionsContext(context.Background(), tenant)
}

func (store *Store) RemoveTenantRestrictionsContext(ctx context.Context, tenant string) (int, error) {
	if store == nil {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, shared := store.runtimeStatePersister.(atomicRuntimeStatePersister); !shared && len(store.tenantRestrictions[tenant]) == 0 {
		return 0, nil
	}
	count := 0
	err := store.updateTenantRestrictionsLocked(ctx, tenant, func(previous map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error) {
		count = len(previous)
		return map[string]tenantrestriction.Setting{}, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

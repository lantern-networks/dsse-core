package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
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
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return fmt.Errorf("select an organization before configuring SaaS restriction")
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	return store.updateTenantRestrictionsLocked(tenant, func(next map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error) {
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

func (store *Store) updateTenantRestrictionsLocked(tenant string, edit func(map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error)) error {
	if store.runtimeStatePersister == nil {
		return fmt.Errorf("durable admin configuration storage is not configured")
	}
	if atomic, ok := store.runtimeStatePersister.(atomicRuntimeStatePersister); ok {
		var committed map[string]map[string]tenantrestriction.Setting
		err := atomic.Update(func(raw []byte) ([]byte, error) {
			document := map[string]json.RawMessage{}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &document); err != nil {
					return nil, err
				}
			}
			all := map[string]map[string]tenantrestriction.Setting{}
			if section := document["saas_tenant_restrictions"]; len(section) > 0 {
				if err := json.Unmarshal(section, &all); err != nil {
					return nil, err
				}
			}
			if all == nil {
				all = map[string]map[string]tenantrestriction.Setting{}
			}
			for _, settings := range all {
				if err := ValidateTenantRestrictions(settings); err != nil {
					return nil, err
				}
			}
			next, err := edit(tenantrestriction.Copy(all[tenant]))
			if err != nil {
				return nil, err
			}
			all[tenant] = next
			document["saas_tenant_restrictions"], err = json.Marshal(all)
			if err != nil {
				return nil, err
			}
			committed = all
			return json.Marshal(document)
		})
		if err != nil {
			return fmt.Errorf("SaaS restriction was not saved: %w", err)
		}
		store.tenantRestrictions = committed
		store.generation++
		return nil
	}
	previous := store.tenantRestrictions[tenant]
	next, err := edit(tenantrestriction.Copy(previous))
	if err != nil {
		return err
	}
	store.tenantRestrictions[tenant] = next
	if err := store.persistLockedChecked(); err != nil {
		if previous == nil {
			delete(store.tenantRestrictions, tenant)
		} else {
			store.tenantRestrictions[tenant] = previous
		}
		return err
	}
	store.generation++
	return nil
}

// Read shared SaaS state at the point it is served, including the first bundle
// after promotion. No periodic timer can guarantee that final read. Edges using
// local stores do not perform I/O here; they retain their signed configuration.
func (store *Store) RefreshTenantRestrictions() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.runtimeStatePersister.(atomicRuntimeStatePersister); !ok {
		return nil
	}
	raw, err := store.runtimeStatePersister.Load()
	if err != nil {
		return err
	}
	var document struct {
		Settings map[string]map[string]tenantrestriction.Setting `json:"saas_tenant_restrictions"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &document); err != nil {
			return err
		}
	}
	if document.Settings == nil {
		document.Settings = map[string]map[string]tenantrestriction.Setting{}
	}
	for _, settings := range document.Settings {
		if err := ValidateTenantRestrictions(settings); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(document.Settings, store.tenantRestrictions) {
		store.tenantRestrictions = document.Settings
		store.generation++
	}
	return nil
}

// Compile rules and resolver values together. The evaluator owns this immutable
// snapshot for the whole request, including the eventual HTTP header rewrite.
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
	if store == nil {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, shared := store.runtimeStatePersister.(atomicRuntimeStatePersister); !shared && len(store.tenantRestrictions[tenant]) == 0 {
		return 0, nil
	}
	count := 0
	err := store.updateTenantRestrictionsLocked(tenant, func(previous map[string]tenantrestriction.Setting) (map[string]tenantrestriction.Setting, error) {
		count = len(previous)
		return map[string]tenantrestriction.Setting{}, nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

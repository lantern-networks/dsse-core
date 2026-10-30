package policy

import (
	"context"
	"fmt"
	"strings"
)

const (
	UpstreamTLSStrict            = "strict"
	UpstreamTLSBrowserCompatible = "browser_compatible"
	// UpstreamTLSDefault applies to every organization that has not chosen a
	// mode. Browser compatibility is the default (2026-10-29 operator decision):
	// a site that opens in Chrome must open through DSSE. Strict stays available
	// as an explicit per-organization choice.
	UpstreamTLSDefault = UpstreamTLSBrowserCompatible
)

func validAuthoredUpstreamTLSMode(mode string) bool {
	return mode == UpstreamTLSStrict || mode == UpstreamTLSBrowserCompatible
}

// ValidateUpstreamTLSMode accepts the omitted field, which means the default.
// Authored updates must name one of the two modes explicitly.
func ValidateUpstreamTLSMode(mode string) error {
	if mode != "" && !validAuthoredUpstreamTLSMode(mode) {
		return fmt.Errorf("upstream TLS mode must be strict or browser_compatible")
	}
	return nil
}

// EffectiveUpstreamTLSMode resolves an unset mode to the default. Only an
// explicit strict choice turns compatibility off.
func EffectiveUpstreamTLSMode(mode string) string {
	if mode == "" {
		return UpstreamTLSDefault
	}
	return mode
}

// ValidateTenantConfig runs before applying any distributed tenant controls.
func ValidateTenantConfig(cfg TenantConfigBundle) error {
	if err := ValidateUpstreamTLSMode(cfg.UpstreamTLSMode); err != nil {
		return err
	}
	return ValidateTenantRestrictions(cfg.SaaSTenantRestrictions)
}

// UpstreamTLSModeFor is a read-only hot-path view of the applied tenant setting.
func (store *Store) UpstreamTLSModeFor(tenantID string) string {
	if store == nil {
		return UpstreamTLSDefault
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return EffectiveUpstreamTLSMode(store.upstreamTLSModes[strings.TrimSpace(tenantID)])
}

func (store *Store) SetUpstreamTLSModeConfirmed(tenantID, mode string) error {
	return store.SetUpstreamTLSModeContext(context.Background(), tenantID, mode)
}

// SetUpstreamTLSModeContext saves the latest shared authority before publishing
// locally. Separate tenant keys survive concurrent writes and CP promotion.
func (store *Store) SetUpstreamTLSModeContext(ctx context.Context, tenantID, mode string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("select a tenant before configuring upstream TLS")
	}
	if !validAuthoredUpstreamTLSMode(mode) {
		return fmt.Errorf("upstream TLS mode must be strict or browser_compatible")
	}
	if store == nil {
		return ErrPolicyPersistence
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.runtimeStatePersister == nil {
		return fmt.Errorf("%w: durable admin configuration storage is not configured", ErrPolicyPersistence)
	}
	return store.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		f.UpstreamTLSModes[tenantID] = mode
		return nil
	})
}

// UpstreamTLSConfigurable reports whether authored edits have durable storage.
func (store *Store) UpstreamTLSConfigurable() bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.runtimeStatePersister != nil
}
func (store *Store) CountUpstreamTLSSettings(tenant string) int {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	// Only a choice that differs from the default changes behaviour.
	if mode := store.upstreamTLSModes[tenant]; mode != "" && mode != UpstreamTLSDefault {
		return 1
	}
	return 0
}
func (store *Store) RemoveUpstreamTLSSettingsContext(ctx context.Context, tenant string) (int, error) {
	if store == nil {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	count := 0
	err := store.editRuntimeLocked(ctx, func(f *adminPolicyRuntimeStateFile) error {
		if mode := f.UpstreamTLSModes[tenant]; mode != "" && mode != UpstreamTLSDefault {
			count = 1
		}
		// Retain an explicit reset for Edges that still hold the former mode.
		f.UpstreamTLSModes[tenant] = UpstreamTLSDefault
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

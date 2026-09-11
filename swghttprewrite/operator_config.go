package swghttprewrite

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/model"
)

const (
	SWGOperatorConfigSchemaVersion = "swg_tenant_restriction_operator_config.v1"
	DefaultSWGOperatorConfigPath   = "config/swg/swg_tenant_restriction_operator_config.json"
)

type OperatorManagedHeaderValueConfig struct {
	SchemaVersion string                       `json:"schema_version"`
	Status        string                       `json:"status"`
	TenantID      string                       `json:"tenant_id"`
	Version       string                       `json:"version"`
	HeaderValues  []OperatorManagedHeaderValue `json:"header_values"`
	Metadata      map[string]any               `json:"metadata"`
}

type OperatorManagedHeaderValue struct {
	Ref               string         `json:"ref"`
	TenantID          string         `json:"tenant_id"`
	SaaSApplicationID string         `json:"saas_application_id"`
	Provider          string         `json:"provider"`
	HeaderName        string         `json:"header_name"`
	HeaderValueKind   string         `json:"header_value_kind"`
	Value             string         `json:"value"`
	Status            string         `json:"status"`
	Metadata          map[string]any `json:"metadata"`
}

// operatorResolverState is the immutable header-value snapshot the resolver serves. It is swapped
// atomically for hot-apply (Admin API value updates) so request-time reads never see a torn map.
type operatorResolverState struct {
	values map[string]string
	refs   []string
}

// OperatorManagedHeaderValueResolver resolves operator-managed tenant-restriction header values by
// ref. The state is held behind a shared *atomic.Pointer so value copies of the resolver (it is
// passed by value through the SWG runtime config) share the same live state and observe hot-apply
// swaps. The zero value resolves nothing (used when tenant restriction is not configured).
type OperatorManagedHeaderValueResolver struct {
	state *atomic.Pointer[operatorResolverState]
}

func LoadOperatorManagedHeaderValueResolver(path string, bundle model.PolicyBundle) (OperatorManagedHeaderValueResolver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return OperatorManagedHeaderValueResolver{}, err
	}
	if err := rejectHeaderValueKeys(data); err != nil {
		return OperatorManagedHeaderValueResolver{}, err
	}

	var config OperatorManagedHeaderValueConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return OperatorManagedHeaderValueResolver{}, err
	}
	return NewOperatorManagedHeaderValueResolver(config, bundle)
}

func NewOperatorManagedHeaderValueResolver(config OperatorManagedHeaderValueConfig, bundle model.PolicyBundle) (OperatorManagedHeaderValueResolver, error) {
	if config.SchemaVersion != SWGOperatorConfigSchemaVersion {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config schema_version=%s want %s", config.SchemaVersion, SWGOperatorConfigSchemaVersion)
	}
	if config.Status != "active" {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config status=%s want active", config.Status)
	}
	if strings.TrimSpace(config.TenantID) == "" {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config tenant_id is required")
	}
	if config.TenantID != bundle.TenantID {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config tenant_id=%s does not match policy bundle tenant_id=%s", config.TenantID, bundle.TenantID)
	}
	if boolConfigMetadata(config.Metadata, "designated_operator_config_file") != true {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config must be marked as designated_operator_config_file")
	}
	if boolConfigMetadata(config.Metadata, "operator_authored_config_secret") {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config values must be marked non-secret")
	}
	if boolConfigMetadata(config.Metadata, "captured_secret_material_committed") {
		return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config must not commit captured secret material")
	}

	// Tenant restriction is OFF by default: zero ACTIVE rules is a valid state (no headers injected). The
	// operator config may still carry configured-and-ready header values for inactive rules, which an admin
	// activates later via the Admin API.
	required := requiredTenantRestrictionRules(bundle)
	known := knownTenantRestrictionRules(bundle)

	values := make(map[string]string, len(config.HeaderValues))
	entries := make(map[string]OperatorManagedHeaderValue, len(config.HeaderValues))
	for _, entry := range config.HeaderValues {
		ref := strings.TrimSpace(entry.Ref)
		if ref == "" || !strings.HasPrefix(ref, "operator_config_ref:") {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config entry has invalid ref")
		}
		if _, exists := values[ref]; exists {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("duplicate operator config ref %s", ref)
		}
		if entry.Status != "active" {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s status=%s want active", ref, entry.Status)
		}
		value := strings.TrimSpace(entry.Value)
		if value == "" {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s value is required", ref)
		}
		if boolConfigMetadata(entry.Metadata, "operator_managed") != true {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s must be operator managed", ref)
		}
		if boolConfigMetadata(entry.Metadata, "operator_config_value_secret") {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s must be marked non-secret", ref)
		}
		if boolConfigMetadata(entry.Metadata, "captured_secret_material_committed") {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s must not commit captured secret material", ref)
		}
		if boolConfigMetadata(entry.Metadata, "report_value_material_logged") {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s must not allow report value material", ref)
		}
		values[ref] = value
		entries[ref] = entry
	}

	for ref, rule := range required {
		entry, ok := entries[ref]
		if !ok {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config missing required ref %s", ref)
		}
		if entry.TenantID != rule.TenantID ||
			entry.SaaSApplicationID != rule.SaaSApplicationID ||
			entry.Provider != rule.Provider ||
			entry.HeaderName != rule.HeaderName ||
			entry.HeaderValueKind != rule.HeaderValueKind {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("%s operator config metadata does not match tenant restriction rule", ref)
		}
	}
	for ref := range values {
		if _, ok := known[ref]; !ok {
			return OperatorManagedHeaderValueResolver{}, fmt.Errorf("operator config ref %s is not referenced by any tenant restriction rule", ref)
		}
	}

	refs := make([]string, 0, len(values))
	for ref := range values {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	state := &atomic.Pointer[operatorResolverState]{}
	state.Store(&operatorResolverState{values: values, refs: refs})
	return OperatorManagedHeaderValueResolver{state: state}, nil
}

func (r OperatorManagedHeaderValueResolver) loadState() *operatorResolverState {
	if r.state == nil {
		return nil
	}
	return r.state.Load()
}

func (r OperatorManagedHeaderValueResolver) ResolveHeaderValue(ref string) (string, bool) {
	state := r.loadState()
	if state == nil {
		return "", false
	}
	value, ok := state.values[ref]
	return value, ok
}

func (r OperatorManagedHeaderValueResolver) OperatorConfigRefs() []string {
	state := r.loadState()
	if state == nil {
		return nil
	}
	return append([]string(nil), state.refs...)
}

// ReplaceHeaderValues hot-swaps the header values for already-configured refs (Admin API write path,
// increment 2). Only refs that already exist may be updated; adding a new ref/SaaS requires a
// policy-bundle rule change and is rejected here. The swap is atomic so concurrent request-time reads
// observe either the old or the new snapshot, never a partial map. Returns the sorted applied refs.
func (r OperatorManagedHeaderValueResolver) ReplaceHeaderValues(updates map[string]string) ([]string, error) {
	current := r.loadState()
	if current == nil {
		return nil, fmt.Errorf("tenant restriction resolver is not configured")
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("no header value updates provided")
	}
	next := make(map[string]string, len(current.values))
	for k, v := range current.values {
		next[k] = v
	}
	applied := make([]string, 0, len(updates))
	for ref, value := range updates {
		ref = strings.TrimSpace(ref)
		if _, ok := next[ref]; !ok {
			return nil, fmt.Errorf("ref %s is not a configured active tenant restriction ref", ref)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("ref %s value is required", ref)
		}
		next[ref] = value
		applied = append(applied, ref)
	}
	sort.Strings(applied)
	r.state.Store(&operatorResolverState{values: next, refs: current.refs})
	return applied, nil
}

func (r OperatorManagedHeaderValueResolver) OperatorConfigRefCount() int {
	state := r.loadState()
	if state == nil {
		return 0
	}
	return len(state.refs)
}

func requiredTenantRestrictionRules(bundle model.PolicyBundle) map[string]model.SWGTenantRestrictionRule {
	required := map[string]model.SWGTenantRestrictionRule{}
	for _, rule := range bundle.SWGTenantRestrictionRules {
		if rule.Status != "active" {
			continue
		}
		ref := strings.TrimSpace(rule.HeaderValueRef)
		if ref == "" {
			continue
		}
		required[ref] = rule
	}
	return required
}

// knownTenantRestrictionRules returns ALL tenant-restriction rules (active AND inactive) keyed by ref. Tenant
// restriction is OFF by default (no active rules), but the operator may keep the header VALUES configured and
// ready (the admin enables a rule later). So an operator-config value is valid when it corresponds to any
// known rule — not only an active one.
func knownTenantRestrictionRules(bundle model.PolicyBundle) map[string]model.SWGTenantRestrictionRule {
	known := map[string]model.SWGTenantRestrictionRule{}
	for _, rule := range bundle.SWGTenantRestrictionRules {
		ref := strings.TrimSpace(rule.HeaderValueRef)
		if ref == "" {
			continue
		}
		known[ref] = rule
	}
	return known
}

func rejectHeaderValueKeys(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			if _, ok := v["header_value"]; ok {
				return fmt.Errorf("operator config must not use header_value key")
			}
			for _, child := range v {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(raw)
}

func boolConfigMetadata(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, _ := metadata[key].(bool)
	return value
}

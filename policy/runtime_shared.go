package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

type contextRuntimePersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func cloneRuntimePolicies(in map[string]map[string]model.Policy) map[string]map[string]model.Policy {
	out := map[string]map[string]model.Policy{}
	for tenant, rows := range in {
		out[tenant] = map[string]model.Policy{}
		for id, p := range rows {
			out[tenant][id] = copyAdminPolicy(p)
		}
	}
	return out
}

func normalizeRuntimeMaps(f *adminPolicyRuntimeStateFile) {
	if f.SaaSTenantRestrictions == nil {
		f.SaaSTenantRestrictions = map[string]map[string]tenantrestriction.Setting{}
	}
	if f.TenantRestrictionRuleStatus == nil {
		f.TenantRestrictionRuleStatus = map[string]string{}
	}
	if f.PolicyStatusOverride == nil {
		f.PolicyStatusOverride = map[string]map[string]string{}
	}
	if f.EastWestEnabled == nil {
		f.EastWestEnabled = map[string]bool{}
	}
	if f.EastWestAllowUnmatched == nil {
		f.EastWestAllowUnmatched = map[string]bool{}
	}
	if f.EastWestRules == nil {
		f.EastWestRules = map[string][]decision.EastWestRule{}
	}
	if f.EastWestMaxGrantTTL == nil {
		f.EastWestMaxGrantTTL = map[string]int{}
	}
	if f.ServerInitiatedEnabled == nil {
		f.ServerInitiatedEnabled = map[string]bool{}
	}
	if f.LegacyExceptions == nil {
		f.LegacyExceptions = map[string][]model.LegacyException{}
	}
	if f.AdminAuthoredPolicies == nil {
		f.AdminAuthoredPolicies = map[string]map[string]model.Policy{}
	}
}

func decodeRuntimeState(raw []byte) (adminPolicyRuntimeStateFile, map[string]json.RawMessage, error) {
	var f adminPolicyRuntimeStateFile
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return f, nil, err
	}
	if len(document) == 0 {
		return f, nil, fmt.Errorf("empty runtime authority")
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, nil, err
	}
	if f.SchemaVersion != "" && f.SchemaVersion != adminPolicyRuntimeStateSchemaVersion {
		return f, nil, fmt.Errorf("unsupported runtime schema")
	}
	// Legacy SaaS-only and pre-schema toggle documents remain readable.
	known := false
	for _, key := range runtimeFieldNames {
		if value, ok := document[key]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return f, nil, fmt.Errorf("null runtime field %s", key)
		}
		if _, ok := document[key]; ok {
			known = true
		}
	}
	if !known {
		return f, nil, fmt.Errorf("runtime authority has no known fields")
	}
	for _, settings := range f.SaaSTenantRestrictions {
		if err := ValidateTenantRestrictions(settings); err != nil {
			return f, nil, err
		}
	}
	normalizeRuntimeMaps(&f)
	return f, document, nil
}

var runtimeFieldNames = []string{"schema_version", "saas_tenant_restrictions", "tenant_restriction_rule_status", "policy_status_override", "east_west_enabled", "east_west_allow_unmatched", "east_west_rules", "east_west_max_grant_ttl", "server_initiated_enabled", "legacy_exceptions", "admin_authored_policies"}

func (s *Store) runtimeSnapshotLocked() adminPolicyRuntimeStateFile {
	return adminPolicyRuntimeStateFile{SchemaVersion: adminPolicyRuntimeStateSchemaVersion, SaaSTenantRestrictions: s.tenantRestrictions, TenantRestrictionRuleStatus: s.tenantRestrictionRuleStatus, PolicyStatusOverride: s.policyStatusOverride, EastWestEnabled: s.eastWestEnabled, EastWestAllowUnmatched: s.eastWestAllowUnmatched, EastWestRules: s.eastWestRules, EastWestMaxGrantTTL: s.eastWestMaxGrantTTL, ServerInitiatedEnabled: s.serverInitiatedEnabled, LegacyExceptions: s.legacyExceptions, AdminAuthoredPolicies: s.adminAuthoredPolicies}
}

// Adopt authored state while keeping bundle and compiled ownership separate.
func (s *Store) adoptRuntimeLocked(f adminPolicyRuntimeStateFile) {
	normalizeRuntimeMaps(&f)
	s.tenantRestrictions = f.SaaSTenantRestrictions
	s.tenantRestrictionRuleStatus = f.TenantRestrictionRuleStatus
	s.policyStatusOverride = f.PolicyStatusOverride
	s.eastWestEnabled = f.EastWestEnabled
	s.eastWestAllowUnmatched = f.EastWestAllowUnmatched
	s.eastWestRules = f.EastWestRules
	s.eastWestMaxGrantTTL = f.EastWestMaxGrantTTL
	s.serverInitiatedEnabled = f.ServerInitiatedEnabled
	s.legacyExceptions = f.LegacyExceptions
	s.adminAuthoredPolicies = f.AdminAuthoredPolicies
	s.policies = cloneRuntimePolicies(s.runtimeBasePolicies)
	for tenant := range f.AdminAuthoredPolicies {
		s.reapplyRuntimeOverlaysLocked(tenant)
	}
	s.applyPolicyStatusOverridesLocked()
	s.rebuildPolicyCacheLocked()
}

// Caller holds mu. The callback edits a detached, latest document, never live state.
func (s *Store) editRuntimeLocked(ctx context.Context, edit func(*adminPolicyRuntimeStateFile) error) error {
	var next adminPolicyRuntimeStateFile
	var callbackErr error
	build := func(raw []byte) ([]byte, error) {
		document := map[string]json.RawMessage{}
		var err error
		if raw == nil {
			if s.runtimeAuthorityKnown {
				return nil, fmt.Errorf("runtime authority disappeared")
			}
			raw, err = json.Marshal(s.runtimeSnapshotLocked())
			if err != nil {
				return nil, err
			}
		}
		next, document, err = decodeRuntimeState(raw)
		if err != nil {
			return nil, err
		}
		if err = edit(&next); err != nil {
			callbackErr = err
			return nil, err
		}
		next.SchemaVersion = adminPolicyRuntimeStateSchemaVersion
		encoded, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(encoded, &fields); err != nil {
			return nil, err
		}
		for _, key := range runtimeFieldNames {
			delete(document, key)
		}
		for key, value := range fields {
			document[key] = value
		}
		// Detach from callback input (including nested rule conditions/slices).
		if next, _, err = decodeRuntimeState(encoded); err != nil {
			return nil, err
		}
		return json.Marshal(document)
	}
	var err error
	shared := false
	switch p := s.runtimeStatePersister.(type) {
	case contextRuntimePersister:
		shared = true
		err = p.UpdateContext(ctx, build)
	case atomicRuntimeStatePersister:
		shared = true
		err = p.Update(build)
	default:
		raw, e := json.Marshal(s.runtimeSnapshotLocked())
		if e != nil {
			return ErrPolicyPersistence
		}
		raw, err = build(raw)
		if err == nil && p != nil {
			err = p.Save(raw)
		}
	}
	if err != nil {
		if callbackErr != nil {
			return callbackErr
		}
		if !shared && errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			// Replacement completed: preserve the same controls a restart will load.
			s.adoptRuntimeLocked(next)
			s.generation++
			s.runtimeAuthorityKnown = true
		}
		if shared || !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return fmt.Errorf("%w: %v", ErrPolicyPersistence, err)
		}
	}
	s.adoptRuntimeLocked(next)
	s.generation++
	if s.runtimeStatePersister != nil {
		s.runtimeAuthorityKnown = true
	}
	return nil
}

// RefreshSharedRuntime runs before management reads/bundle generation, not on the flow hot path.
func (s *Store) RefreshSharedRuntime() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, a := s.runtimeStatePersister.(contextRuntimePersister)
	_, b := s.runtimeStatePersister.(atomicRuntimeStatePersister)
	if !a && !b {
		return nil
	}
	raw, err := s.runtimeStatePersister.Load()
	if err != nil {
		return ErrPolicyPersistence
	}
	if raw == nil {
		if s.runtimeAuthorityKnown {
			return ErrPolicyPersistence
		}
		return nil
	}
	f, _, err := decodeRuntimeState(raw)
	if err != nil {
		return ErrPolicyPersistence
	}
	current := s.runtimeSnapshotLocked()
	normalizeRuntimeMaps(&current)
	f.SchemaVersion = adminPolicyRuntimeStateSchemaVersion
	if !reflect.DeepEqual(current, f) {
		s.adoptRuntimeLocked(f)
		s.generation++
	}
	s.runtimeAuthorityKnown = true
	return nil
}

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Edit only incoming fields in the latest durable document. Publish locally after save succeeds.
// The caller holds s.mu; the callback receives an independent decoded candidate.
func (s *Store) editIncomingRuntimeLocked(ctx context.Context, edit func(*adminPolicyRuntimeStateFile) error) error {
	if s == nil {
		return ErrPolicyPersistence
	}
	current := adminPolicyRuntimeStateFile{
		SchemaVersion:               adminPolicyRuntimeStateSchemaVersion,
		SaaSTenantRestrictions:      s.tenantRestrictions,
		TenantRestrictionRuleStatus: s.tenantRestrictionRuleStatus,
		PolicyStatusOverride:        s.policyStatusOverride,
		EastWestEnabled:             s.eastWestEnabled,
		EastWestAllowUnmatched:      s.eastWestAllowUnmatched,
		EastWestRules:               s.eastWestRules,
		EastWestMaxGrantTTL:         s.eastWestMaxGrantTTL,
		ServerInitiatedEnabled:      s.serverInitiatedEnabled,
		LegacyExceptions:            s.legacyExceptions,
		AdminAuthoredPolicies:       s.adminAuthoredPolicies,
	}
	var editErr error
	var committed adminPolicyRuntimeStateFile
	build := func(raw []byte) ([]byte, error) {
		if raw == nil {
			if s.runtimeAuthorityKnown {
				return nil, fmt.Errorf("runtime authority disappeared")
			}
			var err error
			raw, err = json.Marshal(current)
			if err != nil {
				return nil, err
			}
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil || len(document) == 0 {
			return nil, fmt.Errorf("invalid runtime authority")
		}
		var next adminPolicyRuntimeStateFile
		if err := json.Unmarshal(raw, &next); err != nil || (next.SchemaVersion != "" && next.SchemaVersion != adminPolicyRuntimeStateSchemaVersion) {
			return nil, fmt.Errorf("unsupported runtime authority")
		}
		if next.ServerInitiatedEnabled == nil {
			next.ServerInitiatedEnabled = map[string]bool{}
		}
		if next.LegacyExceptions == nil {
			next.LegacyExceptions = map[string][]model.LegacyException{}
		}
		if editErr = edit(&next); editErr != nil {
			return nil, editErr
		}
		next.SchemaVersion = adminPolicyRuntimeStateSchemaVersion
		for _, section := range []struct {
			key   string
			value any
		}{
			{"schema_version", next.SchemaVersion},
			{"server_initiated_enabled", next.ServerInitiatedEnabled},
			{"legacy_exceptions", next.LegacyExceptions},
		} {
			encoded, err := json.Marshal(section.value)
			if err != nil {
				return nil, err
			}
			document[section.key] = encoded
		}
		committed = next
		return json.Marshal(document)
	}
	var err error
	switch p := s.runtimeStatePersister.(type) {
	case interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}:
		err = p.UpdateContext(ctx, build)
	case atomicRuntimeStatePersister:
		err = p.Update(build)
	case nil:
		_, err = build(nil)
	default:
		var raw []byte
		raw, err = p.Load()
		if err == nil {
			var encoded []byte
			encoded, err = build(raw)
			if err == nil {
				err = p.Save(encoded)
			}
		}
	}
	if editErr != nil {
		return editErr
	}
	if err = blobstore.UnconfirmedSave(err); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyPersistence, err)
	}
	s.serverInitiatedEnabled = committed.ServerInitiatedEnabled
	s.legacyExceptions = committed.LegacyExceptions
	s.generation++
	if s.runtimeStatePersister != nil {
		s.runtimeAuthorityKnown = true
	}
	return nil
}

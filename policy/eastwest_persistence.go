package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
)

var ErrPolicyPersistence = errors.New("policy could not be saved")

type eastWestContextPersister interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (s *Store) ApplyEastWestUpdateConfirmed(tenant string, rules *[]decision.EastWestRule, ttl *int, enabled, unmatched *bool) error {
	return s.ApplyEastWestUpdateContext(context.Background(), tenant, rules, ttl, enabled, unmatched)
}

// ApplyEastWestUpdateContext saves one complete admin edit before publishing it to the live store.
// Shared persisters edit the latest row so another CP's unrelated settings are retained.
func (s *Store) ApplyEastWestUpdateContext(ctx context.Context, tenant string, rules *[]decision.EastWestRule, ttl *int, enabled, unmatched *bool) error {
	if s == nil {
		return ErrPolicyPersistence
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant = strings.TrimSpace(tenant)
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
		if next.EastWestRules == nil {
			next.EastWestRules = map[string][]decision.EastWestRule{}
		}
		if next.EastWestMaxGrantTTL == nil {
			next.EastWestMaxGrantTTL = map[string]int{}
		}
		if next.EastWestEnabled == nil {
			next.EastWestEnabled = map[string]bool{}
		}
		if next.EastWestAllowUnmatched == nil {
			next.EastWestAllowUnmatched = map[string]bool{}
		}
		if rules != nil {
			next.EastWestRules[tenant] = append([]decision.EastWestRule(nil), (*rules)...)
		}
		if ttl != nil {
			next.EastWestMaxGrantTTL[tenant] = max(0, *ttl)
		}
		if enabled != nil {
			next.EastWestEnabled[tenant] = *enabled
		}
		if unmatched != nil {
			next.EastWestAllowUnmatched[tenant] = *unmatched
		}
		next.SchemaVersion = adminPolicyRuntimeStateSchemaVersion
		for _, section := range []struct {
			key   string
			value any
		}{
			{"schema_version", next.SchemaVersion},
			{"east_west_rules", next.EastWestRules},
			{"east_west_max_grant_ttl", next.EastWestMaxGrantTTL},
			{"east_west_enabled", next.EastWestEnabled},
			{"east_west_allow_unmatched", next.EastWestAllowUnmatched},
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
	case eastWestContextPersister:
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
	if err != nil && !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
		return fmt.Errorf("%w: %v", ErrPolicyPersistence, err)
	}
	s.eastWestRules = committed.EastWestRules
	s.eastWestMaxGrantTTL = committed.EastWestMaxGrantTTL
	s.eastWestEnabled = committed.EastWestEnabled
	s.eastWestAllowUnmatched = committed.EastWestAllowUnmatched
	s.generation++
	if s.runtimeStatePersister != nil {
		s.runtimeAuthorityKnown = true
	}
	return nil
}

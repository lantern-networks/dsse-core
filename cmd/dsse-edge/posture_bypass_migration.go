package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// migratePostureOptimizeBypassToRules folds any legacy posture.bypass_groups selection (the pre-B-1 way to
// raw-forward a SaaS Optimize group like m365_optimize) into first-class authored Egress BYPASS rules — the
// unified model's single source of truth. The Console authors these on toggle today
// (Any -> bi-grp-<group> => allow x bypass, see console/effective_policy.js); this is the one-time startup
// migration for a posture set directly or persisted before B-1, so the engine stops needing the legacy
// EffectiveBypassGroupHosts read (the last dual bypass source alongside authored rules).
//
// It is idempotent and UI-coherent: the match is by DESTINATION (bi-grp-<name>) + inspection==bypass — exactly
// how the Console identifies an existing optimize-bypass rule — so a group that already has such a rule is
// skipped, and the UI's two-way toggle still finds and removes a migrated rule (it deletes every matching rule,
// regardless of id). After emitting, the posture's bypass_groups is cleared so the engine no longer double-reads
// it and the "Why" view attributes the host to the authored rule. On a default deployment (decrypt_all with no
// Optimize group enabled) bypass_groups is empty, so this is a no-op and the North Star path is untouched.
// Returns the number of rules emitted.
func migratePostureOptimizeBypassToRules(store *inspectionposture.Store, rules *policyrule.Store, tenantID string) int {
	if store == nil || rules == nil {
		return 0
	}
	p := store.Get()
	if len(p.BypassGroups) == 0 {
		return 0
	}
	existing := rules.List(tenantID, policyrule.PlaneEgress)
	hasBypassRuleFor := func(group string) bool {
		dest := "bi-grp-" + group
		for _, r := range existing {
			if r.Action.Inspection != policyrule.InspectionBypass {
				continue
			}
			for _, d := range r.Destination {
				if strings.EqualFold(d, dest) {
					return true
				}
			}
		}
		return false
	}
	emitted := 0
	for _, name := range p.BypassGroups {
		name = strings.TrimSpace(name)
		if name == "" || hasBypassRuleFor(name) {
			continue
		}
		// Match the Console's authored shape so a migrated rule is indistinguishable from a UI-created one.
		if _, err := rules.Upsert(policyrule.Rule{
			ID: "optimize-bypass-" + name, TenantID: tenantID, Plane: policyrule.PlaneEgress,
			Priority: 60, Name: "Optimize bypass: " + name,
			Source: []string{policyrule.SubjectAny}, Destination: []string{"bi-grp-" + name},
			Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
			Status: policyrule.StatusActive,
		}); err == nil {
			emitted++
		}
	}
	// The selection is now expressed as rules; clear it so it is no longer a parallel engine source.
	p.BypassGroups = nil
	store.Set(p)
	return emitted
}

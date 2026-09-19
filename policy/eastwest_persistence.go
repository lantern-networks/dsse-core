package policy

import (
	"log"
	"maps"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
)

// ApplyEastWestUpdateConfirmed saves the entire admin update once, under one lock.
// A refused or unconfirmed save must not publish a new live enforcement mode.
func (store *Store) ApplyEastWestUpdateConfirmed(tenant string, rules *[]decision.EastWestRule, ttl *int, enabled, unmatched *bool) error {
	if store == nil {
		return ErrPolicyPersistence
	}
	if rules == nil && ttl == nil && enabled == nil && unmatched == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenant = strings.TrimSpace(tenant)
	oldRules, oldTTL, oldEnabled, oldUnmatched := store.eastWestRules, store.eastWestMaxGrantTTL, store.eastWestEnabled, store.eastWestAllowUnmatched
	store.eastWestRules = maps.Clone(oldRules)
	if store.eastWestRules == nil {
		store.eastWestRules = map[string][]decision.EastWestRule{}
	}
	store.eastWestMaxGrantTTL = maps.Clone(oldTTL)
	if store.eastWestMaxGrantTTL == nil {
		store.eastWestMaxGrantTTL = map[string]int{}
	}
	store.eastWestEnabled = maps.Clone(oldEnabled)
	if store.eastWestEnabled == nil {
		store.eastWestEnabled = map[string]bool{}
	}
	store.eastWestAllowUnmatched = maps.Clone(oldUnmatched)
	if store.eastWestAllowUnmatched == nil {
		store.eastWestAllowUnmatched = map[string]bool{}
	}
	if rules != nil {
		store.eastWestRules[tenant] = append([]decision.EastWestRule(nil), (*rules)...)
	}
	if ttl != nil {
		store.eastWestMaxGrantTTL[tenant] = max(0, *ttl)
	}
	if enabled != nil {
		store.eastWestEnabled[tenant] = *enabled
	}
	if unmatched != nil {
		store.eastWestAllowUnmatched[tenant] = *unmatched
	}
	if err := store.persistLockedChecked(); err != nil {
		store.eastWestRules, store.eastWestMaxGrantTTL, store.eastWestEnabled, store.eastWestAllowUnmatched = oldRules, oldTTL, oldEnabled, oldUnmatched
		log.Printf("east-west setting save: %v", err)
		return ErrPolicyPersistence
	}
	store.generation++
	return nil
}

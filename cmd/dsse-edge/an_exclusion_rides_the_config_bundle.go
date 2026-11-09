package main

// an_exclusion_rides_the_config_bundle.go — administrator-authored steering exclusions travel to every Edge on
// the channel the Edges actually pull: the config bundle.
//
// ★★★ "ACTIVE" ON THE SCREEN, "refreshed 0 signed exclusion(s)" ON THE DEVICE (2026-11-08, acceptance C, third
// walk). An administrator excluded ssh.exe so a steered machine could keep its SSH session; the control plane
// saved the policy and the Console listed it as active, and the device went on logging zero exclusions once a
// minute until it was uninstalled. The device takes its signed set from the Edge it steers through, and the
// Edge had none: the bundle — the one thing an installer-built Edge pulls from the control plane — did not carry
// this store, and the separate pull that did (-steer-exclusion-source-url) was never configured by the
// installer and only ever asked for a single organization. Every other section of the bundle learned the same
// lesson earlier; this one had a channel of its own that nothing used.
//
// ★ THE SECTION NAMES THE ORGANIZATIONS IT SPEAKS FOR. An organization it names is REPLACED with what it
// carries, including with nothing — that is how a deleted exclusion leaves the fleet. An organization it does
// not name is left alone: a bundle served to a single organization's credential speaks only for that one, and
// must not be read as "every other organization has none".

import (
	"fmt"
	"sort"
	"strings"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

// steerExclusionBundle is every steering exclusion of the organizations in Tenants.
type steerExclusionBundle struct {
	Tenants  []string                `json:"tenants"`
	Policies []steerexclusion.Policy `json:"policies"`
}

// steerExclusionBundleFor builds the section on the control plane. fleet is whether the caller reads for the
// whole fleet (an Edge, the operator); otherwise only the caller's own organization is spoken for.
func steerExclusionBundleFor(all []steerexclusion.Policy, catalogue []adminTenantModel, callerTenant string, fleet bool) *steerExclusionBundle {
	named := map[string]bool{}
	if fleet {
		for _, t := range catalogue {
			if id := strings.TrimSpace(t.TenantID); id != "" {
				named[id] = true
			}
		}
		for _, p := range all {
			named[p.TenantID] = true
		}
	}
	if id := strings.TrimSpace(callerTenant); id != "" {
		named[id] = true
	}
	section := &steerExclusionBundle{Tenants: []string{}, Policies: []steerexclusion.Policy{}}
	for id := range named {
		section.Tenants = append(section.Tenants, id)
	}
	sort.Strings(section.Tenants)
	for _, p := range all {
		if named[p.TenantID] {
			section.Policies = append(section.Policies, p)
		}
	}
	return section
}

// applySteerExclusionBundle replaces the named organizations' sets on an Edge, all of them or none.
//
// ★ ONLY AN EXPLICIT LIST REMOVES ANYTHING (review C3-R4). A section whose policies are missing or null said
// nothing about them; read as an empty list it erased every exclusion of every organization it named. encoding/json
// leaves a missing or null array nil and an empty one non-nil, so the two are told apart here, and an incomplete
// section is refused — kept and offered again — like the dedicated pull always refused one.
func applySteerExclusionBundle(store *steerexclusion.Store, section *steerExclusionBundle) error {
	if store == nil || section == nil {
		return nil
	}
	if section.Tenants == nil || section.Policies == nil {
		return fmt.Errorf("the section does not say which organizations it speaks for, or what they hold")
	}
	byTenant := make(map[string][]steerexclusion.Policy, len(section.Tenants))
	for _, t := range section.Tenants {
		if t == "" || strings.TrimSpace(t) != t {
			return fmt.Errorf("the section names an organization that is not canonical")
		}
		byTenant[t] = []steerexclusion.Policy{}
	}
	for i, p := range section.Policies {
		if _, named := byTenant[p.TenantID]; !named {
			return fmt.Errorf("policy %d belongs to an organization the section does not speak for", i)
		}
		byTenant[p.TenantID] = append(byTenant[p.TenantID], p)
	}
	// One call: validated and checked for every organization before any is replaced, and a durable copy that
	// could not be written is an error, so the bundle is not recorded as applied (review C3-R3).
	return store.ReplaceTenantsChecked(byTenant)
}

// steerExclusionAuthority is where this node's exclusions are authored, when it is not here. An Edge that
// pulls a bundle holds a copy that the next poll replaces, so a write accepted here would be erased without a
// trace — the same reason the older dedicated pull refused writes.
func steerExclusionAuthority(config serverConfig) string {
	if u := strings.TrimSpace(config.SteerExclusionSourceURL); u != "" {
		return u
	}
	return strings.TrimSpace(config.ConfigSourceURL)
}

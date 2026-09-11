package main

import (
	"strconv"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/inspectionposture"
)

// builtInCatalogAssets turns the shipped SaaS catalog (decrypt + bypass groups) into built-in asset-catalog
// endpoints + groups, so a rule's destination can be a catalog group ("openai", "m365_optimize", …) and the
// engine resolves it to the host patterns. Read-only, tenant-agnostic, not persisted (Phase A2 of the unified
// policy model). Each catalog group becomes a group "bi-grp-<name>" whose members are one endpoint per pattern.
func builtInCatalogAssets() ([]assetcatalog.Endpoint, []assetcatalog.Group) {
	var endpoints []assetcatalog.Endpoint
	var groups []assetcatalog.Group
	add := func(g inspectionposture.AuthDecryptGroup) {
		var members []string
		for i, pattern := range g.Patterns {
			id := "bi-ep-" + g.Name + "-" + strconv.Itoa(i)
			endpoints = append(endpoints, assetcatalog.Endpoint{
				ID: id, Alias: pattern, Kind: assetcatalog.KindNetwork, Address: pattern,
				Source: assetcatalog.SourceManual, BuiltIn: true, Category: g.Category,
			})
			members = append(members, id)
		}
		groups = append(groups, assetcatalog.Group{
			ID: "bi-grp-" + g.Name, Alias: g.Name, StaticMembers: members, BuiltIn: true, Category: g.Category,
		})
	}
	for _, g := range inspectionposture.AuthDecryptGroups {
		add(g)
	}
	for _, g := range inspectionposture.SaaSBypassGroups {
		add(g)
	}
	return endpoints, groups
}

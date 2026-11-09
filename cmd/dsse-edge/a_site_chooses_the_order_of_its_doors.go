package main

// a_site_chooses_the_order_of_its_doors.go — the order in which a site's connectors use the deployment's
// entrances is the administrator's, per site.
//
// ★★★ AN OSAKA SITE THAT DIALS TOKYO FIRST (2026-11-08, the operator during acceptance C's third walk). A
// connector works through its doors in order and goes back to the first one once it has answered three checks in
// a row, so the first door is where the estate behind it lives — and every flow to it from a device in another
// region is relayed across regions to reach it. That order came from the deployment (the order its regions were
// declared) and nothing let an administrator change it: a device's configuration has had ↑↓ for its entrances
// since August; a connector had nothing. Region failover stays as it was — the other doors stay in the list, in
// the order given — only which one is first, and which comes next, is decided here.
//
// The order is held on the site, because the site is where the estate is. A site that has not been given one
// starts with its own region (the region an administrator wrote on it), then the deployment's order: before
// this, the site's region was written down and changed nothing.

import (
	"fmt"
	"strings"
)

// normalizeSiteDoorOrder trims, refuses what is not a region token, and drops repeats.
func normalizeSiteDoorOrder(order []string) ([]string, error) {
	if len(order) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(order))
	for _, region := range order {
		region = strings.TrimSpace(region)
		if region == "" {
			continue
		}
		if !safeAdminTenantToken(region) || strings.Contains(region, ",") {
			return nil, fmt.Errorf("door_order has an entry that is not a region: %q", region)
		}
		key := strings.ToLower(region)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, region)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// orderDoorsForSite puts a site's doors in the order its connectors should use them. doors are "region=URL"
// entries (or bare URLs, which have no region and keep their place after every named one). Regions named in
// order come first, in that order; with no order, the site's own region comes first. Everything else keeps the
// deployment's order. Nothing is added or removed: an order naming a region this organization cannot use is
// ignored for that region.
func orderDoorsForSite(doors []string, order []string, siteRegion string) []string {
	if len(doors) < 2 {
		return doors
	}
	if len(order) == 0 && strings.TrimSpace(siteRegion) != "" {
		order = []string{siteRegion}
	}
	if len(order) == 0 {
		return doors
	}
	regionOf := func(door string) string {
		if i := strings.Index(door, "="); i > 0 && !strings.Contains(door[:i], "/") {
			return strings.ToLower(strings.TrimSpace(door[:i]))
		}
		return ""
	}
	placed := make([]bool, len(doors))
	out := make([]string, 0, len(doors))
	for _, want := range order {
		want = strings.ToLower(strings.TrimSpace(want))
		for i, door := range doors {
			if !placed[i] && want != "" && regionOf(door) == want {
				out = append(out, door)
				placed[i] = true
			}
		}
	}
	for i, door := range doors {
		if !placed[i] {
			out = append(out, door)
		}
	}
	return out
}

// orderDoorListForSite is orderDoorsForSite for the ";"-joined list an enrolment token carries.
func orderDoorListForSite(list string, order []string, siteRegion string) string {
	list = strings.TrimSpace(list)
	if list == "" {
		return list
	}
	doors := []string{}
	for _, entry := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ',' || r == '\n' }) {
		if entry = strings.TrimSpace(entry); entry != "" {
			doors = append(doors, entry)
		}
	}
	return strings.Join(orderDoorsForSite(doors, order, siteRegion), ";")
}

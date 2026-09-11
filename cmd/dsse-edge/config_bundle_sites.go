package main

import (
	"context"
	"strings"
	"time"
)

// config_bundle_sites.go — carrying the Site / Connector Group catalog from the control plane to the Edges.
//
// ★★★ MEASURED BEFORE IT WAS WRITTEN (2026-08-23). The reference deployment, asked the same question twice:
//
//	control plane : lab-dc
//	Edge          : durable-site-1, lab-dc, renew-probe
//
// Two Sites the control plane has never heard of, and one of them predates tonight. Both directions were then
// measured directly: a Site CREATED on the control plane was still invisible on the Edge two minutes later,
// and a Site DELETED on the control plane was still there after three. Each node keeps its own store — the
// Edges share a file in this deployment, the control plane writes a different one — and nothing has ever
// carried a Site between them. The screens do not say so; they present one list.
//
// This is the same defect the directory section beside it records ("the control plane held 90 identities and
// BOTH enforcing Edges held zero, because nothing ever carried them"), one section later. In a pull-fleet the
// enforcing Edges are stateless pullers: anything they must be able to answer about has to be distributed, or
// it simply is not there.
//
// ★ AND IT IS LOAD-BEARING NOW. A connector proves itself with its Site's bootstrap secret
// (connector_enrolment_identity.go, tonight), and the Edge it dials is the party that checks it. An operator
// who issues "Add connector" on the control plane — which is where authority lives — produced a command no
// Edge could honour, because no Edge had the Site.
//
// ★ THE HASH RIDES, AND ONLY THE HASH. adminSiteModel carries BootstrapSecretHash, never the secret; the
// plaintext is returned once, to the operator, and stored nowhere. The Edge cannot authorise a connector
// without something to compare against, so withholding the hash would distribute a Site that is useless to the
// only node that needs it.
//
// ★ SERVED FOR EVERY ORGANIZATION, not the requesting one — the same decision the rules and directory sections
// record above. One Edge serves several organizations, and a connector belonging to any of them dials it; a
// tenant-scoped section would be correct for whichever organization happened to be asked and silently absent
// for the rest.

// siteCatalogBundle carries the Site catalog as one replace-all unit.
type siteCatalogBundle struct {
	Sites []adminSiteModel `json:"sites"`
	// Tenants names the organizations this catalogue SPEAKS FOR, which is not the same as the organizations
	// that happen to appear in Sites.
	//
	// ★ WITHOUT IT, "there are none" CANNOT BE SAID. An empty catalogue names no organization, so a reconcile
	// driven by the entries alone has nothing to walk and clears nothing — deleting the LAST Site of an
	// organization would never propagate, which is the half of the defect this file exists for. Listing the
	// organizations separately lets the publisher say "I looked at these, and this is all there is", and lets
	// an Edge leave every other organization strictly alone.
	Tenants []string `json:"tenants"`
	// Complete says the publisher's own store is DURABLE. An in-memory control plane that has just restarted is
	// empty for a reason that is not "there are none", and applying that would erase every Site off the fleet —
	// taking the bootstrap secret every waiting connector was about to present with it. Same guard the VLAN
	// section carries, for the same reason.
	Complete bool `json:"complete"`
}

// siteBundleSection builds the section the control plane publishes, or nil when this node holds no Site store
// (then it is not the Site authority and must not appear to be one).
func siteBundleSection(ctx context.Context, store adminSiteStore, tenants []string) *siteCatalogBundle {
	if store == nil {
		return nil
	}
	section := &siteCatalogBundle{Sites: []adminSiteModel{}, Tenants: []string{},
		Complete: adminSiteStoreIsDurable(store)}
	seen := map[string]bool{}
	for _, tenant := range tenants {
		tenant = strings.TrimSpace(tenant)
		if tenant == "" || seen[strings.ToLower(tenant)] {
			continue
		}
		seen[strings.ToLower(tenant)] = true
		sites, err := store.List(ctx, tenant)
		if err != nil {
			// One organization's store failing must not publish a section that LOOKS complete without them —
			// that is precisely how a replace-all wipes what it could not read. Report incomplete instead, which
			// makes the Edge keep what it has. And do NOT name it below: an organization the publisher could
			// not read is one it has said nothing about.
			section.Complete = false
			continue
		}
		section.Tenants = append(section.Tenants, tenant)
		section.Sites = append(section.Sites, sites...)
	}
	return section
}

// applySiteBundleSection makes the Edge's Site catalog match the control plane's.
//
// REPLACE, not upsert. Upserting would carry creations and never deletions, which is the half of the defect
// that is hardest to see: an operator deletes a Site in the Console, watches it disappear, and the Edge that
// actually admits connectors keeps honouring its bootstrap secret. A Site removed on the authority has to stop
// existing on the nodes that enforce it.
//
// ★★ PRESENT-BUT-EMPTY CLEARS, which reverses the rule most sections here follow — and it does so for exactly
// the reason the authored-rules section beside it records, measured the same way (2026-08-23).
//
// Keeping local on an empty section costs the property this whole file exists for: DELETE stops propagating as
// soon as it is the LAST Site. Measured — fleet-probe was deleted on the control plane, the CP went to zero
// Sites, and the Edge kept it, with its own /admin/sites now the only way to remove it.
//
// And empty is NOT the dangerous direction here, unlike an empty enrolled inventory (an admission lockout) or
// empty policies (deny-all). An empty Site catalogue stops NEW connectors enrolling; connectors already
// registered hold their own runtime secret and keep working. That is refusing growth, which is the safe
// direction — the same reasoning the enrolment seat gate rests on.
//
// The AMBIGUITY that makes "empty" frightening elsewhere is resolved by two things the section carries. The
// POINTER: a node that holds no Site store publishes no section at all (nil, handled above), so present means
// "I am the authority for Sites". And COMPLETE: a publisher whose own store is volatile, or that could not
// read one of its organizations, says so — and then the Edge keeps what it has, because "I could not look"
// must never be read as "there are none".
func applySiteBundleSection(ctx context.Context, store adminSiteStore, section *siteCatalogBundle,
	now time.Time, logf func(string, ...interface{})) (applied int, removed int) {
	if store == nil || section == nil {
		return 0, 0
	}
	if !section.Complete {
		if logf != nil {
			logf("config_bundle_sites_kept_local reason=%q", "the control plane did not report a complete Site catalog")
		}
		return 0, 0
	}
	wanted := map[string]adminSiteModel{}
	tenants := map[string]bool{}
	// The organizations this catalogue speaks for — including any it says has NO Sites, which is the whole
	// point of carrying them separately.
	for _, tenant := range section.Tenants {
		if t := strings.ToLower(strings.TrimSpace(tenant)); t != "" {
			tenants[t] = true
		}
	}
	for _, site := range section.Sites {
		tenant := strings.ToLower(strings.TrimSpace(site.TenantID))
		id := strings.TrimSpace(site.SiteID)
		if tenant == "" || id == "" {
			continue
		}
		wanted[tenant+"\x00"+id] = site
		// Belt and braces: an entry for an organization the publisher forgot to name is still reconciled, so a
		// mismatch between the two lists can never leave a Site half-applied.
		tenants[tenant] = true
	}
	// Removals first, and only within the organizations the section actually spoke about. A control plane that
	// published two organizations must not be read as having said "and the third has none".
	for tenant := range tenants {
		local, err := store.List(ctx, tenant)
		if err != nil {
			continue
		}
		for _, site := range local {
			key := strings.ToLower(strings.TrimSpace(site.TenantID)) + "\x00" + strings.TrimSpace(site.SiteID)
			if _, keep := wanted[key]; keep {
				continue
			}
			if err := store.Delete(ctx, site.TenantID, site.SiteID); err != nil {
				if logf != nil {
					logf("config_bundle_site_remove_failed tenant=%q site=%q err=%v", site.TenantID, site.SiteID, err)
				}
				continue
			}
			// ★ EVERY REMOVAL BY NAME, never only a count. The first asset reconciliation in this tree deleted
			// 47 operator assets from an Edge holding things the control plane had never received, and nothing
			// in the code can tell "never migrated" from "deliberately removed". What it can do is refuse to be
			// quiet about it — a count says a number, a name says which Site stopped admitting connectors.
			if logf != nil {
				logf("config_bundle_site_removed tenant=%q site=%q reason=%q", site.TenantID, site.SiteID,
					"the control plane's catalog does not contain it")
			}
			removed++
		}
	}
	for _, site := range wanted {
		if _, err := store.Upsert(ctx, site, now); err != nil {
			if logf != nil {
				logf("config_bundle_site_apply_failed tenant=%q site=%q err=%v", site.TenantID, site.SiteID, err)
			}
			continue
		}
		applied++
	}
	if logf != nil && (applied > 0 || removed > 0) {
		logf("config_bundle_sites_applied applied=%d removed=%d", applied, removed)
	}
	return applied, removed
}

// adminSiteStoreIsDurable reports whether this store survives a restart. An in-memory one is empty after a
// restart for a reason that is not "there are none", and a replace-all built from it would erase the fleet's
// Sites — so the publisher says so and the Edges keep what they hold.
func adminSiteStoreIsDurable(store adminSiteStore) bool {
	switch s := store.(type) {
	case nil:
		return false
	case *adminSiteFileStore:
		return strings.TrimSpace(s.path) != ""
	default:
		// A Postgres-backed store, or any other backend: durable by construction. Named in the default rather
		// than by assertion so a new backend is durable unless it says otherwise — the opposite default would
		// silently publish incomplete for a backend nobody remembered to list.
		return true
	}
}

package main

import (
	"fmt"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// config_bundle_grants.go — carrying the deployment's federated-auth grants back down to every Edge.
//
// The other half of grant_cp_report.go. A grant minted at one Edge is told to the control plane; this brings
// the authority's whole set to every node, so a flow held on a node that did not run the ceremony is released
// by a grant it can see, and a revocation authored on the authority reaches the nodes that would otherwise go
// on honouring it.
//
// ★★ APPLIED AS A UNION, NOT A REPLACEMENT. Revocation MARKS a grant rather than deleting it, so "the bundle
// does not carry this one" never means "withdrawn" — it means the authority has not heard yet, which is
// exactly the state of a grant minted here a moment ago. Replacing would delete the grant the ceremony just
// earned, before the report carrying it had been answered.
type grantBundle struct {
	// Grants is every organization's. An Edge carries every organization's flows.
	Grants []grantstore.Grant `json:"grants"`
	// Complete says the control plane could read its whole store. It is carried for the same reason as the
	// other sections, though a union already ignores an absence.
	Complete bool `json:"complete"`
}

// grantBundleSection builds what the control plane publishes, or nil when this node holds no store.
func grantBundleSection(store *grantstore.Store) *grantBundle {
	if store == nil {
		return nil
	}
	rows, err := store.ListAllChecked()
	return &grantBundle{Grants: rows, Complete: err == nil}
}

// applyGrantBundleSection validates and persists the authority's set. A failure
// keeps the generation eligible for retry; locally applied denials remain in force.
func applyGrantBundleSection(store *grantstore.Store, section *grantBundle, now time.Time) (added, updated int, err error) {
	if section == nil {
		return 0, 0, nil
	}
	if store == nil || !section.Complete {
		return 0, 0, fmt.Errorf("access grant bundle is unavailable or incomplete")
	}
	return store.MergeChecked(section.Grants, now)
}

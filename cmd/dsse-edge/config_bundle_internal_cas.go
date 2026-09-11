package main

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/internalca"
)

// config_bundle_internal_cas.go — carrying, from the control plane to the Edges, the certificate authorities
// each organization vouches for over ITS OWN private assets.
//
// ★★★ THIS OBJECT WENT THROUGH TWO CHANNELS THAT DO NOT EXIST ON THIS DEPLOYMENT BEFORE ARRIVING HERE
// (2026-09-01, all three attempts measured against the same running fleet).
//
//  1. A direct database read on the Edge. The enforcing Edges are deliberately zero-DB — the control plane is
//     the configuration authority — so there was nothing to read and nothing said so.
//  2. A bespoke control-plane pull, modelled on the steer-exclusion lane. That lane is configured only where
//     an Edge has no database, and on this deployment it is not configured at all: the goroutine started, and
//     in six minutes of logs there was not one line from it, because the source URL was empty.
//
// Both compiled, both passed their tests, and both were invisible in exactly the way this deployment's worst
// defects are invisible: the feature was present in the code, named in the Console, and reached no Edge.
//
// The channel every authored object on this deployment actually travels is the SIGNED CONFIG BUNDLE, pulled
// every ten seconds and signature-verified. That is where this belongs, and it inherits the signing for free.
//
// ★★ AN EMPTY SECTION MEANS "NONE", AND HERE THAT IS SAFE — unlike the device-CA registry two files over,
// where empty would refuse every device of every organization. Empty here means private assets stop being
// reachable, which is the correct reading of an administrator having deleted the last authority, and it is
// how a deletion reaches the fleet at all. It is still gated on Complete: a control plane that could not read
// its own store says so, and the Edge keeps what it has.
type internalCABundle struct {
	// Authorities is every organization's list. An Edge carries every organization's flows, so the section is
	// fleet-wide rather than scoped to the puller's own organization — the mistake this deployment made eight
	// times in one day was answering a question about somebody else with an attribute of this node.
	Authorities []internalca.Authority `json:"authorities"`
	// Complete says the control plane could read its whole store. False must never be read as "there are none".
	Complete bool `json:"complete"`
}

// internalCABundleSection builds what the control plane publishes, or nil when this node holds no store and is
// therefore not the authority for this object.
func internalCABundleSection(store organizationInternalCAPool) *internalCABundle {
	concrete, ok := store.(*internalca.Store)
	if !ok || concrete == nil {
		return nil
	}
	return &internalCABundle{Authorities: concrete.ListAll(time.Now().UTC()), Complete: true}
}

// applyInternalCABundleSection makes this Edge's list match the control plane's. Returns how many authorities
// this Edge now vouches for, and whether it changed anything.
func applyInternalCABundleSection(store organizationInternalCAPool, section *internalCABundle, logf func(string, ...interface{})) (count int, applied bool) {
	concrete, ok := store.(*internalca.Store)
	if !ok || concrete == nil || section == nil {
		return 0, false
	}
	if !section.Complete {
		if logf != nil {
			logf("config_bundle_internal_cas_kept_local reason=%q",
				"the control plane did not report a complete list of internal certificate authorities")
		}
		return 0, false
	}
	kept := []internalca.Authority{}
	for _, a := range section.Authorities {
		if strings.TrimSpace(a.TenantID) == "" || strings.TrimSpace(a.CertificatePEM) == "" {
			continue
		}
		kept = append(kept, a)
	}
	concrete.ReplaceAll(kept)
	return len(kept), true
}

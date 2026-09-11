package main

import (
	"crypto/ecdsa"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/vendorlicense"
)

// config_bundle_licence.go — carrying the vendor licence from the authority to the Edges.
//
// ★★★ WITHOUT THIS, WIRING THE PAID LANE STOPPED THE DEPLOYMENT (measured 2026-08-27, walking it for the first
// time). Handing an Edge a vendor key turns licensing ON — requireLicence is len(acceptedKeys) > 0 — and the
// licence itself is applied through POST /admin/license, which lands on the control plane. Nothing carried it
// any further. So an operator who configured the lane exactly as the flags describe got:
//
//	enroll_refused reason="no valid licence is installed; enrolment is held until one is applied"
//	HTTP 403 — every enrolment in the deployment, on a deployment that HAD a valid licence
//
// The Edge's refusal was correct in isolation: an Edge told to enforce licensing and given nothing to enforce
// must not fall open. It was the delivery that did not exist.
//
// ★★ THE LICENCE IS CONFIGURATION, so it travels the way configuration travels — authored on the control
// plane, carried in the bundle, applied by every Edge. The alternative considered and rejected was a shared
// store: the enforcement Edges would need the authority's database, which is the exact arrangement
// config_bundle_inspection_posture.go was written to undo, and it fails the same way (one node configured, one
// not, no fleet agreement and nothing saying so).
//
// ★ THE ENVELOPE TRAVELS, NEVER A VERDICT. Each Edge verifies the vendor's signature with its OWN accepted
// keys, against its OWN accepted-serial high-water mark, and refuses on its own terms. A control plane that
// could say "this is licensed for 10,000" without a vendor signature in the path would be issuing entitlement.

// licenceBundle carries the signed licence file itself.
type licenceBundle struct {
	// Envelope is the vendor's file, byte for byte as it was applied. Not a payload, not a seat count.
	Envelope vendorlicense.Envelope `json:"envelope"`
}

// licenceBundleSection builds the section the control plane publishes, or nil when this node holds no licence.
//
// ★ NIL IS NOT "UNLICENSED", it is "I am not the authority for this". An older control plane, or one that has
// never been given a licence, publishes nothing and leaves each Edge with whatever it already holds — which
// for the ordinary unlicensed deployment is nothing, and for a fleet mid-upgrade is the licence it was working
// with a minute ago. Publishing an empty section instead would mean a control plane restart could disarm a
// fleet's licensing for as long as it took an operator to re-apply the file.
func licenceBundleSection(store *licenseStore) *licenceBundle {
	if store == nil {
		return nil
	}
	env, ok := store.Envelope()
	if !ok {
		return nil
	}
	return &licenceBundle{Envelope: env}
}

// applyLicenceBundleSection makes the control plane's licence this node's, verifying it here.
//
// Returns whether anything changed, so the caller logs a change rather than a poll.
func applyLicenceBundleSection(section *licenceBundle, store *licenseStore, gate *enrolmentLicensing,
	accepted []*ecdsa.PublicKey, expectedMSSPID, now string, logf func(string, ...interface{})) (changed bool) {
	if section == nil || store == nil {
		return false
	}
	env := section.Envelope
	if strings.TrimSpace(env.PayloadB64) == "" {
		return false
	}
	// Already holding exactly this file. Re-applying would be REFUSED — the serial is no longer above the
	// high-water mark it set itself — and an Edge would log a verification failure on every poll while being
	// correctly licensed.
	if store.HoldsPayloadSHA(env.PayloadSHA256) {
		return false
	}
	// ★ THIS NODE'S OWN KEYS AND ITS OWN ADDRESSEE. An Edge that accepts a different set of vendor keys from
	// the control plane must refuse, loudly, rather than inherit the authority's opinion: that difference is
	// either a withdrawn key that has not reached every node, or a node being handed somebody else's licence.
	p, err := store.Apply(env, accepted, expectedMSSPID, "carried in the config bundle", now)
	if err != nil {
		if logf != nil {
			logf("config_bundle_licence_refused err=%v — this node did not accept the licence the control "+
				"plane is publishing. Enrolment stays held here while other nodes may be admitting devices; "+
				"check that every node has the same -license-vendor-keys and -license-mssp-id", err)
		}
		return false
	}
	if gate != nil {
		gate.Apply(p)
	}
	if logf != nil {
		logf("config_bundle_licence_applied serial=%d mssp=%q seats_now=%d enrolment_stops=%q evaluation=%v",
			p.Serial, p.MSSPID, p.SeatsAt(time.Now().UTC()), p.EnrolmentStopsAt, p.IsEvaluation)
	}
	return true
}

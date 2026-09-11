package main

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// device_authority_rotation_readiness.go — who has not moved yet, before the destructive half is allowed.
//
// ★★★ WHY THIS EXISTS (2026-08-22). The device-identity authority — the one that signs every device's client
// certificate — had no rotation and no retirement at all. A compromised key had no supported replacement.
//
// Adding the rotation is the easy half. The dangerous half is RETIRING the outgoing authority, and it is
// dangerous in a way the transport rotation is not: the moment the fleet stops registering the old anchor,
// every device still presenting a certificate from it is refused AT THE HANDSHAKE. A laptop that was switched
// off for the whole rotation is exactly the one that will be refused when it comes back, and there is no
// fail-open — admitting an unknown authority is the thing device identity exists to prevent.
//
// ★ AND THE EVIDENCE WAS ALREADY BEING COLLECTED. deviceCertificateFact.AnchorSHA256 records the CA a device's
// chain ACTUALLY ENDED AT, taken from the verified chain of a real handshake — not a self-report, not the
// issuer's name. The comment on that field already explains why the name would not do: two authorities can
// share a common name, and this deployment has that. So the readiness question is answerable from what devices
// have actually presented, without inventing a field for them to report and waiting for two agents to ship it.
//
// ★ SILENCE IS NOT READINESS. A device that has never presented a certificate this process has seen is
// reported as unknown and counted, never folded into "everybody has moved". The whole failure mode here is the
// machine nobody was looking at.

// deviceAuthorityRotationReadiness answers, for one organization mid-rotation, which of its devices are on the
// incoming authority and which are not.
type deviceAuthorityRotationReadiness struct {
	TenantID string `json:"tenant_id"`
	// Rotating is false when this organization has no rotation in flight, in which case there is nothing to
	// be ready for and every list below is empty.
	Rotating        bool     `json:"rotating"`
	IncomingSHA256  string   `json:"incoming_sha256,omitempty"`
	OutgoingSHA256  string   `json:"outgoing_sha256,omitempty"`
	Moved           []string `json:"moved"`
	StillOnOutgoing []string `json:"still_on_outgoing"`
	// OnAnotherOfTheirOwn are devices holding a certificate from a DIFFERENT authority this same organization
	// has registered — not the one being retired, so the retirement does not touch them.
	//
	// ★★★ THE FIRST VERSION OF THIS BLOCKED ON THEM, AND WOULD HAVE BLOCKED FOR EVER (2026-08-22, caught by
	// running it against the real lab instead of a clean room). tenant_reference_lab has TWO device CAs: one
	// it registered itself through /admin/tenant-cas, which all three of its live devices present, and the
	// managed authority this control plane holds. Those coexist by design — a customer may bring its own CA
	// and still use the managed one for new machines. Counting the first group as "on something unknown" made
	// retiring the SECOND impossible while one device remained on the first, which is not a safety property,
	// just a gate that never opens.
	//
	// They are still NAMED, because a denominator that quietly shrinks is a gate that has stopped measuring.
	OnAnotherOfTheirOwn []string `json:"on_another_of_their_own"`
	// OnSomethingElse is an authority this deployment cannot place at all. That DOES hold the retirement: it
	// is a question to answer, not a rounding error.
	OnSomethingElse   []string `json:"on_something_else"`
	NeverSeen         []string `json:"never_seen"`
	MayRetirePrevious bool     `json:"may_retire_previous"`
	Note              string   `json:"note"`
}

// measureDeviceAuthorityRotation compares what each enrolled device last PRESENTED against the two authorities
// this organization is between.
//
// enrolled is every identity that belongs to this organization — the denominator. presented maps an identity
// to the anchor fingerprint its last verified handshake ended at; an identity absent from it has never been
// seen by this process and is counted as such rather than dropped.
//
// othersOfTheirOwn is every OTHER anchor fingerprint registered to this organization — the CAs it brought
// itself. A device on one of those is unaffected by this retirement and must not hold it up.
func measureDeviceAuthorityRotation(tenantID, outgoingSHA256, incomingSHA256 string, enrolled []string,
	presented map[string]string, othersOfTheirOwn map[string]bool) deviceAuthorityRotationReadiness {
	out := deviceAuthorityRotationReadiness{
		TenantID: strings.TrimSpace(tenantID), Moved: []string{}, StillOnOutgoing: []string{},
		OnAnotherOfTheirOwn: []string{}, OnSomethingElse: []string{}, NeverSeen: []string{},
	}
	incoming := strings.ToLower(strings.TrimSpace(incomingSHA256))
	outgoing := strings.ToLower(strings.TrimSpace(outgoingSHA256))
	if incoming == "" {
		out.Note = "this organization is not moving to a new device-identity authority, so there is nothing to " +
			"be ready for"
		return out
	}
	out.Rotating = true
	out.IncomingSHA256, out.OutgoingSHA256 = incoming, outgoing
	for _, id := range enrolled {
		identity := strings.TrimSpace(id)
		if identity == "" {
			continue
		}
		seen, ok := presented[strings.ToLower(identity)]
		seen = strings.ToLower(strings.TrimSpace(seen))
		switch {
		case !ok || seen == "":
			out.NeverSeen = append(out.NeverSeen, identity)
		case seen == incoming:
			out.Moved = append(out.Moved, identity)
		case seen == outgoing:
			out.StillOnOutgoing = append(out.StillOnOutgoing, identity)
		case othersOfTheirOwn[seen]:
			out.OnAnotherOfTheirOwn = append(out.OnAnotherOfTheirOwn, identity)
		default:
			out.OnSomethingElse = append(out.OnSomethingElse, identity)
		}
	}
	for _, l := range [][]string{out.Moved, out.StillOnOutgoing, out.OnAnotherOfTheirOwn, out.OnSomethingElse,
		out.NeverSeen} {
		sort.Strings(l)
	}
	// ★ EVERY LIST BUT Moved IS A NO, INCLUDING THE ONES THAT LOOK LIKE BOOKKEEPING. "Never seen" is the
	// switched-off laptop this whole shape exists for, and "on something else" is a device presenting an
	// authority neither of these — which is a question to answer before removing anything, not a rounding error.
	// ★ ONLY THE DEVICES THIS RETIREMENT WOULD ACTUALLY REFUSE HOLD IT UP — plus the two kinds of not-knowing,
	// which are both a no. A device on another of this organization's own authorities is not touched by it.
	accountedFor := len(out.Moved) + len(out.OnAnotherOfTheirOwn)
	// ★★★ "NOBODY HAS BEEN SEEN" AND "THERE IS NOBODY" ARE DIFFERENT ZEROES (2026-08-22 — the fourth gate in
	// this product to conflate them, after the transport-name retirement, the authority promotion and the
	// interception promotion).
	//
	// The rule wants a positive witness: at least one device presenting something. Right when devices exist,
	// because silence is the switched-off laptop this gate protects — retiring early refuses it at the
	// handshake, and it is the one nobody was watching. A dead end when the organization has none: the
	// witness cannot exist and the act cannot refuse anybody. Measured on tenant_acme, which has no devices
	// and could not finish a replacement it had started.
	nobodyToRefuse := len(enrolled) == 0
	out.MayRetirePrevious = (nobodyToRefuse || accountedFor > 0) && len(out.StillOnOutgoing) == 0 &&
		len(out.OnSomethingElse) == 0 && len(out.NeverSeen) == 0
	switch {
	case out.MayRetirePrevious && nobodyToRefuse:
		// Its own sentence: "there is nobody to refuse" is a different claim from "everybody moved", and an
		// operator reading a screen must not be handed the second when the first is true.
		out.Note = "this organization has no device, so retiring the previous authority refuses nobody. This " +
			"is not evidence that anything moved — it is that there is nothing to move"
	case out.MayRetirePrevious && len(out.OnAnotherOfTheirOwn) > 0:
		out.Note = fmt.Sprintf("%d device(s) moved to the incoming authority and %d hold a certificate from "+
			"another authority this organization registered itself, which this retirement does not touch. "+
			"Nothing is left on the outgoing authority, so it can be retired",
			len(out.Moved), len(out.OnAnotherOfTheirOwn))
	case out.MayRetirePrevious:
		out.Note = fmt.Sprintf("every one of this organization's %d device(s) has presented a certificate from "+
			"the incoming authority, so the previous one can be retired", len(out.Moved))
	case len(out.Moved) == 0 && len(out.NeverSeen) == len(enrolled):
		out.Note = "no device has been seen since the rotation began. That is not readiness — it is the " +
			"absence of evidence, and retiring now would refuse every one of them at the handshake"
	default:
		out.Note = fmt.Sprintf("%d moved, %d still on the outgoing authority, %d on another authority this "+
			"organization registered itself (unaffected), %d on an authority this deployment cannot place, "+
			"%d not seen at all. Retiring now would refuse everything still on the outgoing authority, and "+
			"the last two groups are questions rather than evidence",
			len(out.Moved), len(out.StillOnOutgoing), len(out.OnAnotherOfTheirOwn),
			len(out.OnSomethingElse), len(out.NeverSeen))
	}
	return out
}

// registerDeviceAuthorityRotationRoute exposes the measurement on the EDGE, because only an Edge has seen a
// handshake. The control plane holds the two acts; this is the evidence an operator reads between them.
func registerDeviceAuthorityRotationRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig) {
	mux.HandleFunc("GET /admin/device-authority-rotation", adminEndpoint("admin.endpoints.read",
		func(w http.ResponseWriter, r *http.Request) {
			tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
			prints, known := tenantDeviceIdentity.Rotation(tenant)
			if !known {
				writeJSON(w, http.StatusOK, deviceAuthorityRotationReadiness{
					TenantID: tenant, Moved: []string{}, StillOnOutgoing: []string{},
					OnSomethingElse: []string{}, NeverSeen: []string{},
					Note: "this node holds no device-identity authority for your organization, so it enrols " +
						"none of your devices and has nothing to say about a rotation",
				})
				return
			}
			// ★ THE DENOMINATOR IS THE ENROLLED LEDGER, NOT THE DEVICES THAT HAPPENED TO REPORT. A rotation is
			// finished when every device this organization HAS has moved, and a list built from whoever showed
			// up would shrink to the ones that are easy to satisfy.
			enrolled := []string{}
			if config.EnrolledLedger != nil {
				for _, e := range config.EnrolledLedger.List() {
					if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, e.Identity, tenant); placeable && belongs {
						enrolled = append(enrolled, e.Identity)
					}
				}
			}
			presented := map[string]string{}
			for _, f := range deviceCertificates.snapshot() {
				if fp := strings.TrimSpace(f.AnchorSHA256); fp != "" {
					presented[strings.ToLower(strings.TrimSpace(f.Identity))] = fp
				}
			}
			// ★ THE OTHER AUTHORITIES THIS ORGANIZATION BROUGHT ITSELF. A customer may register its own device
			// CA through /admin/tenant-cas and still use the managed one for new machines — tenant_reference_lab
			// does exactly that. A device on one of those is untouched by this retirement, so it must not hold
			// it up; see the note on OnAnotherOfTheirOwn.
			others := map[string]bool{}
			if config.TenantCARegistry != nil {
				for _, anchor := range config.TenantCARegistry.Anchors() {
					owner, resolved := chainsToTenant([][]*x509.Certificate{{anchor}}, config.TenantCARegistry)
					if !resolved || !strings.EqualFold(strings.TrimSpace(owner), tenant) {
						continue
					}
					fp := strings.ToLower(certFingerprint(anchor))
					if fp != "" && fp != strings.ToLower(prints.SignerSHA256) &&
						fp != strings.ToLower(prints.OutgoingSHA256) {
						others[fp] = true
					}
				}
			}
			writeJSON(w, http.StatusOK, measureDeviceAuthorityRotation(tenant, prints.OutgoingSHA256,
				signerWhenRotating(prints), enrolled, presented, others))
		}))
}

// signerWhenRotating is the incoming authority's fingerprint, or empty when nothing is in flight. The signer
// is only "incoming" while there is something it is incoming FROM — reporting a rotation with no outgoing
// authority would make an ordinary deployment look mid-migration for ever.
func signerWhenRotating(p deviceAuthorityFingerprints) string {
	if strings.TrimSpace(p.OutgoingSHA256) == "" {
		return ""
	}
	return p.SignerSHA256
}

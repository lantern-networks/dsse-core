package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// interception_authority_rotation_readiness.go — may the staged interception authority be promoted yet?
//
// ★★★ WHY (2026-08-22). Handing over a replacement interception authority used to switch every Edge to
// signing under the new root on its next material fetch. Every device that had not yet added that root lost
// every HTTPS site, at once — the eighteen minutes of 2026-08-19, with both sides reporting healthy the whole
// time. Staging fixed the switch; this is what says when the switch is safe.
//
// ★ THIS IS THE TRANSPORT SHAPE, NOT THE DEVICE-IDENTITY ONE. The two rotations built this week run opposite
// ways and it decides which half is dangerous:
//
//	device identity   the DEVICE presents, the Edge verifies   → retiring early refuses devices
//	interception      the EDGE presents, the device verifies   → PROMOTING early breaks every device
//
// So the gate is on the promotion, and the evidence is what devices report HOLDING, not what they were sent.
// pinned_interception_root_sha256 is that report, and the lab's two real devices populate it.
//
// ★ AND A DEVICE THAT HAS SAID NOTHING IS NOT READY. It is the machine that was switched off during the
// rotation, and promoting takes every site away from it the moment it comes back — the failure this whole
// shape exists to prevent, and the one nobody is watching.

type interceptionAuthorityRotationReadiness struct {
	TenantID string `json:"tenant_id"`
	// Rotating is false when nothing is staged, in which case there is nothing to be ready for.
	Rotating       bool   `json:"rotating"`
	IncomingSHA256 string `json:"incoming_sha256,omitempty"`
	CurrentSHA256  string `json:"current_sha256,omitempty"`
	// Holds are devices that report holding the incoming root — the only group that counts as ready.
	Holds []string `json:"holds"`
	// DoesNotHold reported their roots and the incoming one was not among them.
	DoesNotHold []string `json:"does_not_hold"`
	// NeverReported have said nothing about their roots at all. Counted against the promotion, never folded in.
	NeverReported []string `json:"never_reported"`
	// NotAgents are enrolled identities with no interception trust store to hold a root in — a connector has
	// no browser. Named rather than dropped.
	NotAgents  []string `json:"not_agents,omitempty"`
	MayPromote bool     `json:"may_promote"`
	Note       string   `json:"note"`
}

// measureInterceptionAuthorityRotation compares what each of an organization's devices reports HOLDING against
// the root it is being asked to adopt.
//
// enrolled is the denominator — every device that belongs to this organization. held maps an identity to the
// root fingerprints it reported; an identity absent from it has reported nothing.
func measureInterceptionAuthorityRotation(tenantID, currentSHA256, incomingSHA256 string, enrolled []string,
	held map[string][]string) interceptionAuthorityRotationReadiness {
	return measureInterceptionAuthorityRotationExcluding(tenantID, currentSHA256, incomingSHA256, enrolled, held, nil)
}

// measureInterceptionAuthorityRotationExcluding takes the identities that hold no interception trust store at
// all — see NotAgents. They are removed from the denominator and NAMED in the answer.
func measureInterceptionAuthorityRotationExcluding(tenantID, currentSHA256, incomingSHA256 string,
	enrolled []string, held map[string][]string,
	notAgents map[string]bool) interceptionAuthorityRotationReadiness {
	// ★★★ AN IDENTITY WITH NO TRUST STORE HELD THE PROMOTION SHUT (2026-08-22, measured — both devices held
	// the incoming root and conn_lab_001 did not, because a connector has no browser and no interception
	// trust store to hold one in). Third gate in one day with the same shape.
	//
	// ★ EVIDENCE-BASED AND SELF-CANCELLING, exactly like the transport-name gate. Excluded only while it is
	// not an endpoint AND has reported NO interception root at all. The day something reports one, it is
	// counted like anything else, with no code change and nobody having to remember.
	//
	// ★ AND NAMED, NOT SUBTRACTED. A denominator that shrinks without saying so is a gate that has stopped
	// measuring.
	kept := make([]string, 0, len(enrolled))
	excluded := []string{}
	for _, id := range enrolled {
		key := strings.ToLower(strings.TrimSpace(id))
		if notAgents[key] && len(held[key]) == 0 {
			excluded = append(excluded, id)
			continue
		}
		kept = append(kept, id)
	}
	sort.Strings(excluded)
	enrolled = kept
	out := interceptionAuthorityRotationReadiness{
		TenantID: strings.TrimSpace(tenantID), Holds: []string{}, DoesNotHold: []string{},
		NeverReported: []string{}, NotAgents: excluded,
	}
	incoming := strings.ToLower(strings.TrimSpace(incomingSHA256))
	if incoming == "" {
		out.Note = "this organization is not moving to a new interception authority, so there is nothing to " +
			"be ready for"
		return out
	}
	out.Rotating = true
	out.IncomingSHA256 = incoming
	out.CurrentSHA256 = strings.ToLower(strings.TrimSpace(currentSHA256))
	for _, id := range enrolled {
		identity := strings.TrimSpace(id)
		if identity == "" {
			continue
		}
		roots, reported := held[strings.ToLower(identity)]
		if !reported || len(roots) == 0 {
			out.NeverReported = append(out.NeverReported, identity)
			continue
		}
		found := false
		for _, r := range roots {
			if strings.EqualFold(strings.TrimSpace(r), incoming) {
				found = true
				break
			}
		}
		if found {
			out.Holds = append(out.Holds, identity)
			continue
		}
		out.DoesNotHold = append(out.DoesNotHold, identity)
	}
	for _, l := range [][]string{out.Holds, out.DoesNotHold, out.NeverReported} {
		sort.Strings(l)
	}
	out.MayPromote = len(out.Holds) > 0 && len(out.DoesNotHold) == 0 && len(out.NeverReported) == 0
	switch {
	case out.MayPromote:
		out.Note = fmt.Sprintf("every one of this organization's %d device(s) reports holding the incoming "+
			"root, so it can be promoted", len(out.Holds))
	case len(out.Holds) == 0 && len(out.NeverReported) == len(enrolled):
		out.Note = "no device has reported which roots it holds. That is not readiness — it is the absence of " +
			"evidence, and promoting now would take every HTTPS site away from all of them"
	default:
		out.Note = fmt.Sprintf("%d hold the incoming root, %d do not, %d have not said. Promoting now would "+
			"take every HTTPS site away from everything outside the first group, the moment this fleet starts "+
			"signing under it", len(out.Holds), len(out.DoesNotHold), len(out.NeverReported))
	}
	return out
}

// registerInterceptionAuthorityRotationRoute exposes the measurement on the EDGE, because only an Edge
// collects what a device reports holding. The control plane holds the promotion.
func registerInterceptionAuthorityRotationRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig) {
	mux.HandleFunc("GET /admin/interception-authority-rotation", adminEndpoint("admin.endpoints.read",
		func(w http.ResponseWriter, r *http.Request) {
			tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
			current, incoming := "", ""
			if config.NetworkExtensionLabTLS != nil {
				current, incoming = config.NetworkExtensionLabTLS.TenantRootFingerprints(tenant)
			}
			// ★ THE DENOMINATOR IS THE ENROLLED LEDGER. A list built from whoever happened to report would
			// shrink to the devices that are easy to satisfy, and the one that matters here is the one that
			// has not been heard from.
			enrolled := []string{}
			if config.EnrolledLedger != nil {
				for _, e := range config.EnrolledLedger.List() {
					if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, e.Identity, tenant); placeable && belongs {
						enrolled = append(enrolled, e.Identity)
					}
				}
			}
			held := map[string][]string{}
			if config.ObservedExclusions != nil {
				for _, e := range config.ObservedExclusions.Query(tenant, observedQueryFilter{}).Entries {
					if len(e.PinnedInterceptionRootSHA256) > 0 {
						held[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = e.PinnedInterceptionRootSHA256
					}
				}
			}
			// What an identity IS comes from the shared enrolled ledger, so two Edges cannot disagree.
			notAgents := map[string]bool{}
			if config.EnrolledLedger != nil {
				for _, e := range config.EnrolledLedger.List() {
					if !e.IsEndpoint() {
						notAgents[strings.ToLower(strings.TrimSpace(e.Identity))] = true
					}
				}
			}
			writeJSON(w, http.StatusOK, measureInterceptionAuthorityRotationExcluding(tenant, current, incoming,
				enrolled, held, notAgents))
		}))
}

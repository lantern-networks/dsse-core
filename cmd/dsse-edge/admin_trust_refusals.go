package main

import (
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"sort"
	"strings"
	"time"
)

// What devices declined to trust, as one list. GET /admin/pki/trust-refusals.
//
// This is the answer to the question the 2026-07-31 outage could not ask: a fleet that has refused a
// certificate and a fleet that is switched off produce the same silence at the Edge, and the difference
// existed only in each device's own log. Devices journal their refusals and carry them on the first
// connection that works, so this arrives late by construction — that is the only option a refusal has, and
// it is still the difference between "explainable in a minute" and "47 minutes".
//
// Reporter-declared throughout. A fingerprint here is compared with what this node serves, never believed:
// the certificate a device says it saw is evidence about that device, not about the Edge.

type adminTrustRefusal struct {
	DeviceIdentity string `json:"device_identity"`
	ServedSHA256   string `json:"served_sha256,omitempty"`
	// ServedIsCurrent says whether the refused certificate is the one this node presents NOW. False means the
	// refusal is about something already replaced, which is the ordinary case after a rollback — the operator
	// is reading why the thing they backed out of failed.
	// Pointer, so "this node cannot say" is null rather than false — see servedIsCurrent.
	ServedIsCurrent *bool  `json:"served_is_current"`
	Reason          string `json:"reason"`
	FirstAt         string `json:"first_at"`
	LastAt          string `json:"last_at"`
	Count           int    `json:"count"`
}

type adminTrustRefusalReport struct {
	SchemaVersion string              `json:"schema_version"`
	ServingSHA256 string              `json:"serving_sha256,omitempty"`
	Refusals      []adminTrustRefusal `json:"refusals"`
	// WithheldOtherOrganizations counts rows about machines that are not the caller's. Reported rather than
	// silently dropped: "no refusals" and "no refusals YOU can see" are different facts.
	WithheldOtherOrganizations int `json:"withheld_other_organizations,omitempty"`
}

// trustRefusals is the durable record. Nil until wired, which reads as "nothing reported" rather than a
// crash on a node that has not enabled it.
var trustRefusals *trustRefusalStore

// interceptionRefusals is the same store for a different question: what a device's own probe found wrong with
// the certificates INTERCEPTION served it, as opposed to the Edge's own certificate above.
//
// ★ SEPARATE, NOT MERGED. "the Edge's certificate was refused" and "the certificate interception served is
// refused" have different causes and different fixes; one list would make them indistinguishable, which is
// the confusion win-dev-1's device-side journal was built to end. Same durability, same merge-never-replace
// rule — a device clears its journal once this side accepts it, so an overwrite would destroy the evidence
// moments after receiving it.
var interceptionRefusals *trustRefusalStore

// servedIsCurrent answers whether the refused certificate is the one being served: true, false, or nil when
// this node does not know what it is serving. Never false on an unknown.
func servedIsCurrent(refused, serving string) *bool {
	if strings.TrimSpace(serving) == "" || strings.TrimSpace(refused) == "" {
		return nil
	}
	same := strings.EqualFold(strings.TrimSpace(refused), strings.TrimSpace(serving))
	return &same
}

func buildTrustRefusalsFromStore(byDevice map[string][]observedTrustRefusal, servingFingerprint string) adminTrustRefusalReport {
	entries := make([]observedExclusionEntry, 0, len(byDevice))
	for _, id := range sortedDeviceKeys(byDevice) {
		entries = append(entries, observedExclusionEntry{DeviceIdentity: id, TrustRefusals: byDevice[id]})
	}
	return buildTrustRefusals(entries, servingFingerprint)
}

func buildTrustRefusals(entries []observedExclusionEntry, servingFingerprint string) adminTrustRefusalReport {
	out := adminTrustRefusalReport{SchemaVersion: "admin_trust_refusals.v1",
		ServingSHA256: servingFingerprint, Refusals: []adminTrustRefusal{}}
	for _, e := range entries {
		for _, r := range e.TrustRefusals {
			out.Refusals = append(out.Refusals, adminTrustRefusal{
				DeviceIdentity: e.DeviceIdentity,
				ServedSHA256:   r.ServedSHA256,
				// ★★★ NULL WHEN THIS NODE CANNOT SAY, AND false ONLY WHEN IT KNOWS (2026-09-05, measured on a
				// live deployment). servingFingerprint comes from servedTransportLeaf(), a package global set
				// by one listener path; where that path did not run it is empty — and this expression turned
				// "we do not know what we are serving" into "the refused certificate is stale". The Console
				// hides a refusal on exactly that flag, so a device that was refusing the Edge's certificate
				// every few minutes, right then, appeared nowhere:
				//
				//	inventory   component_server:transport  265b7f2f…91b2
				//	refusal     served_sha256               265b7f2f…91b2   served_is_current: false
				//
				// The same fingerprint on both lines, and the screen said the refusal was about something the
				// deployment no longer serves. A trust refusal is how anyone learns that a certificate
				// replacement is breaking devices; suppressing it on an unknown is the worst available answer.
				ServedIsCurrent: servedIsCurrent(r.ServedSHA256, servingFingerprint),
				Reason:          r.Reason,
				FirstAt:         r.FirstAt.UTC().Format(time.RFC3339),
				LastAt:          r.LastAt.UTC().Format(time.RFC3339),
				Count:           r.Count,
			})
		}
	}
	// Most recent first: an operator reading this is asking what is happening now, not what happened first.
	sort.Slice(out.Refusals, func(i, j int) bool {
		if out.Refusals[i].LastAt != out.Refusals[j].LastAt {
			return out.Refusals[i].LastAt > out.Refusals[j].LastAt
		}
		return out.Refusals[i].DeviceIdentity < out.Refusals[j].DeviceIdentity
	})
	return out
}

func registerAdminTrustRefusals(mux *http.ServeMux, build func(tenant string) adminTrustRefusalReport,
	ledger *enrolledinventory.Ledger, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/pki/trust-refusals", adminEndpoint("admin.certs.read",
		func(w http.ResponseWriter, r *http.Request) {
			// The answer is about the organization the request names; an operator who has not entered one is
			// asking about the deployment and gets every tenant's.
			tenant, wholeDeployment := adminAnswerScope(r)
			if wholeDeployment {
				tenant = ""
			}
			report := build(tenant)
			// ★ These rows name DEVICES. The certificate they refuse is the deployment's, which is why the row
			// exists; whose machine refused it is that organization's. Measured as a customer administrator:
			// two machines belonging to another organization, by name.
			ids := make([]string, 0, len(report.Refusals))
			for _, ref := range report.Refusals {
				ids = append(ids, ref.DeviceIdentity)
			}
			allowed, withheld := deviceIdentitiesForCaller(ids, ledger, r)
			if withheld > 0 {
				mine := map[string]bool{}
				for _, id := range allowed {
					mine[id] = true
				}
				kept := make([]adminTrustRefusal, 0, len(allowed))
				for _, ref := range report.Refusals {
					if mine[ref.DeviceIdentity] {
						kept = append(kept, ref)
					}
				}
				report.Refusals = kept
				report.WithheldOtherOrganizations = withheld
			}
			writeJSON(w, http.StatusOK, report)
		}))
}

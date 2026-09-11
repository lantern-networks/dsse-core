package main

import (
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// recovery_name_readiness.go — the fold's fourth step: has every enrolled device been told where to recover?
//
// ★ THE PORT MAY ONLY CLOSE ON AN ANSWER, NOT ON THE ABSENCE OF A COMPLAINT. The dedicated recovery listener
// exists for devices whose certificate expired while they were switched off. Those devices are, by definition,
// the ones least likely to have reported anything recently — so silence here is "not yet", and it is counted
// and named rather than folded into the total.
//
// Shape and shelf life are the transport-CA readiness rules, deliberately: a claim about what a device holds
// NOW is worthless when it was made six months ago, and a gate that accepts a stale claim opens on a machine
// that has since been re-imaged.
type recoveryNameReadiness struct {
	Name string `json:"name"`
	// Contradicting are devices that report holding the name this Edge announces NOW while also reporting a
	// distribution older than the one that first carried it. Both cannot be true, and the pair is worth naming
	// rather than resolving: whichever field is stale, a gate reading the other is deciding on a fiction.
	// Measured on win-dev-1, 2026-08-19 — the current name and serial 35 of 54 — which is what holds roadmap
	// D's withdrawal shut.
	Contradicting []string `json:"contradicting,omitempty"`
	// The name/target was reported, but its introduction or the device's adopted
	// serial is unknown. This is missing evidence, not a contradictory report.
	SerialUnverified []string `json:"serial_unverified,omitempty"`
	// NotAgents are enrolled identities that cannot dial this path at all, named rather than dropped: a
	// denominator that shrinks without saying so is a gate that stops measuring.
	NotAgents             []string `json:"not_agents,omitempty"`
	Holds                 []string `json:"holds"`
	DoesNotHold           []string `json:"does_not_hold"`
	Silent                []string `json:"silent"`
	NeverReportedAnything []string `json:"never_reported_anything"`
	// DedicatedPortRetired records that the port this measurement was built to protect is already gone.
	//
	// ★ THE VERDICT SENTENCE OUTLIVED THE DECISION IT GUARDED (2026-08-20). The dedicated recovery listener
	// was closed on 2026-08-19 once every device had been measured onto the name, and the bundle stopped
	// announcing the endpoint with it. This line kept saying "the dedicated recovery port must stay open" —
	// which after a restart, when nobody has reported yet, is the FIRST thing an operator reads, and it names
	// a fallback that no longer exists. What is actually at stake is the opposite: a device that has not
	// adopted the name has NO way back if its certificate expires.
	DedicatedPortRetired bool `json:"dedicated_port_retired,omitempty"`
}

// MayCloseTheDedicatedPort is the whole decision, in one place: every enrolled device has said, recently, that
// it holds this name. Anything else — a device that reported another name, a device that said nothing, a
// deployment with no devices at all — is a no.
func (r recoveryNameReadiness) MayCloseTheDedicatedPort() bool {
	if strings.TrimSpace(r.Name) == "" {
		return false
	}
	if len(r.Holds) == 0 {
		return false
	}
	return len(r.DoesNotHold) == 0 && len(r.Silent) == 0 && len(r.Contradicting) == 0 && len(r.SerialUnverified) == 0
}

func (r recoveryNameReadiness) Line() string {
	if strings.TrimSpace(r.Name) == "" {
		return "recovery name readiness: no name is being announced, so no device can hold one"
	}
	out := "recovery name readiness for " + r.Name + ": holds " + namesOrNone(r.Holds) +
		" / does NOT hold " + namesOrNone(r.DoesNotHold) + " / silent " + namesOrNone(r.Silent)
	if len(r.Contradicting) > 0 {
		out += " — ★ CONTRADICTORY: " + strings.Join(r.Contradicting, ",") + " report this name AND an older " +
			"distribution than the one that first carried it; one of those two fields is stale and every gate " +
			"reading either is deciding on a fiction"
	}
	if len(r.SerialUnverified) > 0 {
		out += " / recovery distribution evidence unknown: " + namesOrNone(r.SerialUnverified)
	}
	if len(r.NotAgents) > 0 {
		out += " (not counted, service identities that never dial this path: " + strings.Join(r.NotAgents, ",") + ")"
	}
	if r.MayCloseTheDedicatedPort() {
		if r.DedicatedPortRetired {
			return out + " — every enrolled device holds it, and the dedicated recovery port is already retired"
		}
		return out + " — every enrolled device holds it, so the dedicated recovery port may close"
	}
	if r.DedicatedPortRetired {
		return out + " — ★ the dedicated recovery port is ALREADY RETIRED, so a device that is not on this " +
			"list has no way back if its certificate expires. Silence counts as not yet: right after a restart " +
			"nobody has reported, and a device that is switched off is the one this path exists for"
	}
	return out + " — the dedicated recovery port must stay open (silence counts as not yet, because a device " +
		"that is switched off is the one this path exists for)"
}

func namesOrNone(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ",")
}

// excludeIdentitiesThatNeverDialRecovery removes identities that cannot use this path at all, and NAMES them.
//
// ★ THE ONLY IDENTITIES REMOVED ARE THE ONES THE ENROLLED LEDGER SAYS ARE NOT MANAGED DEVICES (Entry.Kind).
// "It looked irrelevant" is how a denominator quietly shrinks until the gate measures nothing; the ledger is a
// machine-checkable fact that every Edge reads the same way, and the reason is specific: a service identity
// enrols with a token over its tunnel and never dials POST /enroll/renew, the only route this port serves.
// Counting them would hold the port open forever on components that would never use it — and NOT saying so
// would be the other mistake. An earlier version asked the per-Edge connector registry and two nodes then gave
// two answers, which is the same defect one level down.
func excludeIdentitiesThatNeverDialRecovery(known []string, connectorIDs map[string]bool) (kept, excluded []string) {
	kept, excluded = []string{}, []string{}
	for _, id := range known {
		if connectorIDs[strings.ToLower(strings.TrimSpace(id))] {
			excluded = append(excluded, id)
			continue
		}
		kept = append(kept, id)
	}
	sort.Strings(kept)
	sort.Strings(excluded)
	return kept, excluded
}

func measureRecoveryNameReadiness(entries []observedExclusionEntry, want string, knownDevices []string,
	now time.Time) recoveryNameReadiness {
	return measureRecoveryNameReadinessSince(entries, want, knownDevices, now, 0)
}

// measureRecoveryNameReadinessSince takes the serial at which this name was FIRST announced, so a device that
// reports the name while reporting an older distribution can be named as contradicting itself.
func measureRecoveryNameReadinessSince(entries []observedExclusionEntry, want string, knownDevices []string,
	now time.Time, firstSerial int64) recoveryNameReadiness {
	name := strings.ToLower(strings.TrimSpace(want))
	out := recoveryNameReadiness{Name: name, Holds: []string{}, DoesNotHold: []string{}, Silent: []string{},
		NeverReportedAnything: []string{}}
	if name == "" {
		return out
	}
	reported := map[string]observedExclusionEntry{}
	for _, e := range entries {
		reported[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = e
	}
	for _, device := range knownDevices {
		id := strings.ToLower(strings.TrimSpace(device))
		if id == "" {
			continue
		}
		entry, ok := reported[id]
		if !ok {
			out.Silent = append(out.Silent, device)
			out.NeverReportedAnything = append(out.NeverReportedAnything, device)
			continue
		}
		if !entry.ReportedAt.IsZero() && now.Sub(entry.ReportedAt) > transportCAReportShelfLife {
			out.Silent = append(out.Silent, device)
			continue
		}
		switch {
		case strings.TrimSpace(entry.RenewalRecoverySNISent) == "":
			// It reported, and said nothing about this. Unknown, not "holds none" — an agent too old to carry
			// the field is in exactly this state, and it is the state the port must stay open for.
			out.Silent = append(out.Silent, device)
		case strings.EqualFold(strings.TrimSpace(entry.RenewalRecoverySNISent), name):
			// ★★★ AND WHERE IT WOULD ACTUALLY DIAL (2026-08-20, reported from win-dev-1). Holding the name was
			// treated as evidence of reaching it, and on one platform those were two pieces of code: it
			// reported the name and would still have dialled the port that had just been closed. A device that
			// has not said where it resolves to has not shown it can get here.
			if target := strings.TrimSpace(entry.RenewalRecoveryTarget); target == "" {
				out.Silent = append(out.Silent, device)
			} else if !strings.Contains(strings.ToLower(target), name) {
				out.DoesNotHold = append(out.DoesNotHold, device)
			} else {
				out.Holds = append(out.Holds, device)
			}
		default:
			out.DoesNotHold = append(out.DoesNotHold, device)
		}
	}
	sort.Strings(out.Contradicting)
	sort.Strings(out.Holds)
	sort.Strings(out.DoesNotHold)
	sort.Strings(out.Silent)
	sort.Strings(out.NeverReportedAnything)
	return out
}

// organizationsOf lists every organization with an enrolled identity on this node, the node's own included.
// The port being decided is the NODE's, so the question is asked of every fleet that reaches it.
func organizationsOf(ledger *enrolledinventory.Ledger, nodeTenant string) []string {
	seen := map[string]bool{strings.TrimSpace(nodeTenant): true}
	out := []string{strings.TrimSpace(nodeTenant)}
	for _, e := range ledger.List() {
		t := strings.TrimSpace(e.TenantID)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// keptForTenant narrows an already-filtered identity list to one organization.
func keptForTenant(ledger *enrolledinventory.Ledger, tenant string, kept []string) []string {
	in := map[string]bool{}
	for _, k := range kept {
		in[strings.ToLower(strings.TrimSpace(k))] = true
	}
	out := []string{}
	for _, e := range ledger.List() {
		id := strings.TrimSpace(e.Identity)
		if !in[strings.ToLower(id)] {
			continue
		}
		t := strings.TrimSpace(e.TenantID)
		if t == "" {
			t = tenant // an identity with no organization is the node's own, as everywhere else
		}
		if strings.EqualFold(t, tenant) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// contradictingRecoveryReports names devices whose two reported facts cannot both be true: they hold the name
// this Edge announces now, and they report a distribution older than the one that first carried it.
//
// ★ IT IS NOT RESOLVED, ONLY NAMED. Either field could be the stale one, and picking a winner would put a
// guess underneath a decision — the withdrawal gate reads the serial, this gate reads the name, and while
// they disagree neither answer is evidence. Measured on win-dev-1 on 2026-08-19: the current recovery name
// beside serial 35 of 54, which is what holds roadmap D's withdrawal shut.
func contradictingRecoveryReports(store observedExclusionStoreAPI, tenant, name string, known []string,
	firstSerial int64) []string {
	if store == nil || firstSerial <= 0 || strings.TrimSpace(name) == "" || len(known) == 0 {
		return nil
	}
	r := store.RecoveryNameReadiness(tenant, name, known)
	held := map[string]bool{}
	for _, d := range r.Holds {
		held[strings.ToLower(strings.TrimSpace(d))] = true
	}
	out := []string{}
	for _, e := range store.Query(tenant, observedQueryFilter{}).Entries {
		id := strings.ToLower(strings.TrimSpace(e.DeviceIdentity))
		if !held[id] || e.AdoptedTrustSerial <= 0 || e.AdoptedTrustSerial >= firstSerial {
			continue
		}
		out = append(out, e.DeviceIdentity)
	}
	sort.Strings(out)
	return out
}

// applyRecoverySerialEvidence compares only the introduction of the measured
// tenant/name with reports from that tenant. A missing floor is never replaced
// with either the current revision or a node-local legacy counter.
func applyRecoverySerialEvidence(r *recoveryNameReadiness, entries []observedExclusionEntry, firstSerial int64) {
	r.Contradicting = nil
	r.SerialUnverified = nil
	reported := map[string]int64{}
	for _, e := range entries {
		reported[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = e.AdoptedTrustSerial
	}
	for _, id := range r.Holds {
		serial := reported[strings.ToLower(strings.TrimSpace(id))]
		switch {
		case firstSerial <= 0 || serial <= 0:
			r.SerialUnverified = append(r.SerialUnverified, id)
		case serial < firstSerial:
			r.Contradicting = append(r.Contradicting, id)
		}
	}
	sort.Strings(r.Contradicting)
	sort.Strings(r.SerialUnverified)
}

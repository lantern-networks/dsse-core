package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// transport_name_rename_readiness.go — may the previous transport name be dropped yet?
//
// ★★★ WHY A NAME CHANGES AT ALL (2026-08-22, measured). An organization created before ids were issued takes
// its transport name from its id, and those ids are the customer's own word: tenant_northwind is served as
// "northwind.dsse.invalid". SNI is plaintext and this deployment strips ECH, so every observer between a
// device and the Edge is told which company that laptop belongs to. Organizations created since are safe —
// their ids are unguessable, so the derived names are — which leaves exactly the ones that predate it.
//
// ★ AND THE RETIREMENT IS THE DANGEROUS HALF, again. transportTenantCertificates is keyed BY NAME: the moment
// the certificate stops carrying the old one, every device still sending it fails the handshake. Not a policy
// refusal with a message — a TLS failure, on the path the device uses to be told anything at all.
//
// ★★ THE EVIDENCE IS transport_server_name_sent, WHICH THIS DEPLOYMENT COULD NOT READ UNTIL TODAY. It arrives
// on the effective report and was being discarded at the door until the gate that counts reported fields found
// it. As of this being written it comes back EMPTY from both devices — win-dev-1 is on 0.2.21 and its own
// start-up line names the SNI it adopted — so this gate correctly refuses every retirement, and the rename
// cannot be finished until that is resolved. That is the honest state, and it is written here rather than
// worked around: a gate that guesses when a device is silent is the failure this whole shape exists to avoid.
type transportNameRenameReadiness struct {
	TenantID string `json:"tenant_id"`
	// Renaming is false when nothing is in flight.
	Renaming     bool   `json:"renaming"`
	ServerName   string `json:"server_name,omitempty"`
	PreviousName string `json:"previous_server_name,omitempty"`
	// SendingNew are devices that report sending the new name — the only group that counts as moved.
	SendingNew []string `json:"sending_new"`
	// StillSendingPrevious would be refused at the handshake the moment the old name is dropped.
	StillSendingPrevious []string `json:"still_sending_previous"`
	// SendingSomethingElse named a third name. A question, not a rounding error.
	SendingSomethingElse []string `json:"sending_something_else"`
	// NeverReported have not said which name they send. This is the switched-off laptop.
	NeverReported []string `json:"never_reported"`
	// NotAgents are enrolled identities that DO NOT SEND AN ORGANIZATION NAME, named rather than dropped.
	//
	// ★★★ MEASURED BEFORE IT WAS BELIEVED (2026-08-22). Both real devices reported sending the new name and
	// the gate stayed shut on conn_lab_001, a connector, which dials this deployment by HOST and presents no
	// per-organization SNI. Retiring a transport NAME cannot fail a handshake that never carries it, so the
	// lab's only rename was held shut for ever by an identity the rename could not touch.
	//
	// ★★★ AND THE REASON IS THE NAME, NOT THE PORT. The first version of this said "a connector reaches the
	// agent plane" as though the plane were the distinguishing fact. It is not: in production a connector
	// reaches the Edge on 443, THE SAME DOOR AS AN AGENT. A reader who took the port as the reason would keep
	// this exclusion after the fold gave connectors a per-organization name, and then a rename would drop a
	// name a connector was still sending — the exact outage this gate exists to prevent, arrived at through
	// its own comment.
	//
	// So the exclusion is EVIDENCE-BASED and self-cancelling: an identity is excluded only while it is not an
	// endpoint AND has never reported a name. The day a connector reports one, it is counted like anything
	// else, with no code change and nobody having to remember.
	//
	// ★ AND IT IS NAMED, NOT SUBTRACTED. A denominator that shrinks without saying so is a gate that has
	// stopped measuring — the same rule the recovery-name readiness beside this one follows, and the same
	// source for what an identity IS: Entry.IsEndpoint from the SHARED enrolled ledger, so two Edges cannot
	// disagree.
	NotAgents         []string `json:"not_agents,omitempty"`
	MayRetirePrevious bool     `json:"may_retire_previous"`
	Note              string   `json:"note"`
}

// measureTransportNameRename compares what each of an organization's devices reports SENDING against the name
// it is being moved onto.
//
// enrolled is the denominator — every device the organization has. sending maps an identity to the SNI it last
// reported presenting; an identity absent from it has not said.
func measureTransportNameRename(tenantID, serverName, previousName string, enrolled []string,
	sending map[string]string) transportNameRenameReadiness {
	return measureTransportNameRenameExcluding(tenantID, serverName, previousName, enrolled, sending, nil)
}

// measureTransportNameRenameExcluding takes the identities that do not dial this Edge by an organization name
// — see NotAgents. They are removed from the denominator and NAMED in the answer.
func measureTransportNameRenameExcluding(tenantID, serverName, previousName string, enrolled []string,
	sending map[string]string, notAgents map[string]bool) transportNameRenameReadiness {
	kept := make([]string, 0, len(enrolled))
	excluded := []string{}
	for _, id := range enrolled {
		key := strings.ToLower(strings.TrimSpace(id))
		// Excluded only while it has said NOTHING. An identity that reports a name is dialling by name,
		// whatever kind it is, and a rename can break it.
		if notAgents[key] && strings.TrimSpace(sending[key]) == "" {
			excluded = append(excluded, id)
			continue
		}
		kept = append(kept, id)
	}
	sort.Strings(excluded)
	enrolled = kept
	out := transportNameRenameReadiness{
		TenantID: strings.TrimSpace(tenantID), SendingNew: []string{}, StillSendingPrevious: []string{},
		SendingSomethingElse: []string{}, NeverReported: []string{}, NotAgents: excluded,
	}
	current := strings.ToLower(strings.TrimSpace(serverName))
	previous := strings.ToLower(strings.TrimSpace(previousName))
	if previous == "" {
		out.Note = "this organization is not moving off another transport name, so there is nothing to be " +
			"ready for"
		return out
	}
	out.Renaming, out.ServerName, out.PreviousName = true, current, previous
	for _, id := range enrolled {
		identity := strings.TrimSpace(id)
		if identity == "" {
			continue
		}
		said, reported := sending[strings.ToLower(identity)]
		said = strings.ToLower(strings.TrimSpace(said))
		switch {
		case !reported || said == "":
			out.NeverReported = append(out.NeverReported, identity)
		case said == current:
			out.SendingNew = append(out.SendingNew, identity)
		case said == previous:
			out.StillSendingPrevious = append(out.StillSendingPrevious, identity)
		default:
			out.SendingSomethingElse = append(out.SendingSomethingElse, identity)
		}
	}
	for _, l := range [][]string{out.SendingNew, out.StillSendingPrevious, out.SendingSomethingElse,
		out.NeverReported} {
		sort.Strings(l)
	}
	// ★★★ "NOBODY HAS REPORTED" AND "THERE IS NOBODY" ARE DIFFERENT ZEROES (2026-08-22, measured — an
	// organization with no devices could never finish a rename, for ever).
	//
	// The rule below requires a positive witness: at least one device saying it sends the new name. That is
	// right when devices EXIST, because silence is exactly the switched-off laptop this gate protects. It is
	// a dead end when the denominator is empty — an organization provisioned ahead of its first device, or
	// one whose devices have all been removed — because the witness it demands cannot exist and the act it
	// blocks cannot hurt anyone. Measured on tenant_northwind: nought devices, nought silent, and
	// may_retire_previous false with nothing left to wait for.
	//
	// Empty means empty AFTER the exclusions above, and that is deliberate: an organization whose only
	// enrolled identity is a connector has nobody who sends a name, so dropping one breaks nobody. The
	// excluded identities are named in the answer either way.
	nobodyToBreak := len(enrolled) == 0
	out.MayRetirePrevious = (nobodyToBreak || len(out.SendingNew) > 0) && len(out.StillSendingPrevious) == 0 &&
		len(out.SendingSomethingElse) == 0 && len(out.NeverReported) == 0
	switch {
	case out.MayRetirePrevious && nobodyToBreak:
		// Said as its own sentence, because "nobody is affected" is a different claim from "everybody has
		// moved" and an operator reading a screen must not be handed the second when the first is true.
		out.Note = fmt.Sprintf("this organization has no device that sends a transport name, so dropping %q "+
			"breaks nobody. This is not evidence that anything moved — it is that there is nothing to move",
			previous)
	case out.MayRetirePrevious:
		out.Note = fmt.Sprintf("every one of this organization's %d device(s) reports sending %q, so the "+
			"certificate can stop carrying %q", len(out.SendingNew), current, previous)
	case len(out.SendingNew) == 0 && len(out.NeverReported) == len(enrolled):
		out.Note = fmt.Sprintf("no device has said which transport name it sends. That is not readiness — it "+
			"is the absence of evidence, and dropping %q would fail the handshake for every one of them. An "+
			"agent that does not report transport_server_name_sent cannot finish a rename", previous)
	default:
		out.Note = fmt.Sprintf("%d send %q, %d still send %q, %d send a third name, %d have not said. "+
			"Dropping the previous name now would fail the handshake for everything outside the first group",
			len(out.SendingNew), current, len(out.StillSendingPrevious), previous,
			len(out.SendingSomethingElse), len(out.NeverReported))
	}
	return out
}

// registerTransportNameRenameRoute answers on the EDGE: only an Edge collects what a device reports sending.
func registerTransportNameRenameRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig) {
	mux.HandleFunc("GET /admin/transport-name-rename", adminEndpoint("admin.endpoints.read",
		func(w http.ResponseWriter, r *http.Request) {
			tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
			current, previous := transportTenantCertificates.RenameState(tenant)
			enrolled := []string{}
			if config.EnrolledLedger != nil {
				for _, e := range config.EnrolledLedger.List() {
					if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, e.Identity, tenant); placeable && belongs {
						enrolled = append(enrolled, e.Identity)
					}
				}
			}
			sending := map[string]string{}
			if config.ObservedExclusions != nil {
				for _, e := range config.ObservedExclusions.Query(tenant, observedQueryFilter{}).Entries {
					if n := strings.TrimSpace(e.TransportServerNameSent); n != "" {
						sending[strings.ToLower(strings.TrimSpace(e.DeviceIdentity))] = n
					}
				}
			}
			// What an identity IS comes from the shared enrolled ledger, so two Edges cannot disagree — the
			// per-Edge connector registry got this wrong once and made region-a and region-b answer the same
			// question differently.
			notAgents := map[string]bool{}
			if config.EnrolledLedger != nil {
				for _, e := range config.EnrolledLedger.List() {
					if !e.IsEndpoint() {
						notAgents[strings.ToLower(strings.TrimSpace(e.Identity))] = true
					}
				}
			}
			writeJSON(w, http.StatusOK, measureTransportNameRenameExcluding(tenant, current, previous, enrolled,
				sending, notAgents))
		}))
}

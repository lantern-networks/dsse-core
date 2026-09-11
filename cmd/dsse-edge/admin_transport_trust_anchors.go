package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The transport trust anchors, and how far the fleet has got with each one.
//
// These are what a device checks before it will talk to an Edge at all. Replacing one is the operation that can
// strand the entire fleet, and the reason it is survivable is that two anchors are served at once: the new one
// is distributed, devices adopt it on their own schedule, and only when every device holds it does the old one
// get withdrawn. Cutting early is what strands the devices that were switched off.
//
// Until now an operator could not see any of this. The anchors appeared in one startup log line as bare
// fingerprints, and the adoption count lived behind an endpoint that required knowing a fingerprint in advance
// to ask about. So the safe procedure existed and the information needed to follow it did not, which is a
// procedure in name only.
//
// Anchors and adoption are returned TOGETHER on purpose. Asked separately, an operator has to carry a
// fingerprint from one answer to the next by hand, and the one thing they must not get wrong is which anchor
// they are talking about.

type transportTrustAnchor struct {
	SHA256    string `json:"sha256"`
	Subject   string `json:"subject"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
	IsExpired bool   `json:"is_expired"`
	Serving   bool   `json:"serving"`
	// IssuesCurrent marks the certificate the Edge's presented identity currently chains from — the one an
	// operator means by "the current one".
	IssuesCurrent bool `json:"issues_current"`
	// CanWithdraw and WithdrawBlockedReason are the withdrawal gate, decided HERE (the same decision the
	// DELETE enforces) so the screen never renders a button the server would refuse — or hides one it would
	// accept. Only meaningful when the set is runtime-mutable.
	CanWithdraw bool `json:"can_withdraw"`
	// The code and its parameters let the Console say this in the operator's language; the text is kept
	// for API consumers and logs, and is what the Console falls back to for a code it does not know —
	// a refusal it cannot phrase must still be readable, never blank.
	WithdrawBlockedCode   string   `json:"withdraw_blocked_code,omitempty"`
	WithdrawBlockedParams []string `json:"withdraw_blocked_params,omitempty"`
	WithdrawBlockedReason string   `json:"withdraw_blocked_reason,omitempty"`
	// AcknowledgedIdentities are the ones an operator has asserted hold this anchor by other means — a
	// connector whose CA file they updated, say. Counted towards safety and reported SEPARATELY from what
	// devices said themselves: the two are different kinds of evidence, and merging them would answer "is this
	// safe" while destroying "how do we know".
	AcknowledgedIdentities []transportAnchorAcknowledgement `json:"acknowledged,omitempty"`
	// Readiness is nil when device telemetry is not enabled — the honest answer, and different from "no device
	// has it". A screen that renders a missing measurement as zero adoption would push an operator to wait
	// forever for a number that is never going to arrive.
	Readiness *transportCAReadiness `json:"readiness,omitempty"`
}

type transportTrustAnchorsResponse struct {
	SchemaVersion string                 `json:"schema_version"`
	Serial        int64                  `json:"serial"`
	Anchors       []transportTrustAnchor `json:"anchors"`
	// DevicesConsidered is the enrolled, ENABLED device count the adoption figures are measured against, so a
	// percentage can be read without wondering what its denominator was.
	DevicesConsidered int `json:"devices_considered"`
	// DevicesWithheldOtherOrganizations counts machines left out because they are not the caller's.
	DevicesWithheldOtherOrganizations int    `json:"devices_withheld_other_organizations,omitempty"`
	TelemetryEnabled                  bool   `json:"telemetry_enabled"`
	Note                              string `json:"note,omitempty"`
	// ChangeProcedure is how an anchor is actually added or withdrawn on THIS deployment, with its real path
	// and serial. There is no runtime route for it — the anchors are read from a file at startup — so a screen
	// that shows adoption and stops there leaves an operator watching a number with no way to act on it.
	//
	// The serial is the part people get wrong. Devices refuse a bundle that does not advance past the highest
	// they have accepted, which is deliberate rollback protection and reads as "the change did nothing".
	ChangeProcedure []string `json:"change_procedure,omitempty"`
	// ForOrganization names whose bundle these anchors are. The set differs per organization once any of them
	// has an authority of its own, so an answer that does not say who it is about cannot be read.
	ForOrganization string `json:"for_organization,omitempty"`
	// OwnAnchors is how many of them belong to that organization rather than being the shared, deployment-wide
	// one. Two means a rotation is in flight between its own authorities; one plus SharedWithdrawn means the
	// organization no longer depends on an anchor other organizations' devices also trust — the end state
	// roadmap D is walking toward.
	OwnAnchors      int  `json:"own_anchors"`
	SharedWithdrawn bool `json:"shared_anchor_withdrawn"`
}

// enabledEnrolledIdentities is the denominator every trust measurement uses: the ENROLLED inventory, never
// telemetry — otherwise the fleet looks fully ready precisely because the devices missing the certificate
// are the ones not reporting.
//
// Scoped to THIS Edge's tenant, because readiness reports are: counting another tenant's devices in the
// denominator while their reports are filtered out leaves them permanently unaccounted, so the gate can
// only ever be opened by vouching — and a safeguard that must be talked around is not one (review R10②).
// An entry with no tenant recorded belongs to a single-tenant deployment and counts.
func enabledEnrolledIdentities(config serverConfig) []string {
	return enabledEnrolledIdentitiesFor(config, "")
}

// enabledEnrolledIdentitiesFor is the same question asked ABOUT a named organization.
//
// ★★★ THE INNER NARROWING EMPTIED THE SET BEFORE THE OUTER ONE COULD SCOPE IT (2026-09-06, measured on a
// three-region deployment with two devices enrolled in a customer organization). The per-organization read
// below already says "scoped to the organization this answer is about" and hands its result to
// deviceIdentitiesForCaller — but the list it hands over was built with `want` = THIS NODE's organization,
// which on any deployment with customers is never the organization being asked about. So:
//
//	GET /admin/enrolled-devices          2 devices, both enabled, both in tenant_obz3…
//	GET /admin/transport-trust-anchors   devices_considered 0, for_organization tenant_obz3…
//
// One node, one ledger, one organization, two answers. And the zero is the denominator the shared anchor's
// withdrawal is judged on, so the last step of per-organization PKI reads as "nothing to measure" on exactly
// the population it exists for. Nothing fails; the screen simply never says why it is not moving.
//
// An empty tenant keeps the old meaning — the node's own organization — because the call sites that ask
// about the NODE rather than about a customer are asking a different question and are correct as they are.
func enabledEnrolledIdentitiesFor(config serverConfig, tenant string) []string {
	var known []string
	if config.EnrolledLedger != nil {
		want := strings.TrimSpace(tenant)
		if want == "" {
			want = strings.TrimSpace(config.TenantIDForTrust)
		}
		connectors := connectorIdentitiesFor(config.Registry, want)
		for _, entry := range config.EnrolledLedger.List() {
			if !entry.Enabled {
				continue
			}
			if want != "" && strings.TrimSpace(entry.TenantID) != "" && strings.TrimSpace(entry.TenantID) != want {
				continue
			}
			// ★ ONLY IDENTITIES A TRUST BUNDLE CAN REACH (2026-08-19). The withdrawal question is "has every
			// device taken the distribution that carries this CA". A service identity — a connector — never
			// takes one: it pins the Edge CA handed to it at enrolment and never reads a bundle, so it can
			// neither confirm nor be harmed by what a bundle stops announcing. Counting it left roadmap D's
			// last step permanently blocked on a client the withdrawal does not affect.
			//
			// The identity's Kind is the ledger's own answer and is the same on every Edge. It is a narrowing,
			// so the cost of getting it wrong is a withdrawal that should have been refused — which is why it
			// is the LEDGER's declaration and never an inference from the identifier, and why the readiness
			// response names who was left out.
			if !entry.IsEndpoint() {
				continue
			}
			// ★★★ AND THE LEDGER NEVER DECLARED IT (2026-09-06, measured: a connector, a Mac and a Windows
			// machine in one organization, all three with kind ""). The narrowing above is the LEDGER's
			// declaration, which is right — but nothing in this product writes KindService, so the declaration
			// is absent on every entry ever made and the narrowing has never once fired. A connector was
			// therefore counted as a device that must adopt a distribution it never reads, which is exactly
			// the outcome the note above says it was written to prevent.
			//
			// The connector REGISTRY is authoritative for what is a connector — this repository already made
			// that decision, for this same question, on the device list. Asking it is not an inference from
			// the identifier; it is asking the component that knows. The ledger's own declaration stays above
			// and wins when it is ever written.
			if isConnectorIdentity(connectors, entry.Identity) {
				continue
			}
			known = append(known, entry.Identity)
		}
	}
	return known
}

// anchorCoverage is the readiness for one distributed certificate with the operator's assertions applied —
// the exact quantity the withdrawal gate is decided on.
//
// It reads the current serial FROM THE TRUST STORE, so it must never run while the caller holds that
// store's lock — WithdrawIf's in-lock gate re-judgement did exactly that on 2026-08-02 and deadlocked the
// Edge's whole trust surface (goroutine dump: WithdrawIf → gate → here → Current → the same mutex).
// Callers inside the lock use anchorCoverageAtSerial with a serial captured before locking.
func anchorCoverage(config serverConfig, tenantID, fp string, known []string) transportCAReadiness {
	_, serial := currentTrustAnchors(config)
	return anchorCoverageAtSerial(config, tenantID, fp, known, serial)
}

// anchorCoverageAtSerial is anchorCoverage with the distribution serial supplied by the caller — the form
// that is safe under the trust-store lock, because it touches only the observed store and the ack store.
func anchorCoverageAtSerial(config serverConfig, tenantID, fp string, known []string, serial int64) transportCAReadiness {
	// At the serial this Edge is currently distributing: a device still reporting an older one is verifying
	// against a set it has since been sent a replacement for, so its fingerprints are about something that is
	// no longer in use and must not count toward opening the gate.
	readiness := config.ObservedExclusions.TransportCAReadinessAtSerial(tenantID, fp, known, serial)
	if acks := transportAnchorAcks.For(fp); len(acks) > 0 {
		acknowledged := map[string]bool{}
		for _, ack := range acks {
			acknowledged[strings.ToLower(strings.TrimSpace(ack.Identity))] = true
		}
		readiness = applyAnchorAcknowledgements(readiness, acknowledged, known)
	}
	return readiness
}

// anchorWithdrawGate decides whether the certificate with fingerprint targetSHA may be withdrawn — ONE
// decision, used both to answer the DELETE and to state the button on the screen, so the two can never
// disagree. Withdrawal is allowed only when some REMAINING certificate (a) is trusted by every enrolled
// device (reported or operator-confirmed) and (b) still verifies the identity the Edge presents today.
// gateVerdict is a refusal an operator can be told in their own language. The sentence is kept for API
// consumers and logs, but the Console renders from the CODE — a server sentence printed verbatim into a
// Japanese screen is the operator reading someone else's language at the moment they are blocked. Params
// carry the names the sentence needs, so the wording lives with the UI rather than in the gate.
type gateVerdict struct {
	Code   string   `json:"code,omitempty"`
	Params []string `json:"params,omitempty"`
	Text   string   `json:"text,omitempty"`
}

func gateRefuse(code, text string, params ...string) gateVerdict {
	return gateVerdict{Code: code, Text: text, Params: params}
}

// anchorWithdrawGate takes the distribution serial as a parameter rather than reading it from the trust
// store, because its in-lock caller (WithdrawIf's re-judgement) already holds that store's mutex.
func anchorWithdrawGate(config serverConfig, tenantID, targetSHA string,
	anchors []*x509.Certificate, known []string, serial int64) (bool, gateVerdict) {
	if transportTrust == nil {
		return false, gateRefuse("trust_set_fixed_at_startup", "the trust set on this node is fixed at startup (-transport-trust-store is not configured)")
	}
	if len(anchors) < 2 {
		return false, gateRefuse("last_certificate", "the last certificate cannot be withdrawn")
	}
	if config.ObservedExclusions == nil {
		return false, gateRefuse("not_measurable", "trust cannot be measured on this node")
	}
	// What the Edge is actually SERVING, not what is on disk: a write that failed after the file was
	// replaced, or a read racing a truncating write, would otherwise have the gate reason about a
	// certificate nobody is being served (review R6).
	chain := servedTransportChain(config)
	if len(chain) == 0 {
		// No certificate to reason about is not permission. The previous seed made the chain condition
		// vacuously true whenever the file was unset or unreadable, which — combined with an empty
		// denominator — left no gate at all.
		return false, gateRefuse("served_certificate_unreadable", "the certificate the Edge presents cannot be read, so a withdrawal cannot be judged")
	}

	// ONE remaining certificate must satisfy BOTH conditions. Two independent existential quantifiers
	// would pass when B covers the fleet and C verifies the chain and neither does both — which is not
	// the invariant this gate's own comment states, and composes into a real strand with rollback (R5).
	// ★★★ A device on its organization's OWN transport authority does not depend on this store (2026-08-20).
	// See anchor_gate_device_on_its_own_authority.go: after roadmap D both real devices pin their
	// organization's CA and neither pins the shared anchor, so no certificate here was trusted by "every
	// device" and nothing could ever be withdrawn again. Those devices are removed from the denominator on
	// their own fresh evidence; everyone else stays in it.
	selfCovered := devicesOnTheirOwnOrganizationsAuthority(config, tenantID, targetSHA, known)
	uncovered := map[string]bool{}
	for _, c := range anchors {
		sum := sha256.Sum256(c.Raw)
		fp := hex.EncodeToString(sum[:])
		if fp == strings.ToLower(strings.TrimSpace(targetSHA)) {
			continue
		}
		cov := anchorCoverageAtSerial(config, tenantID, fp, known, serial)
		stillNeeded := []string{}
		for _, id := range append(append(append([]string{}, cov.NotReady...), cov.Silent...), cov.NeverReportedAnything...) {
			if !selfCovered[strings.ToLower(strings.TrimSpace(id))] {
				stillNeeded = append(stillNeeded, id)
			}
		}
		// The chain condition is NOT relaxed: whatever remains must still verify the identity this Edge
		// presents, so withdrawing can never leave the node unverifiable for anyone who does depend on it.
		if len(stillNeeded) == 0 && verifiesCurrentChain(c, chain) {
			return true, gateVerdict{} // this one certificate carries everyone who still needs this store
		}
		for _, id := range stillNeeded {
			uncovered[id] = true
		}
	}
	if len(uncovered) > 0 {
		names := []string{}
		for id := range uncovered {
			names = append(names, id)
		}
		sort.Strings(names)
		return false, gateRefuse("no_single_certificate_does_both",
			"no single remaining certificate is both trusted by every device and able to verify the Edge — unconfirmed: "+
				strings.Join(names, ", "), names...)
	}
	return false, gateRefuse("none_verifies_served", "no remaining certificate verifies the identity the Edge presents — switch the Edge's certificate first")
}

// deviceClientCARetireGate decides whether a CA may leave device trust. Retiring one that a device still
// chains from rejects that device at its next handshake, so the denominator has to be the ENROLLED
// inventory — the same one the anchor gate uses — not "devices seen since this process started".
//
// The first version read `deviceCertificates` alone, an in-memory map an Edge restart empties: right after
// a restart it saw no holders and permitted retiring the CA the whole fleet chains from (review R3). Every
// enrolled device must be accounted for: seen on another CA, or explicitly not chaining from this one.
// A device that has not been observed at all blocks, because a laptop that has been off for two weeks is
// exactly who this protects.
//
// The certificate a device PRESENTS is not the only one it HOLDS. On 2026-08-02 this gate correctly saw the
// whole fleet presenting renewed certificates and permitted retiring their old CA — and a device that later
// fell back to its BOOTSTRAP credential was refused at every handshake, because the bootstrap chained to the
// CA that had just been retired. Devices now report that fallback credential in reverse telemetry, and a CA
// that still issues any enrolled device's fallback does not retire.
func deviceClientCARetireGate(config serverConfig, tenantID, targetSHA string) (bool, gateVerdict) {
	if deviceClientCAs == nil {
		return false, gateRefuse("device_ca_set_fixed_at_startup", "the device-trust CA set on this node is fixed at startup")
	}
	var target *x509.Certificate
	remaining := 0
	for _, c := range deviceClientCAs.Anchors() {
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == strings.ToLower(strings.TrimSpace(targetSHA)) {
			target = c
			continue
		}
		remaining++
	}
	if target == nil {
		return false, gateRefuse("unknown_fingerprint", "no CA in device trust has that fingerprint")
	}
	if remaining == 0 {
		return false, gateRefuse("last_device_ca", "the last CA cannot be retired — no device certificate could be verified at all")
	}

	known := enabledEnrolledIdentities(config)
	if len(known) == 0 {
		// An empty enrolled inventory is not a fleet that has moved on; it is a node that cannot tell.
		return false, gateRefuse("no_enrolled_device", "no enrolled device to measure against, so retirement cannot be judged")
	}
	observed := map[string]deviceCertificateFact{}
	for _, fact := range deviceCertificates.snapshot() {
		observed[fact.Identity] = fact
	}
	// An identity can be enrolled and never present a device certificate here at all — a connector holds an
	// identity because it needs one, and connects on a different path. Without an escape hatch this gate can
	// never open while such an identity exists, and a safeguard that cannot be satisfied is an instruction to
	// work around the safeguard. So the operator may account for one BY NAME, on the same terms as the
	// transport-trust gate: a claim about a deployment, recorded with who made it and why.
	vouched := map[string]bool{}
	for _, ack := range transportAnchorAcks.For(strings.ToLower(strings.TrimSpace(targetSHA))) {
		vouched[strings.ToLower(strings.TrimSpace(ack.Identity))] = true
	}
	var chaining, unseen []string
	for _, id := range known {
		if vouched[strings.ToLower(strings.TrimSpace(id))] {
			continue
		}
		fact, seen := observed[id]
		if !seen {
			unseen = append(unseen, id)
			continue
		}
		// Fingerprint would be better than issuer CN, but the observed fact carries the CN only; a CA
		// rotation that keeps the CN is therefore indistinguishable here and is called out in the ledger.
		if strings.TrimSpace(fact.IssuerCN) == target.Subject.CommonName {
			chaining = append(chaining, id)
		}
	}
	if len(chaining) > 0 {
		sort.Strings(chaining)
		return false, gateRefuse("still_presented_by",
			"still presented by "+strings.Join(chaining, ", ")+" — their certificates chain from this CA", chaining...)
	}
	if len(unseen) > 0 {
		sort.Strings(unseen)
		return false, gateRefuse("unseen_since_start",
			"not seen since this node started, so what they chain from is unknown: "+strings.Join(unseen, ", ")+
				" — confirm each of them, or wait until they connect", unseen...)
	}
	if fallbackHolders := devicesWhoseFallbackChainsFrom(config, tenantID, target, known, vouched); len(fallbackHolders) > 0 {
		return false, gateRefuse("issues_a_fallback_credential",
			"this CA issues the BOOTSTRAP credential of "+strings.Join(fallbackHolders, ", ")+
				" — a device falling back to it would be refused at every handshake; re-provision those bootstraps first",
			fallbackHolders...)
	}
	return true, gateVerdict{}
}

// devicesWhoseFallbackChainsFrom lists the enrolled identities whose REPORTED fallback (bootstrap) client
// certificate is issued by target — checked by verifying the fallback's signature against the candidate CA,
// never by comparing names, so a rotation that keeps the subject cannot fool it. A report older than the
// telemetry shelf life, or a device that never reported a fallback, adds no constraint: this check can only
// make retirement HARDER as agents learn to report, and an absent report keeps the gate exactly as strict as
// it was before the field existed. An identity the operator vouched for by name is skipped, on the same
// terms as every other condition in this gate.
func devicesWhoseFallbackChainsFrom(config serverConfig, tenantID string, target *x509.Certificate,
	known []string, vouched map[string]bool) []string {
	if config.ObservedExclusions == nil || target == nil {
		return nil
	}
	var holders []string
	for _, id := range known {
		if vouched[strings.ToLower(strings.TrimSpace(id))] {
			continue
		}
		page := config.ObservedExclusions.Query(tenantID, observedQueryFilter{Device: id, Limit: 1})
		if len(page.Entries) == 0 {
			continue
		}
		entry := page.Entries[0]
		if strings.TrimSpace(entry.FallbackClientCertPEM) == "" ||
			time.Since(entry.ReportedAt) > transportCAReportShelfLife {
			continue
		}
		block, _ := pem.Decode([]byte(entry.FallbackClientCertPEM))
		if block == nil {
			continue
		}
		fallback, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if fallback.CheckSignatureFrom(target) == nil {
			holders = append(holders, id)
		}
	}
	sort.Strings(holders)
	return holders
}

// servedTransportChain is the chain the transport listeners are presenting right now, preferring the
// hot-reload registry (the truth) over the backing file (which can be mid-write, or ahead of a reload
// that failed).
func servedTransportChain(config serverConfig) []*x509.Certificate {
	if transportServedCert != nil {
		if c := transportServedCert.Current(); c != nil && len(c.Certificate) > 0 {
			out := make([]*x509.Certificate, 0, len(c.Certificate))
			for _, der := range c.Certificate {
				if parsed, err := x509.ParseCertificate(der); err == nil {
					out = append(out, parsed)
				}
			}
			return out
		}
	}
	if p := strings.TrimSpace(config.TransportCertFile); p != "" {
		if raw, err := os.ReadFile(p); err == nil {
			return parseAllCerts(raw)
		}
	}
	// ★ AND THE REGISTRY, which is what the listeners actually present — the same last resort
	// servedTransportLeaf uses. Without it this returned nil on a deployment whose Edge serves its door from
	// the main listener, and the withdrawal gate refused every anchor of every organization with
	// "the certificate the Edge presents cannot be read": a gate closed by a nil rather than by a
	// measurement, on a deployment that could name the certificate on the screen beside it.
	if chain, err := registeredTransportChain(); err == nil {
		return chain
	}
	return nil
}

func registerTransportTrustAnchorsEndpoint(mux *http.ServeMux, config serverConfig, tenantID string,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	record func(r *http.Request, action, targetID, reason string, metadata map[string]any)) {
	mux.HandleFunc("GET /admin/transport-trust-anchors", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		// Read what the fleet has distributed before judging or listing: this node may be between
		// recompute ticks and holding what it last wrote. See AdoptFleetDistribution.
		transportTrust.AdoptFleetDistribution()
		_, serial := currentTrustAnchors(config)
		// ★★★ THE SET THIS ORGANIZATION'S DEVICES ARE ACTUALLY TOLD TO TRUST (2026-08-20).
		//
		// This read used to answer from the node's CONFIGURED bundle. Measured on the lab the same day: the
		// screen listed one anchor, the shared one, while the organization's devices were being handed three —
		// the shared one plus the two authorities of its own it is being moved between. Readiness and "safe to
		// cut" were therefore computed about a set nobody verifies against, and the decision this screen exists
		// to support is the withdrawal of that shared anchor.
		//
		// Both now come from the same place the bundle is built from, so they cannot disagree by omission.
		target := strings.TrimSpace(adminTenantIDFromRequest(r))
		if target == "" {
			target = tenantID // an unscoped deployment answers about the node's own organization, as before
		}
		pems, ownAnchors, sharedWithdrawn := perTenantTrustBundlesForAdmin.AnnouncedAnchorsFor(target)
		if strings.TrimSpace(pems) == "" {
			pems, _ = currentTrustAnchors(config)
		}
		if strings.TrimSpace(pems) == "" {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("no transport trust bundle is configured on this node"))
			return
		}
		certs, err := (agentpolicy.TrustBundlePayload{TransportCAPEM: pems}).Anchors()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("parse trust bundle: %w", err))
			return
		}
		// ★ Scoped to the organization this answer is about. These lists name MACHINES, and the anchor they
		// hold is the deployment's — which is why the anchor is shown and the holders are not. Measured as a
		// customer administrator: three machines belonging to another organization, by name.
		known, withheldDevices := deviceIdentitiesForCaller(enabledEnrolledIdentitiesFor(config, target), config.EnrolledLedger, r)
		// ★ AND THE MACHINES COUNTED ARE THE ONES THE ANSWER IS ABOUT. The reports behind readiness are stored
		// per organization, so measuring an organization's anchor against machines belonging to another reads as
		// "0 of 2 ready" — a denominator from one organization over a numerator from another. Before this read
		// resolved the organization at all, the two happened to be the same on a single-tenant node and stopped
		// being the same the moment an operator looked at a shared fleet.
		if config.EnrolledLedger != nil && strings.TrimSpace(target) != "" {
			// ★★ AND THIS NARROWING WAS COUNTED NOWHERE (2026-08-20). deviceIdentitiesForCaller says how many
			// machines it held back, and then this line drops more — silently. Measured as the operator: the
			// screen answered devices_considered=0 and devices_withheld_other_organizations absent, which reads
			// as "the fleet is empty", while a withdrawal of the shared anchor was being judged against
			// mac-dev-1 and win-dev-1 and refused by name. The reader could see neither the machines nor the
			// fact that there were machines. The comment three lines above already states the rule this broke:
			// said rather than swallowed.
			before := len(known)
			known = keptForTenant(config.EnrolledLedger, target, known)
			if dropped := before - len(known); dropped > 0 {
				withheldDevices += dropped
			}
		}

		var presented []*x509.Certificate
		if p := strings.TrimSpace(config.TransportCertFile); p != "" {
			if raw, rerr := os.ReadFile(p); rerr == nil {
				presented = parseAllCerts(raw)
			}
		}

		now := time.Now()
		out := transportTrustAnchorsResponse{
			SchemaVersion:     "admin_transport_trust_anchors.v1",
			Serial:            serial,
			ForOrganization:   target,
			OwnAnchors:        ownAnchors,
			SharedWithdrawn:   sharedWithdrawn,
			DevicesConsidered: len(known),
			// Said rather than swallowed: a coverage figure computed over machines the reader cannot see is a
			// figure about other people, and "none" would read as "the fleet is empty".
			DevicesWithheldOtherOrganizations: withheldDevices,
			TelemetryEnabled:                  config.ObservedExclusions != nil,
			Anchors:                           []transportTrustAnchor{},
		}
		if !out.TelemetryEnabled {
			out.Note = "Device telemetry is not enabled on this node, so trust cannot be measured here."
		}
		// The file procedure applies only while the set is startup-fixed; with the store, add and withdraw
		// are the buttons on the screen.
		if transportTrust == nil {
			if path := strings.TrimSpace(config.TrustBundleCAPath); path != "" {
				out.ChangeProcedure = []string{
					"File: " + path + " (read at startup)",
					"Add: append the PEM → raise -trust-bundle-serial above " + fmt.Sprint(serial) + " → restart",
					"Wait until every device shows as trusting the new certificate",
					"Withdraw: remove the old PEM → raise the serial again → restart",
				}
			}
		}
		for _, c := range certs {
			sum := sha256.Sum256(c.Raw)
			fp := hex.EncodeToString(sum[:])
			anchor := transportTrustAnchor{
				SHA256:    fp,
				Subject:   c.Subject.CommonName,
				NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
				DaysLeft:  int(c.NotAfter.Sub(now).Hours() / 24),
				IsExpired: now.After(c.NotAfter),
				Serving:   true,
			}
			if len(presented) > 0 {
				anchor.IssuesCurrent = presented[0].Issuer.CommonName == c.Subject.CommonName && verifiesCurrentChain(c, presented)
			}
			if config.ObservedExclusions != nil {
				// ★★★ COUNTED IN THE ORGANIZATION THIS ANSWER IS ABOUT (2026-09-07, measured on a device that
				// was reporting every minute and read as never having reported at all).
				//
				// The anchors above come from `target` — the organization the caller asked about — and the
				// device list is that organization's too. The readiness was looked up in `tenantID`, the
				// NODE's own organization, whose report list is empty on any deployment where the customers
				// are somebody else. So every device in every customer organization came back
				// never_reported_anything, ready_pct 0, safe_to_cut false, for ever.
				//
				// Measured: the Edge's own observed record held the device's report — posture, pinned
				// transport CA, adopted serial, the name it sends — timestamped seconds earlier, while the
				// screen beside it said the device had never said anything. The withdrawal of an
				// organization's shared anchor is the decision this readiness exists to support, and it could
				// not be taken.
				//
				// The same correction was made at the withdrawal gate on 2026-09-06 and this half was left
				// behind: the gate counted in the right organization while the screen counted in the wrong
				// one, so an operator was refused by a number no screen agreed with.
				readiness := anchorCoverage(config, target, fp, known)
				// An operator's assertion counts, and is shown for what it is. Something that cannot report —
				// a connector verifies the Edge against a CA file rather than running the steering agent — can
				// otherwise never be ready, so the gate could never open and would stop being a safeguard.
				// The acknowledgements name machines too, so they follow the same scope.
				acks := transportAnchorAcks.For(fp)
				ackIDs := make([]string, 0, len(acks))
				for _, ack := range acks {
					ackIDs = append(ackIDs, ack.Identity)
				}
				visible, _ := deviceIdentitiesForCaller(ackIDs, config.EnrolledLedger, r)
				keep := map[string]bool{}
				for _, id := range visible {
					keep[id] = true
				}
				shown := make([]transportAnchorAcknowledgement, 0, len(acks))
				for _, ack := range acks {
					if keep[ack.Identity] {
						shown = append(shown, ack)
					}
				}
				anchor.AcknowledgedIdentities = shown
				anchor.Readiness = &readiness
			}
			ok, verdict := anchorWithdrawGate(config, tenantID, fp, certs, known, serial)
			anchor.CanWithdraw = ok
			anchor.WithdrawBlockedReason = verdict.Text
			anchor.WithdrawBlockedCode = verdict.Code
			anchor.WithdrawBlockedParams = verdict.Params
			out.Anchors = append(out.Anchors, anchor)
		}
		writeJSON(w, http.StatusOK, out)
	}))

	// ADD a certificate to what devices trust — always the safe direction: devices gain a certificate they
	// can match, nobody loses one. The serial advances and the distribution is re-signed atomically.
	mux.HandleFunc("POST /admin/transport-trust-anchors", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		// Read what the fleet has distributed before judging or listing: this node may be between
		// recompute ticks and holding what it last wrote. See AdoptFleetDistribution.
		transportTrust.AdoptFleetDistribution()
		if transportTrust == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("the trust set on this node is fixed at startup (-transport-trust-store is not configured)"))
			return
		}
		// ★★★ AUTHORED ON THE CONTROL PLANE, BECAUSE ONLY THE CONTROL PLANE CAN CARRY IT ACROSS REGIONS
		// (2026-09-07, measured on a three-region deployment).
		//
		// This set travels in the signed config bundle. A write taken HERE lands on one Edge's own store: the
		// Console shows the certificate added, that Edge serves it, and the other regions never hear of it —
		// no error, no log, and an operator with every reason to believe the deployment has it. It is worse
		// for a withdrawal, where the regions that did not hear keep announcing an authority the operator has
		// retired.
		//
		// Refusing with a 409 that names where to write is the difference between an error somebody can act
		// on and a fleet that silently disagrees with itself about what devices may trust.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "what devices trust about this deployment") {
			return
		}
		var req struct {
			CertificatePEM string `json:"certificate_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode certificate: %w", err))
			return
		}
		added, serial, err := transportTrust.Add(req.CertificatePEM)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		sum := sha256.Sum256(added.Raw)
		fp := hex.EncodeToString(sum[:])
		logInfof("transport_trust_certificate_added subject=%q sha256=%s serial=%d", added.Subject.CommonName, fp, serial)
		if record != nil {
			record(r, "transport_trust_certificate_added", fp, "a certificate was added to what devices trust",
				map[string]any{"subject": added.Subject.CommonName, "serial": serial})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_transport_trust_anchors.v1",
			"added":          added.Subject.CommonName, "sha256": fp, "serial": serial,
		})
	}))

	// WITHDRAW a certificate — the gated operation. The gate is the same decision the GET reports per
	// certificate, enforced here regardless of what any screen displayed.
	mux.HandleFunc("DELETE /admin/transport-trust-anchors/{sha256}", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		// Read what the fleet has distributed before judging or listing: this node may be between
		// recompute ticks and holding what it last wrote. See AdoptFleetDistribution.
		transportTrust.AdoptFleetDistribution()
		if transportTrust == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("the trust set on this node is fixed at startup (-transport-trust-store is not configured)"))
			return
		}
		// ★★★ AUTHORED ON THE CONTROL PLANE, BECAUSE ONLY THE CONTROL PLANE CAN CARRY IT ACROSS REGIONS
		// (2026-09-07, measured on a three-region deployment).
		//
		// This set travels in the signed config bundle. A write taken HERE lands on one Edge's own store: the
		// Console shows the certificate added, that Edge serves it, and the other regions never hear of it —
		// no error, no log, and an operator with every reason to believe the deployment has it. It is worse
		// for a withdrawal, where the regions that did not hear keep announcing an authority the operator has
		// retired.
		//
		// Refusing with a 409 that names where to write is the difference between an error somebody can act
		// on and a fleet that silently disagrees with itself about what devices may trust.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "what devices trust about this deployment") {
			return
		}
		target := strings.ToLower(strings.TrimSpace(r.PathValue("sha256")))
		known := enabledEnrolledIdentities(config)
		// The serial is captured HERE, outside the store lock, and carried into both judgements. The in-lock
		// gate below must not read it from the store itself: WithdrawIf holds the store mutex while running
		// the gate, and the gate reading the serial through currentTrustAnchors → Current re-locks the same
		// mutex — the self-deadlock that froze this Edge's entire trust surface on 2026-08-02 the first time
		// a withdrawal ever passed the pre-check. (A withdrawal bumps the serial only AFTER it commits, so
		// the pre-lock serial is exact for the gate's purpose.)
		_, distributionSerial := currentTrustAnchors(config)
		// Judged first so a refusal is a 409 with the gate's reason, and re-judged INSIDE the store lock so
		// a concurrent withdrawal cannot be admitted against a set that still contains the other's target.
		if ok, verdict := anchorWithdrawGate(config, tenantID, target, transportTrust.Anchors(), known, distributionSerial); !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("withdrawal refused: %s", verdict.Text))
			return
		}
		var targetCert *x509.Certificate
		for _, c := range transportTrust.Anchors() {
			sum := sha256.Sum256(c.Raw)
			if hex.EncodeToString(sum[:]) == target {
				targetCert = c
			}
		}
		removed, serial, err := transportTrust.WithdrawIf(target, func(remaining []*x509.Certificate) (bool, string) {
			// anchorWithdrawGate takes the whole set and skips the target itself, so hand it the set as it
			// stands at this instant: what would remain, plus the one being removed.
			ok, verdict := anchorWithdrawGate(config, tenantID, target,
				append(append([]*x509.Certificate{}, remaining...), targetCert), known, distributionSerial)
			return ok, verdict.Text
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfof("transport_trust_certificate_withdrawn subject=%q sha256=%s serial=%d", removed.Subject.CommonName, target, serial)
		if record != nil {
			record(r, "transport_trust_certificate_withdrawn", target, "a certificate was withdrawn from what devices trust",
				map[string]any{"subject": removed.Subject.CommonName, "serial": serial})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_transport_trust_anchors.v1",
			"withdrawn":      removed.Subject.CommonName, "sha256": target, "serial": serial,
			"note": "Devices drop it when they next take the distribution; ones holding it meanwhile merely trust one certificate more than needed. Adding it back is a single action if this turns out to be premature.",
		})
	}))

	// The other side of the handshake: the CAs device client certificates are verified against. Retiring one
	// is gated on OBSERVED use — a CA some device still chains to cannot be removed, and the last CA never
	// can. Adding one is the safe direction (a rotation's first step).
	//
	// INVARIANT this set must hold: devices present their certificate as a BARE LEAF, so the leaf's DIRECT
	// issuer must itself be an anchor here. An intermediate's root is not a substitute — replace the issuing
	// CA with "just the root" and every device that leaf chains through the intermediate is refused with
	// unknown_ca, exactly as if the CA had been retired.
	// ★★ RETIRED (2026-08-18, operator decision). This registered a device-trust CA and recorded NO OWNER, so
	// the deployment could hold a CA belonging to nobody — and the certificate screen, having no owner to read,
	// took it for the deployment's own material and listed it to every tenant. Measured as one tenant's
	// administrator: "CN=Probe3 Device CA, O=Bootstrap Probe 3", another tenant's.
	//
	// "Trust that belongs to nobody" does not fit the admission rule either: the tenant is resolved from the
	// ISSUING CA, so a device admitted through an unowned CA resolves to no tenant at all.
	//
	// POST /admin/tenant-cas is the one route: it adds the CA to the trust store AND registers the owner, and a
	// tenant's own administrator can call it for their own tenant. Answered rather than deleted, because a
	// caller that used to succeed here deserves to be told where the act moved to — a 404 would read as a
	// deployment fault.
	mux.HandleFunc("POST /admin/device-client-cas", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusGone, fmt.Errorf(
			"this route is retired: it registered a device-trust CA without recording which tenant it belongs to, "+
				"and a CA belonging to nobody admits devices that resolve to no tenant. Use POST /admin/tenant-cas, "+
				"which records the owner — a tenant's own administrator may call it for their own tenant"))
	}))
	mux.HandleFunc("DELETE /admin/device-client-cas/{sha256}", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		if deviceClientCAs == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("the device-trust CA set on this node is fixed at startup (-device-client-ca-store is not configured)"))
			return
		}
		target := strings.ToLower(strings.TrimSpace(r.PathValue("sha256")))
		if ok, verdict := deviceClientCARetireGate(config, tenantID, target); !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("retirement refused: %s", verdict.Text))
			return
		}
		removed, _, err := deviceClientCAs.Withdraw(target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfof("device_client_ca_retired subject=%q sha256=%s", removed.Subject.CommonName, target)
		if record != nil {
			record(r, "device_client_ca_retired", target, "a CA no observed device chains to was retired from device trust",
				map[string]any{"subject": removed.Subject.CommonName})
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_client_cas.v1",
			"retired": removed.Subject.CommonName, "sha256": target,
			"note": "New handshakes verify against the reduced set immediately; established connections are untouched. Adding it back is a single action."})
	}))

	// An operator asserting that an identity holds an anchor by other means. Per identity and per anchor,
	// recorded with who said it, because it is a claim about a deployment rather than an observation of one —
	// and a claim that turns out to be wrong strands that device.
	mux.HandleFunc("POST /admin/transport-trust-anchors/{sha256}/acknowledge", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ THE ASSERTION HAS TO BE WHERE THE JUDGEMENT IS. An acknowledgement is what OPENS the
		// withdrawal gate, and the withdrawal is authored on the control plane. Recorded on an Edge it
		// counts towards nothing: the operator asserts that a device holds the certificate, the screen says
		// so, and the withdrawal on the control plane still refuses because it never saw the claim.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL,
			"an acknowledgement that a device holds a certificate") {
			return
		}
		var req struct {
			Identity string `json:"identity"`
			Reason   string `json:"reason"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode acknowledgement: %w", err))
			return
		}
		by := ""
		if identity, ok := adminIdentityFromRequest(r); ok {
			by = strings.TrimSpace(identity.PrincipalLabel)
			if by == "" {
				by = identity.PrincipalID
			}
		}
		if err := transportAnchorAcks.Acknowledge(r.PathValue("sha256"), req.Identity, req.Reason, by, time.Now()); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfof("transport_anchor_acknowledged sha256=%q identity=%q by=%q reason=%q",
			r.PathValue("sha256"), strings.TrimSpace(req.Identity), by, strings.TrimSpace(req.Reason))
		// An operator asserting that a device holds a certificate is what OPENS the withdrawal gate — the
		// judgement that can strand a fleet. It was written to the process log and to no audit trail, so the
		// decision existed but its author did not.
		record(r, "transport_trust_acknowledged", r.PathValue("sha256"),
			"An operator asserted that a device holds this certificate, which counts towards allowing a withdrawal.",
			map[string]any{
				"identity":        strings.TrimSpace(req.Identity),
				"acknowledged_by": by,
				"stated_reason":   strings.TrimSpace(req.Reason),
			})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": transportAnchorAckSchemaVersion, "acknowledged": true,
			"identity": strings.TrimSpace(req.Identity), "acknowledged_by": by,
			"note": "Recorded as an operator's assertion, not as a device report. It counts towards the withdrawal decision and is shown separately from what devices said themselves.",
		})
	}))
	mux.HandleFunc("DELETE /admin/transport-trust-anchors/{sha256}/acknowledge/{identity}", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		// Taking an assertion back belongs beside making it — on the node that judges the withdrawal.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL,
			"an acknowledgement that a device holds a certificate") {
			return
		}
		if err := transportAnchorAcks.Withdraw(r.PathValue("sha256"), r.PathValue("identity")); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logInfof("transport_anchor_acknowledgement_withdrawn sha256=%q identity=%q", r.PathValue("sha256"), r.PathValue("identity"))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": transportAnchorAckSchemaVersion, "withdrawn": true})
	}))
}

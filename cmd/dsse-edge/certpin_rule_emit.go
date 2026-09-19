package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type certPinRuleWriteError struct {
	stage string
	err   error
}

func (e *certPinRuleWriteError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *certPinRuleWriteError) Unwrap() error { return e.err }
func certPinWriteStage(err error) string {
	var failure *certPinRuleWriteError
	if errors.As(err, &failure) {
		return failure.stage
	}
	return "bypass_rule"
}

// emitCertPinBypassRule materializes an admin-approved cert-pinning candidate as a first-class, tagged Egress
// BYPASS rule (Any → <host> ⇒ allow × bypass), so a pinned-site bypass is authored intent the operator can see,
// toggle, and delete in the Egress view — not an opaque entry derived from the candidate store (Phase C of the
// unified policy model). The rule resolves through a catalog endpoint created for the host (tagged cert_pin), so
// EgressBypassFQDNs folds it into the engine's raw-forward set exactly like any other authored bypass rule.
//
// Ids are deterministic (certpin-ep-<id> / certpin-rule-<id>) so re-materializing the same candidate is
// idempotent (Upsert replaces in place) rather than accumulating duplicates.
// The runtime's source of bypass intent is the authored rule, not candidate status.
func emitCertPinBypassRule(assets *assetcatalog.Store, rules *policyrule.Store, c policycandidate.Candidate) error {
	host, _, err := policycandidate.CertPinBypassTarget(c)
	if err != nil {
		return err
	}
	tenant := strings.TrimSpace(c.TenantID)
	if tenant == "" {
		return fmt.Errorf("cert-pin candidate %s has no tenant", c.CandidateID)
	}
	epID := "certpin-ep-" + c.CandidateID
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{
		ID: epID, TenantID: tenant, Alias: host, Kind: assetcatalog.KindNetwork,
		Address: host, Source: assetcatalog.SourceManual, Tags: []string{"cert_pin"},
	}); err != nil {
		return &certPinRuleWriteError{stage: "bypass_endpoint", err: err}
	}
	if _, err := rules.Upsert(policyrule.Rule{
		ID: "certpin-rule-" + c.CandidateID, TenantID: tenant, Plane: policyrule.PlaneEgress,
		Priority: systemBypassFloorPriority, Name: "Cert-pin bypass: " + host,
		Source: []string{policyrule.SubjectAny}, Destination: []string{epID},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
		Status: policyrule.StatusActive,
	}); err != nil {
		return &certPinRuleWriteError{stage: "bypass_rule", err: err}
	}
	return nil
}

package main

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// emitCertPinBypassRule materializes an admin-approved cert-pinning candidate as a first-class, tagged Egress
// BYPASS rule (Any → <host> ⇒ allow × bypass), so a pinned-site bypass is authored intent the operator can see,
// toggle, and delete in the Egress view — not an opaque entry derived from the candidate store (Phase C of the
// unified policy model). The rule resolves through a catalog endpoint created for the host (tagged cert_pin), so
// EgressBypassFQDNs folds it into the engine's raw-forward set exactly like any other authored bypass rule.
//
// Ids are deterministic (certpin-ep-<id> / certpin-rule-<id>) so re-materializing the same candidate is
// idempotent (Upsert replaces in place) rather than accumulating duplicates. The cert-pin bypass still also
// flows through the legacy materialized-hosts path for back-compat; the Egress aggregator dedups a host that now
// has an authored rule so it is shown once (as the rule).
func emitCertPinBypassRule(assets *assetcatalog.Store, rules *policyrule.Store, c policycandidate.Candidate) error {
	host := strings.TrimSpace(c.Host)
	if host == "" {
		host = strings.TrimSpace(c.SNI)
	}
	if host == "" {
		return fmt.Errorf("cert-pin candidate %s has no host/sni to bypass", c.CandidateID)
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
		return fmt.Errorf("create cert-pin endpoint for %s: %w", host, err)
	}
	if _, err := rules.Upsert(policyrule.Rule{
		ID: "certpin-rule-" + c.CandidateID, TenantID: tenant, Plane: policyrule.PlaneEgress,
		Priority: systemBypassFloorPriority, Name: "Cert-pin bypass: " + host,
		Source: []string{policyrule.SubjectAny}, Destination: []string{epID},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
		Status: policyrule.StatusActive,
	}); err != nil {
		return fmt.Errorf("create cert-pin bypass rule for %s: %w", host, err)
	}
	return nil
}

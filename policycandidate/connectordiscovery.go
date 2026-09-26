package policycandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// SourceConnectorDiscovered marks a candidate proposed by the connector route layer: a destination a tenant's
// connector DECLARES it can reach (reachable_routes) that is not yet published as a private_app. Discovery only
// PROPOSES — it never auto-publishes a Private App and never authorizes any user. An administrator must approve
// it (as web|tcp|network), which materializes a published Private App through the publish path. This is a
// separate lifecycle from the cert-pinning TLS decrypt-bypass path (SourceCertPinningDetection): approving a
// connector-discovered candidate publishes reachability, it never writes a decrypt-bypass rule.
const SourceConnectorDiscovered = "connector_discovered"

// ConnectorDiscoveredCandidateID derives a stable candidate id from the destination (+port) so repeated
// discovery of the same reachable route upserts the same candidate (refreshing evidence/last_observed) rather
// than duplicating, and an admin's earlier decision (approved/rejected/suppressed) on that destination sticks.
func ConnectorDiscoveredCandidateID(destination string, port int) string {
	key := normalizeHostValue(destination) + "|" + strconv.Itoa(port)
	sum := sha256.Sum256([]byte(key))
	return "connector-disc-" + hex.EncodeToString(sum[:10])
}

// connectorDiscoveryAttribution classifies how safe it is to act on a connector-discovered candidate from its
// destination (by design). A named FQDN (incl. a "*.suffix" wildcard) is a reviewable ENTITY -> "medium" /
// "review". A CIDR or a bare IP literal is not an entity -> "low" / "investigate_only" (the UI should
// de-emphasize publish CTAs for it). Advisory only — it gates nothing; approve is the publish gate.
func connectorDiscoveryAttribution(destination string) (confidence, suggestedAction string) {
	d := strings.TrimSpace(destination)
	if d == "" || strings.Contains(d, "/") || net.ParseIP(d) != nil {
		return "low", suggestedActionInvestigateOnly
	}
	return "medium", "review"
}

// ObserveConnectorDiscovered records a connector-discovered destination as a PENDING private-app candidate the
// first time, and refreshes attribution + last_observed (merging evidence) on subsequent observations. It NEVER
// publishes or allows anything — an administrator must approve to publish. An already-decided candidate
// (approved/rejected/suppressed/dismissed) keeps its status while its evidence is refreshed, so a prior admin
// decision is never silently reset to pending (fail-closed).
func (store *Store) ObserveConnectorDiscovered(ctx context.Context, tenantID, destination string, port int, publishProtocol, connectorID, site, namespace string, evidence []string, now time.Time) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	destination = normalizeHostValue(destination)
	if destination == "" {
		return Candidate{}, fmt.Errorf("destination is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observed := now.UTC().Format(time.RFC3339)
	id := ConnectorDiscoveredCandidateID(destination, port)

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(store, ctx, func(next *Store) (Candidate, error) {
			return next.ObserveConnectorDiscovered(ctx, tenantID, destination, port, publishProtocol, connectorID, site, namespace, evidence, now)
		})
	}

	cand := Candidate{
		CandidateID:             id,
		TenantID:                tenantID,
		Source:                  SourceConnectorDiscovered,
		CandidateType:           "private_app",
		ProposedAction:          "publish",
		Host:                    destination,
		Port:                    port,
		ServiceFamily:           "https",
		PublishProtocol:         strings.TrimSpace(publishProtocol),
		ObservedFromConnectorID: strings.TrimSpace(connectorID),
		ObservedFromSite:        strings.TrimSpace(site),
		Namespace:               strings.TrimSpace(namespace),
		Evidence:                append([]string(nil), evidence...),
		LastObserved:            &observed,
	}
	if existing, ok := store.candidates[tenantID][id]; ok {
		cand = existing
		cand.LastObserved = &observed
		if v := strings.TrimSpace(connectorID); v != "" {
			cand.ObservedFromConnectorID = v
		}
		if v := strings.TrimSpace(site); v != "" {
			cand.ObservedFromSite = v
		}
		if v := strings.TrimSpace(namespace); v != "" {
			cand.Namespace = v
		}
		if v := strings.TrimSpace(publishProtocol); v != "" {
			cand.PublishProtocol = v
		}
		cand.Evidence = normalizedStringList(append(append([]string(nil), cand.Evidence...), evidence...))
	}
	// Classify attribution from the destination each observation so it stays correct: a named FQDN -> medium,
	// a CIDR/raw-IP -> investigate_only.
	cand.Confidence, cand.SuggestedAction = connectorDiscoveryAttribution(cand.Host)
	normalized, err := normalizeObservation(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return Candidate{}, err
	}
	return copyCandidate(normalized), nil
}

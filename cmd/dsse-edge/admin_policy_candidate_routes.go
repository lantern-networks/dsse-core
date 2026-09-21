package main

// Policy-candidate workflow admin routes — candidate CRUD/review, materialize (incl. the
// cert-pin decrypt-bypass path), manual cert-pin-bypass, connector-discovery refresh, and
// approve-private-app (the Slice 4 publish path) — moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Only mechanical change:
// config.ApplyMaterializedCertPinBypass / config.AssetStore / config.RuleStore became the
// applyMaterializedCertPinBypass / assetStore / ruleStore parameters.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func registerPolicyCandidateRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, policyStore policy.RuntimeStore, policyCandidateStore policycandidate.RuntimeStore, applicationCatalogStore appcatalog.RuntimeStore, registry connectorRegistryStore, assetStore *assetcatalog.Store, ruleStore *policyrule.Store, applyMaterializedCertPinBypass func(tenantID string), configSourceURL string) {
	// Serialize this server's candidate administration across its dependent writes.
	// Other nodes and the general rule editor still require their own coordination.
	var candidateWrites sync.Mutex
	recordCandidate := func(r *http.Request, event string, c policycandidate.Candidate, now time.Time, outcome policyCandidateAuditOutcome) {
		outcome.actor = auditActorPrincipal(r)
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminPolicyCandidateAuditLog(event, c, evaluator, now, outcome), now)
	}
	partial := func(w http.ResponseWriter, r *http.Request, event string, c policycandidate.Candidate, now time.Time, stage, operation string) {
		recordCandidate(r, event, c, now, policyCandidateAuditOutcome{result: "partial", failedStage: stage, ruleOperation: operation})
		message := "Bypass registration is incomplete. Candidate information was saved, but a later save could not be confirmed. Reload and retry; an existing bypass may still be active."
		if operation == "delete" {
			message = "Candidate review was saved, but bypass rule removal could not be confirmed. The bypass may remain active. Check Internet Access and retry removal."
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": message, "partial": true, "failed_stage": stage, "candidate_id": c.CandidateID, "candidate_status": c.Status})
	}
	mux.HandleFunc("GET /admin/policy-candidates", adminEndpoint("admin.policy_candidates.read", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		options := policycandidate.ListOptions{
			Status:        strings.TrimSpace(r.URL.Query().Get("status")),
			CandidateType: strings.TrimSpace(r.URL.Query().Get("candidate_type")),
			Limit:         boundedIntQuery(r.URL.Query().Get("limit"), 100, 1, 1000),
		}
		result, err := policyCandidateStore.List(r.Context(), adminTenantIDFromRequest(r), options)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		rows := make([]policyCandidateView, 0, len(result.Candidates))
		for _, candidate := range result.Candidates {
			rows = append(rows, policyCandidateForView(candidate))
		}
		writeJSON(w, http.StatusOK, map[string]any{"candidates": rows, "count": result.Count, "limit": result.Limit, "tenant_id": adminTenantIDFromRequest(r)})
	}))
	mux.HandleFunc("GET /admin/policy-candidates/{candidate_id}", adminEndpoint("admin.policy_candidates.read", func(w http.ResponseWriter, r *http.Request) {
		candidate, found, err := policyCandidateStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id"))
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy candidate %s is absent", r.PathValue("candidate_id")))
			return
		}
		writeJSON(w, http.StatusOK, candidate)
	}))
	mux.HandleFunc("POST /admin/policy-candidates", adminEndpoint("admin.policy_candidates.write", func(w http.ResponseWriter, r *http.Request) {
		var candidate policycandidate.Candidate
		if err := decodeLimitedJSONBody(w, r, &candidate, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode policy candidate: %w", err))
			return
		}
		now := time.Now()
		candidateWrites.Lock()
		defer candidateWrites.Unlock()
		created, err := policyCandidateStore.Upsert(r.Context(), candidate, adminTenantIDFromRequest(r), now)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		recordCandidate(r, "admin_policy_candidate_upserted", created, now, policyCandidateAuditOutcome{result: "success"})
		writeJSON(w, http.StatusOK, created)
	}))
	mux.HandleFunc("POST /admin/policy-candidates/{candidate_id}/review", adminEndpoint("admin.policy_candidates.review", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		var review policycandidate.ReviewRequest
		if err := decodeLimitedJSONBody(w, r, &review, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode policy candidate review: %w", err))
			return
		}
		now := time.Now()
		candidateWrites.Lock()
		defer candidateWrites.Unlock()
		// cp-authored-conditional: removing an existing cert-pin rule must be authored at the CP.
		if ruleStore != nil {
			if c, found, err := policyCandidateStore.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id")); err != nil {
				writePolicyCandidateError(w, err)
				return
			} else if found && c.Source == policycandidate.SourceCertPinningDetection {
				if _, exists := ruleStore.Get(c.TenantID, "certpin-rule-"+c.CandidateID); exists && configWriteRejectedWhenSourced(w, configSourceURL, "removing a pinned-certificate bypass") {
					return
				}
			}
		}
		reviewed, found, err := policyCandidateStore.Review(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id"), review, now)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy candidate %s is absent", r.PathValue("candidate_id")))
			return
		}
		// Forward lifecycle sync: a cert-pin bypass's single source is its emitted Egress rule, so moving the
		// candidate away from materialized (suppress/reject/dismiss a live bypass) must DELETE that rule — only
		// then does the host get decrypted again. Then rebuild the bypass set (now without the rule).
		if reviewed.Source == policycandidate.SourceCertPinningDetection && reviewed.Status != "materialized" && ruleStore != nil {
			if _, err := ruleStore.DeleteContext(r.Context(), adminTenantIDFromRequest(r), "certpin-rule-"+reviewed.CandidateID); err != nil {
				partial(w, r, "admin_policy_candidate_reviewed", reviewed, now, "bypass_rule_removal", "delete")
				return
			}
		}
		if applyMaterializedCertPinBypass != nil {
			applyMaterializedCertPinBypass(adminTenantIDFromRequest(r))
		}
		recordCandidate(r, "admin_policy_candidate_reviewed", reviewed, now, policyCandidateAuditOutcome{result: "success", ruleOperation: "delete", ruleConfirmed: reviewed.Source == policycandidate.SourceCertPinningDetection && ruleStore != nil, applied: applyMaterializedCertPinBypass != nil})
		writeJSON(w, http.StatusOK, reviewed)
	}))
	mux.HandleFunc("POST /admin/policy-candidates/{candidate_id}/materialize", adminEndpoint("admin.policy_candidates.review", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		concrete, ok := policyCandidateStore.(*policycandidate.Store)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("policy candidate store does not support materialize"))
			return
		}
		now := time.Now()
		// An unattributed (investigate_only) cert-pin candidate is no-decrypt-gated: it materializes only with
		// an explicit high-risk override in the body ({"allow_high_risk": true}). Body is optional (absent =
		// override off) for attributed candidates, which are unaffected.
		var materializeReq struct {
			AllowHighRisk bool `json:"allow_high_risk"`
		}
		if r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &materializeReq, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode materialize request: %w", err))
				return
			}
		}
		// ★ Same reasoning as POST /admin/cert-pin-bypass below, reached from the other direction: materializing a
		// DETECTED cert-pin candidate emits the same Egress bypass rule, so on a config-pulling Edge it is the
		// same adoption that expires at the next poll.
		//
		// Checked BEFORE the transition, which required looking the candidate up first. Guarding after
		// Materialize would flip the candidate to materialized and THEN refuse — leaving the console showing an
		// adoption with nothing behind it, which is worse than either outcome it is choosing between.
		// cp-authored-conditional: this route is guarded only for cert-pin candidates. The same route also
		// materializes allow-policy and private-app candidates, which stay Edge-local, so it must NOT go in the
		// console's CP_AUTHORED_WRITES table — sending every materialize to the control plane would 404, because
		// candidates are observations of traffic and only an Edge has them. The console adopts a cert-pin
		// candidate by posting its host to /admin/cert-pin-bypass instead, which IS CP-authored and is
		// self-contained. This guard is what stops an API caller from taking the old path.
		candidateWrites.Lock()
		defer candidateWrites.Unlock()
		if existing, ok, gerr := concrete.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id")); gerr == nil && ok &&
			existing.Source == policycandidate.SourceCertPinningDetection &&
			configWriteRejectedWhenSourced(w, configSourceURL, "adopting a pinned-certificate bypass") {
			return
		}
		if c, found, err := concrete.Get(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id")); err == nil && found && c.Source == policycandidate.SourceCertPinningDetection && (assetStore == nil || ruleStore == nil) {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("bypass rule storage is unavailable"))
			return
		}
		materialized, found, err := concrete.Materialize(r.Context(), adminTenantIDFromRequest(r), r.PathValue("candidate_id"), materializeReq.AllowHighRisk, now)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy candidate %s is absent", r.PathValue("candidate_id")))
			return
		}
		// Unified model (Phase C): a materialized cert-pin candidate also becomes a first-class, tagged Egress
		// bypass rule (Any → <host> ⇒ allow × bypass) so the pinned-site bypass is authored intent the operator
		// sees/toggles/deletes in the Egress view, not just an opaque candidate-store entry. Emitted BEFORE the
		// re-apply below; candidate status alone does not bypass traffic.
		if materialized.Source == policycandidate.SourceCertPinningDetection && assetStore != nil && ruleStore != nil {
			if err := emitCertPinBypassRuleContext(r.Context(), assetStore, ruleStore, materialized); err != nil {
				partial(w, r, "admin_policy_candidate_materialized", materialized, now, certPinWriteStage(err), "upsert")
				return
			}
		}
		// Apply the bypass NOW (not just status-flip): rebuild the interception engine's decrypt-bypass
		// set so the materialized host is actually raw-forwarded. This is the ONLY point traffic is
		// bypassed — detection/approval never bypass on their own.
		if applyMaterializedCertPinBypass != nil {
			applyMaterializedCertPinBypass(adminTenantIDFromRequest(r))
		}
		// Adopt an observed (allow-policy) candidate into explicit policy: materializing it inserts an allow
		// policy for its destination so the destination is now explicitly governed and keeps working after a
		// later switch to enforce. The runtime evaluator reads policyStore live, so it takes effect at once.
		if materialized.CandidateType == "allow_policy" {
			host := strings.TrimSpace(materialized.Host)
			if host == "" {
				host = strings.TrimSpace(materialized.SNI)
			}
			if host != "" {
				tenantID := adminTenantIDFromRequest(r)
				adopted := model.Policy{
					ID:         "adopted-" + materialized.CandidateID,
					TenantID:   tenantID,
					Name:       "Adopted from observation: " + host,
					Priority:   500,
					Status:     "active",
					Conditions: map[string]any{"fqdn": host},
					Action:     model.PolicyAction{Decision: "allow"},
				}
				if _, perr := policyStore.Upsert(r.Context(), adopted, tenantID, now); perr != nil {
					recordCandidate(r, "admin_policy_candidate_materialized", materialized, now, policyCandidateAuditOutcome{result: "partial", failedStage: "allow_policy"})
					writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Candidate adoption was saved, but allow-policy saving could not be confirmed. Reload and retry.", "partial": true, "failed_stage": "allow_policy", "candidate_id": materialized.CandidateID})
					return
				}
			}
		}
		recordCandidate(r, "admin_policy_candidate_materialized", materialized, now, policyCandidateAuditOutcome{result: "success", ruleOperation: "upsert", ruleConfirmed: materialized.Source == policycandidate.SourceCertPinningDetection, applied: applyMaterializedCertPinBypass != nil})
		writeJSON(w, http.StatusOK, materialized)
	}))
	// Manually add a known pinned site directly to the decrypt-bypass, without waiting for the detector to
	// surface it (there is no way to search for a not-yet-detected host, so an operator who already knows a
	// site pins its cert can register it here). This creates an approved operator candidate and runs it through
	// the SAME materialize path as a detected-then-adopted one — emitting a first-class Egress bypass rule — so
	// it appears in the same lists and is toggled/re-intercepted identically. Gated on admin.policy_candidates.
	// review (it makes a bypass live), and an explicit admin action, so it does not violate never-auto-bypass.
	// ★ CP-AUTHORED. This route's durable product is an Egress bypass RULE, and rules are replaced wholesale by
	// every config bundle (config_bundle_sync ReplaceAll). Written on a config-pulling Edge it returns 200, the
	// pinned site starts working, and the next poll deletes it — the adoption expires while the console still
	// shows the candidate as adopted, because only the RULE was erased and the candidate is Edge-local.
	//
	// The route is self-contained (a host is all it needs), so the control plane can run exactly this handler
	// and the rule then reaches every Edge in the fleet, which is what an inspection bypass has to do: a site
	// that must not be decrypted must not be decrypted by whichever Edge the device happens to reach.
	mux.HandleFunc("POST /admin/cert-pin-bypass", adminEndpoint("admin.policy_candidates.review", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if configWriteRejectedWhenSourced(w, configSourceURL, "cert-pin bypass") {
			return
		}
		concrete, ok := policyCandidateStore.(*policycandidate.Store)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("policy candidate store does not support manual cert-pin bypass"))
			return
		}
		var req struct {
			Host string `json:"host"`
			// ★ Present because this route is now the ONLY way to adopt a cert-pin bypass on a config-pulling
			// deployment. An unattributed candidate — a raw IP with no SNI — is high risk precisely because
			// nobody can say what is being un-inspected, and the decision to do it anyway must remain explicit
			// and recorded. Moving the authoring to the control plane must not quietly drop the gate that made
			// the operator own that choice.
			AllowHighRisk bool `json:"allow_high_risk"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode cert-pin bypass request: %w", err))
			return
		}
		now := time.Now()
		tenantID := adminTenantIDFromRequest(r)
		candidateWrites.Lock()
		defer candidateWrites.Unlock()
		if assetStore == nil || ruleStore == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("bypass rule storage is unavailable"))
			return
		}
		approved, err := concrete.AddManualCertPinBypass(r.Context(), tenantID, req.Host, now)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		materialized, found, err := concrete.Materialize(r.Context(), tenantID, approved.CandidateID, req.AllowHighRisk, now)
		if err != nil {
			if errors.Is(err, policycandidate.ErrPersistence) {
				partial(w, r, "admin_cert_pin_bypass_added", approved, now, "candidate_materialization", "upsert")
			} else {
				writePolicyCandidateError(w, err)
			}
			return
		}
		if !found {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("cert-pin candidate %s vanished before materialize", approved.CandidateID))
			return
		}
		if assetStore != nil && ruleStore != nil {
			if err := emitCertPinBypassRuleContext(r.Context(), assetStore, ruleStore, materialized); err != nil {
				partial(w, r, "admin_cert_pin_bypass_added", materialized, now, certPinWriteStage(err), "upsert")
				return
			}
		}
		if applyMaterializedCertPinBypass != nil {
			applyMaterializedCertPinBypass(tenantID)
		}
		recordCandidate(r, "admin_cert_pin_bypass_added", materialized, now, policyCandidateAuditOutcome{result: "success", ruleOperation: "upsert", ruleConfirmed: true, applied: applyMaterializedCertPinBypass != nil})
		writeJSON(w, http.StatusOK, materialized)
	}))
	// Connector UX Slice 4: refresh connector-discovered candidates. Derives candidates from the
	// reachable_routes − published diff (destinations a connector DECLARES it can reach that are not yet a
	// published Private App) and writes each as a PENDING candidate. It NEVER auto-publishes or auto-allows —
	// the only effect is proposing pending review items (fail-closed). Tenant-scoped + secret-safe (reachable
	// route domains are already non-secret; private base URLs/secrets are never touched).
	mux.HandleFunc("POST /admin/connector-discovery/refresh", adminEndpoint("admin.policy_candidates.write", func(w http.ResponseWriter, r *http.Request) {
		concrete, ok := policyCandidateStore.(*policycandidate.Store)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("policy candidate store does not support connector discovery"))
			return
		}
		now := time.Now()
		tenantID := adminTenantIDFromRequest(r)
		discovered, err := refreshConnectorDiscoveredCandidates(r.Context(), registry, applicationCatalogStore, concrete, tenantID, now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "connector_discovery_refresh.v1",
			"candidates":     discovered,
			"count":          len(discovered),
		})
	}))
	// Connector UX Slice 4: approve a connector-discovered candidate INTO a published Private App. This is the
	// SEPARATE materialize path from the cert-pin TLS decrypt-bypass: it calls the Slice 2 publish path
	// (applicationCatalogStore upsert with published=true) to create REACHABILITY, then promotes the candidate
	// out of pending (status=approved). It must never run on a cert-pin candidate (that uses /materialize) and
	// it never touches the decrypt-bypass rule store — so an admin can never accidentally create a TLS bypass
	// here. Published != Allow: the response carries the same review block, so a freshly published app still
	// authorizes nobody until a policy is bound (fail-closed).
	mux.HandleFunc("POST /admin/policy-candidates/{candidate_id}/approve-private-app", adminEndpoint("admin.policy_candidates.review", func(w http.ResponseWriter, r *http.Request) {
		tenantID := adminTenantIDFromRequest(r)
		candidateID := strings.TrimSpace(r.PathValue("candidate_id"))
		var body struct {
			PublishProtocol  string `json:"publish_protocol"`
			ApplicationID    string `json:"application_id"`
			Name             string `json:"name"`
			ConnectorGroupID string `json:"connector_group_id"`
			DestinationPort  int    `json:"destination_port"`
			ReviewReasonCode string `json:"review_reason_code"`
		}
		if r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode approve-private-app request: %w", err))
				return
			}
		}
		now := time.Now()
		candidateWrites.Lock()
		defer candidateWrites.Unlock()
		cand, found, err := policyCandidateStore.Get(r.Context(), tenantID, candidateID)
		if err != nil {
			writePolicyCandidateError(w, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("policy candidate %s is absent", candidateID))
			return
		}
		// Fail-closed source guard: this publish path is ONLY for connector-discovered candidates. A cert-pin
		// (decrypt-bypass) candidate must go through /materialize so it can never be turned into a published app
		// by mistake — and a connector-discovered candidate can never become a TLS bypass here.
		if cand.Source != policycandidate.SourceConnectorDiscovered {
			writeError(w, http.StatusBadRequest, fmt.Errorf("approve-private-app only applies to connector-discovered candidates (source=%s)", cand.Source))
			return
		}
		if cand.Status != "pending" {
			writeError(w, http.StatusConflict, fmt.Errorf("candidate %s is not pending (status=%s)", candidateID, cand.Status))
			return
		}
		destination := strings.TrimSpace(cand.Host)
		if destination == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("candidate %s has no destination to publish", candidateID))
			return
		}
		publishProtocol := strings.TrimSpace(body.PublishProtocol)
		if publishProtocol == "" {
			publishProtocol = strings.TrimSpace(cand.PublishProtocol)
		}
		if publishProtocol == "" {
			publishProtocol = "web"
		}
		applicationID := strings.TrimSpace(body.ApplicationID)
		if applicationID == "" {
			applicationID = candidateID // stable, slash-free
		}
		connectorGroup := strings.TrimSpace(body.ConnectorGroupID)
		if connectorGroup == "" {
			connectorGroup = strings.TrimSpace(cand.ObservedFromSite)
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			name = destination
		}
		port := body.DestinationPort
		if port == 0 {
			port = cand.Port
		}
		entry := appcatalog.Entry{
			ApplicationID:    applicationID,
			TenantID:         tenantID,
			Name:             name,
			ApplicationType:  "private_app",
			Destination:      destination,
			DestinationPort:  port,
			PublishProtocol:  publishProtocol,
			ConnectorGroupID: connectorGroup,
			Published:        true,
			Status:           "active",
		}
		created, err := applicationCatalogStore.Upsert(r.Context(), entry, tenantID, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Promote the candidate out of pending (approved). Separate from cert-pin: no Materialize call and no
		// decrypt-bypass rule store write here.
		reviewReason := strings.TrimSpace(body.ReviewReasonCode)
		if reviewReason == "" {
			reviewReason = "connector_candidate_published"
		}
		reviewed, reviewFound, rerr := policyCandidateStore.Review(r.Context(), tenantID, candidateID, policycandidate.ReviewRequest{Decision: "approved", ReviewReasonCode: reviewReason}, now)
		// Reachability was saved independently. Do not claim candidate approval
		// or discard the confirmed application when the second store fails.
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, applicationAuditWithActor(r, adminApplicationPublishAuditLog(created, evaluator, now, true)), now)
		if rerr != nil || !reviewFound {
			record := adminPolicyCandidateAuditLog("admin_policy_candidate_reviewed", cand, evaluator, now, policyCandidateAuditOutcome{actor: auditActorPrincipal(r), result: "partial", failedStage: "candidate_review"})
			record.Metadata["candidate_saved"] = false
			record.Metadata["application_saved"] = true
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, record, now)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Application publication was saved, but candidate review could not be confirmed. Reload and reconcile the application before retrying.", "partial": true, "failed_stage": "candidate_review", "candidate_id": candidateID, "application_id": created.ApplicationID})
			return
		}
		recordCandidate(r, "admin_policy_candidate_reviewed", reviewed, now, policyCandidateAuditOutcome{result: "success"})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "connector_candidate_publish.v1",
			"application":    created,
			"candidate":      reviewed,
			"review":         applicationPublishReview(created, evaluator, policyStore),
		})
	}))
}

// Storage details remain in the server, not in the response or common audit.
func writePolicyCandidateError(w http.ResponseWriter, err error) {
	if errors.Is(err, policycandidate.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("candidate state is unavailable; reload and retry"))
		return
	}
	if errors.Is(err, policycandidate.ErrPersistence) {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("candidate save could not be confirmed; reload and retry"))
		return
	}
	writeError(w, http.StatusBadRequest, err)
}

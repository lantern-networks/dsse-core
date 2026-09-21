package main

// DLP admin routes — entitlements, DLP Policy objects (S5), egress DLP rules, findings,
// custom classifiers, the false-positive allowlist, and EDM fingerprints — moved verbatim
// out of newServerWithConfig (Phase 2 route-registration split). Parameter names match the
// constructor's locals so the handler bodies are untouched.

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/hotstore"
	inspection "github.com/lantern-networks/dsse-core/inspection"
	"github.com/lantern-networks/dsse-core/model"
)

func registerDLPRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, evaluator decision.Evaluator, adminHotStore hotstore.Store, dlpRuleStore *dlpRuleRuntimeStore, dlpAllowlistStore *dlpAllowlistRuntimeStore, dlpPolicyObjects *dlpPolicyObjectStore, dlpFingerprintStore *dlpFingerprintRuntimeStore, dlpClassifierStore *dlpClassifierRuntimeStore, entitlementStore *entitlementStore, inspectionEvents *inspection.Store, configSourceURL string) {
	mux.HandleFunc("GET /admin/entitlements", adminEndpoint("admin.config.read", func(w http.ResponseWriter, r *http.Request) {
		if err := entitlementStore.RefreshShared(); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("entitlements are unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"features": entitlementStore.FeaturesForTenant(adminTenantIDFromRequest(r))})
	}))
	// ★ A TENANT COULD GRANT ITSELF PAID FEATURES (2026-08-15). Entitlements are the licensing boundary, and
	// this route was gated on admin.config.write — which every ordinary tenant `admin` holds. Reproduced on the
	// lab: a customer's own administrator granted its tenant `dlp` and got 200. The party a limit constrains
	// was the party who could lift it. admin.quota.write is the operator permission the seat-allocation routes
	// already use for exactly this reason.
	mux.HandleFunc("PUT /admin/entitlements", adminEndpoint("admin.quota.write", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Features map[string]bool `json:"features"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode entitlements: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		// ★ AN UNKNOWN FEATURE NAME USED TO BE ACCEPTED AND THEN IGNORED (2026-08-15). SetFeature stores any
		// string, FeaturesForTenant lists only the known ones, and nothing validated in between — so granting
		// "decrypt_all" answered 200, wrote a row nobody reads, and returned a body that did not contain it.
		// The operator's evidence that the grant worked was a response quietly missing the thing they granted.
		// Measured while standing up a second tenant. The comment on knownFeatures already said "validation".
		for f := range body.Features {
			if !slices.Contains(knownFeatures, f) {
				writeError(w, http.StatusBadRequest, fmt.Errorf(
					"%q is not a feature this build can gate — known features: %s", f, strings.Join(knownFeatures, ", ")))
				return
			}
		}
		if err := entitlementStore.SetFeaturesContext(r.Context(), tenant, body.Features); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("entitlement persistence could not be confirmed"))
			return
		}
		logInfof("entitlements_applied_by_admin tenant=%s features=%v", tenant, body.Features)
		writeJSON(w, http.StatusOK, map[string]any{"features": entitlementStore.FeaturesForTenant(tenant)})
	}))
	// dlpFeatureGate rejects a DLP config write when the tenant is not licensed for DLP (the paid-feature gate).
	dlpFeatureGate := func(w http.ResponseWriter, r *http.Request) bool {
		if err := entitlementStore.RefreshShared(); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("entitlements are unavailable"))
			return true
		}
		if !entitlementStore.Entitled(adminTenantIDFromRequest(r), featureDLP) {
			writeError(w, http.StatusForbidden, fmt.Errorf("DLP is not licensed for this tenant"))
			return true
		}
		return false
	}
	// (DLP device risk is configured per DLP Policy via device_risk conditions on /admin/dlp-policies — no global
	// threshold endpoint; the composite conditions supersede the raw count.)
	// DLP Policies (S5): the reusable named DLP Policy objects an egress rule references by id (detectors + action
	// + instance scope + device-risk conditions). CRUD: GET lists, POST creates/updates (id optional), DELETE by id.
	mux.HandleFunc("GET /admin/dlp-policies", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshDLPStores(w, dlpPolicyObjects) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": dlpPolicyObjects.List(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/dlp-policies", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP policies") || dlpFeatureGate(w, r) {
			return
		}
		var obj model.DLPPolicyObject
		if err := decodeLimitedJSONBody(w, r, &obj, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dlp policy: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		obj.TenantID = tenant
		if strings.TrimSpace(obj.Name) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
			return
		}
		if !refreshDLPStores(w, dlpClassifierStore, dlpFingerprintStore) {
			return
		}
		if err := validateDLPPolicyObject(obj, dlpClassifierStore.ClassifierSetForTenant(tenant), dlpFingerprintStore.FingerprintSetForTenant(tenant)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(obj.ID) == "" {
			obj.ID = randomEdgeID("dlpp_", time.Now())
		}
		if strings.TrimSpace(obj.Status) == "" {
			obj.Status = "active"
		}
		if err := dlpPolicyObjects.UpsertContext(r.Context(), obj); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save DLP policy"))
			return
		}
		logInfof("dlp_policy_object_applied_by_admin tenant=%s id=%s name=%q identifiers=%d action=%s device_risk=%d", tenant, obj.ID, obj.Name, len(obj.Identifiers), obj.OnMatch, len(obj.DeviceRisk))
		writeJSON(w, http.StatusOK, map[string]any{"policy": obj, "policies": dlpPolicyObjects.List(tenant)})
	}))
	mux.HandleFunc("DELETE /admin/dlp-policies", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP policies") {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("id query parameter is required"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		removed, err := dlpPolicyObjects.DeleteContext(r.Context(), tenant, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("could not delete DLP policy"))
			return
		}
		logInfof("dlp_policy_object_removed_by_admin tenant=%s id=%s removed=%t", tenant, id, removed)
		writeJSON(w, http.StatusOK, map[string]any{"removed": removed, "policies": dlpPolicyObjects.List(tenant)})
	}))
	// (The former tenant-wide GET/POST /admin/dlp-policy back-compat API was removed: the data path never read
	// its store, so it accepted config that silently did nothing. DLP is configured via /admin/dlp-rules and
	// named DLP Policy objects only — per-destination, surfaced as a dlp_inspect directive.)
	// DLP rules (the egress-rule option): read/hot-apply per-tenant model.DLPRules (selector + identifiers ->
	// on_match). Overlaid onto the bundle so the evaluator surfaces a dlp_inspect directive per destination.
	mux.HandleFunc("GET /admin/dlp-rules", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"rules": dlpRuleStore.RulesForTenant(adminTenantIDFromRequest(r))})
	}))
	// DLP findings (VISIBILITY, V-slice): the operator-facing list of what DLP has DETECTED — the dlp_match
	// DLP findings (dlp_match) for the tenant, NON-SECRET (identifier types + counts + action + destination +
	// who/where + time, never the raw value). Read-only; drives the Console "DLP findings" view. Findings only —
	// non-scannable "did-not-scan" content is not logged at all. Optional filters: ?identifier=, ?action=,
	// ?severity=, ?since=<RFC3339>, ?limit= (default 200). Aggregated summary included. (?include_skipped is
	// accepted but a no-op, kept for backward compatibility.)
	mux.HandleFunc("GET /admin/dlp-findings", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		q := r.URL.Query()
		fIdent := strings.TrimSpace(q.Get("identifier"))
		fAction := strings.TrimSpace(q.Get("action"))
		fSeverity := strings.TrimSpace(q.Get("severity"))
		fSince := strings.TrimSpace(q.Get("since"))
		limit := 200
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 2000 {
			limit = v
		}
		// S2 (event_log_design.md): serve DLP Findings from the AGGREGATION hot store — fleet-wide and
		// restart-safe — not a single Edge's in-memory cache. inspection_events is shipped to the control plane
		// (defaultAuditShipStreams), so on the CP this is the whole fleet's findings. Search returns newest-first,
		// so a bounded recent-window scan captures the latest; the loop below filters to DLP finding types and
		// re-caps to the display limit. Fall back to the in-memory store only when no hot store is wired (a
		// standalone Edge). An empty (non-error) hot-store result is authoritative — it does NOT fall back.
		var events []model.InspectionEvent
		servedFromHotStore := false
		if adminHotStore != nil {
			from := time.Now().Add(-dlpFindingsHotStoreWindow)
			res, err := adminHotStore.Search(r.Context(), hotstore.SearchQuery{TenantID: tenant, Stream: dlpFindingsHotStoreStream, From: &from, Limit: dlpFindingsHotStoreScan})
			if err != nil {
				// A local cache cannot stand in for an unavailable fleet-wide result.
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("DLP findings are temporarily unavailable; retry the request"))
				return
			}
			servedFromHotStore = true
			for _, row := range res.Rows {
				if ev, ok := inspectionEventFromRow(row); ok {
					events = append(events, ev)
				}
			}
		}
		if !servedFromHotStore && inspectionEvents != nil {
			if err := inspectionEvents.RefreshShared(); err != nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("DLP findings are temporarily unavailable; retry the request"))
				return
			}
			events = inspectionEvents.ListByTenant(tenant)
		}
		findings := make([]map[string]any, 0, len(events))
		byIdentifier := map[string]int{}
		byAction := map[string]int{}
		byDestination := map[string]int{}
		blocked := 0
		// DLP Findings are dlp_match ONLY. Non-scannable content ("did-not-scan") is no longer logged at all — DLP
		// runs only where a policy enables it, and a per-flow "not scanned" record is pure noise; the flow itself
		// is in the access stream. So there is no skipped list/count/rollup to reconcile.
		for _, ev := range events {
			ft := derefStringPtr(ev.FindingType)
			if ft != "dlp_match" {
				continue // findings only
			}
			if fSince != "" && ev.Timestamp < fSince {
				continue
			}
			if fSeverity != "" && !strings.EqualFold(derefStringPtr(ev.Severity), fSeverity) {
				continue
			}
			action := stringMetadata(ev.Metadata, "dlp_action")
			if fAction != "" && !strings.EqualFold(action, fAction) {
				continue
			}
			idents := stringSliceMetadata(ev.Metadata, "dlp_identifier_types")
			if fIdent != "" {
				matched := false
				for _, id := range idents {
					if strings.EqualFold(id, fIdent) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
			destination := stringMetadata(ev.Metadata, "dlp_destination")
			row := map[string]any{
				"id":               ev.ID,
				"timestamp":        ev.Timestamp,
				"finding_type":     ft,
				"severity":         derefStringPtr(ev.Severity),
				"action":           action,
				"identifier_types": idents,
				"findings":         ev.Metadata["dlp_findings"],
				"destination":      destination,
				// Source (who sent it): corporate identity, device, the OS/corporate user, originating app, the
				// signed-in account, and source IP — whichever the flow carried (device-only steered flows have no
				// corporate session, so user_id may be empty but source_app / source_ip / account still identify it).
				"user_id":            derefStringPtr(ev.UserID),
				"device_id":          derefStringPtr(ev.DeviceID),
				"corporate_user":     stringMetadata(ev.Metadata, "dlp_corporate_user"),
				"source_app":         stringMetadata(ev.Metadata, "dlp_source_app"),
				"account":            stringMetadata(ev.Metadata, "dlp_account"),
				"source_ip":          stringMetadata(ev.Metadata, "dlp_source_ip"),
				"application_id":     derefStringPtr(ev.ApplicationID),
				"access_decision_id": derefStringPtr(ev.AccessDecisionID),
				"content_type":       stringMetadata(ev.Metadata, "request_content_type"),
				"instance_class":     stringMetadata(ev.Metadata, "dlp_instance_class"), // "" | corporate | personal
				"rule_id":            stringMetadata(ev.Metadata, "dlp_rule_id"),        // the rule that caught it (S3)
			}
			findings = append(findings, row)
			if ft == "dlp_match" {
				for _, id := range idents { // count findings per identifier type (event-level)
					byIdentifier[id]++
				}
				if action != "" {
					byAction[action]++
				}
				if destination != "" {
					byDestination[destination]++
				}
				if strings.EqualFold(action, "block") {
					blocked++
				}
			}
		}
		// Newest first, then cap.
		sort.Slice(findings, func(i, j int) bool { return findings[i]["timestamp"].(string) > findings[j]["timestamp"].(string) })
		total := len(findings)
		if len(findings) > limit {
			findings = findings[:limit]
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":        "admin_dlp_findings.v1",
			"tenant_id":             tenant,
			"findings":              findings,
			"summary":               map[string]any{"total": total, "returned": len(findings), "by_identifier": byIdentifier, "by_action": byAction, "by_destination": byDestination, "blocked": blocked},
			"no_secret_attestation": true,
		})
	}))
	mux.HandleFunc("POST /admin/dlp-rules", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP rules") {
			return
		}
		if dlpFeatureGate(w, r) {
			return
		}
		var body struct {
			Rules []model.DLPRule `json:"rules"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dlp rules: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if err := validateDLPRules(body.Rules, dlpClassifierStore.ClassifierSetForTenant(tenant)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		for i := range body.Rules {
			body.Rules[i].TenantID = tenant // tenant is authoritative from the admin identity
			if body.Rules[i].Status == "" {
				body.Rules[i].Status = "active"
			}
		}
		dlpRuleStore.SetRules(tenant, body.Rules)
		logInfof("dlp_rules_applied_by_admin tenant=%s rules=%d", tenant, len(body.Rules))
		writeJSON(w, http.StatusOK, map[string]any{"rules": dlpRuleStore.RulesForTenant(tenant)})
	}))
	// DLP custom classifiers (slice C): read/hot-apply the operator-defined identifiers (regex + keyword
	// dictionaries) the DLP scan detects alongside the built-ins. Non-secret: a classifier emits only its name +
	// a count, never the matched bytes. POST replaces the whole tenant set ([] = clear);
	// validation and configured storage must succeed before the live set changes.
	mux.HandleFunc("GET /admin/dlp-classifiers", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshDLPStores(w, dlpClassifierStore) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": adminTenantIDFromRequest(r), "classifiers": dlpClassifierStore.SpecsForTenant(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/dlp-classifiers", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP classifiers") {
			return
		}
		if dlpFeatureGate(w, r) {
			return
		}
		var body struct {
			Classifiers      *[]dlp.ClassifierSpec `json:"classifiers"`
			ExpectedTenantID string                `json:"expected_tenant_id,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dlp classifiers: %w", err))
			return
		}
		if body.Classifiers == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("classifiers must be an array; use [] to clear"))
			return
		}
		if len(*body.Classifiers) > dlp.MaxClassifiers {
			writeError(w, http.StatusBadRequest, fmt.Errorf("too many classifiers: %d (max %d)", len(*body.Classifiers), dlp.MaxClassifiers))
			return
		}
		// Validate up-front so a malformed set is rejected atomically (all-or-nothing), never partially applied.
		if _, errs := dlp.NewClassifierSet(*body.Classifiers); len(errs) > 0 {
			msgs := make([]string, 0, len(errs))
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid classifiers: %s", strings.Join(msgs, "; ")))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if body.ExpectedTenantID != "" && body.ExpectedTenantID != tenant {
			writeError(w, http.StatusConflict, fmt.Errorf("the organization changed; reload the list before editing"))
			return
		}
		if err := dlpClassifierStore.SetSpecsContext(r.Context(), tenant, *body.Classifiers); err != nil {
			logInfof("dlp_classifiers_save_unconfirmed tenant=%s", tenant)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("saving identifiers could not be confirmed; check the saved configuration before retrying"))
			return
		}
		logInfof("dlp_classifiers_applied_by_admin tenant=%s classifiers=%d", tenant, len(*body.Classifiers))
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenant, "classifiers": dlpClassifierStore.SpecsForTenant(tenant)})
	}))
	// DLP allowlist (slice F, false-positive tuning): the operator-declared KNOWN-SAFE values whose DLP matches are
	// suppressed (a test card, a sample My Number used in docs, a benign email). POST replaces the whole tenant
	// list (empty = clear). These are values the operator asserts are non-sensitive; the Console warns not to enter
	// real secrets. The scanner keeps hashes; authored values are stored and distributed for management.
	mux.HandleFunc("GET /admin/dlp-allowlist", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshDLPStores(w, dlpAllowlistStore) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": adminTenantIDFromRequest(r), "values": dlpAllowlistStore.ValuesForTenant(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/dlp-allowlist", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP allowlist") {
			return
		}
		if dlpFeatureGate(w, r) {
			return
		}
		var body struct {
			Values           *[]string `json:"values"`
			ExpectedTenantID string    `json:"expected_tenant_id,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dlp allowlist: %w", err))
			return
		}
		if body.Values == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("values must be an array; use [] to clear"))
			return
		}
		values, err := validatedAllowlistValues(*body.Values)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if body.ExpectedTenantID != "" && body.ExpectedTenantID != tenant {
			writeError(w, http.StatusConflict, fmt.Errorf("the organization changed; reload the list before editing"))
			return
		}
		if err := dlpAllowlistStore.SetValuesContext(r.Context(), tenant, values); err != nil {
			logInfof("dlp_allowlist_save_unconfirmed tenant=%s", tenant)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("saving the allowlist could not be confirmed; check the saved configuration before retrying"))
			return
		}
		logInfof("dlp_allowlist_applied_by_admin tenant=%s values=%d", tenant, len(values))
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenant, "values": dlpAllowlistStore.ValuesForTenant(tenant)})
	}))
	// DLP fingerprints (slice E, Exact-Data-Match): fingerprint a SENSITIVE dataset (a list of exact values —
	// customer record ids, employee numbers) into salted hashes under a named identifier; the scan then detects any
	// of those exact values in egress and raises a finding under that name. NON-SECRET: only salted hashes are
	// stored and only the dataset name + value count are ever returned — the values are never persisted or shown
	// back. GET lists datasets; POST creates/replaces one; DELETE removes one.
	mux.HandleFunc("GET /admin/dlp-fingerprints", adminEndpoint("admin.dlp.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshDLPStores(w, dlpFingerprintStore) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": adminTenantIDFromRequest(r), "datasets": dlpFingerprintStore.DatasetsForTenant(adminTenantIDFromRequest(r))})
	}))
	mux.HandleFunc("POST /admin/dlp-fingerprints", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP fingerprints") {
			return
		}
		if dlpFeatureGate(w, r) {
			return
		}
		var body struct {
			Name             string   `json:"name"`
			Values           []string `json:"values"`
			ExpectedTenantID string   `json:"expected_tenant_id,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dlp fingerprints: %w", err))
			return
		}
		if !dlp.ValidIdentifierName(body.Name) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("dataset name %q must be lowercase snake_case (2–40 chars) and not a reserved identifier", body.Name))
			return
		}
		if len(body.Values) > maxFingerprintValues {
			writeError(w, http.StatusBadRequest, fmt.Errorf("too many values: %d (max %d)", len(body.Values), maxFingerprintValues))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if body.ExpectedTenantID != "" && body.ExpectedTenantID != tenant {
			writeError(w, http.StatusConflict, fmt.Errorf("the organization changed; reload the list before editing"))
			return
		}
		count, err := dlpFingerprintStore.SetDatasetContext(r.Context(), tenant, body.Name, body.Values)
		if err != nil {
			if errors.Is(err, errInvalidFingerprintDataset) {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			logInfof("dlp_fingerprints_save_unconfirmed tenant=%s", tenant)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("saving the dataset could not be confirmed; check the saved configuration before retrying"))
			return
		}
		logInfof("dlp_fingerprints_applied_by_admin tenant=%s dataset=%s values=%d", tenant, body.Name, count)
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenant, "dataset": dlpFingerprintDataset{Name: body.Name, Count: count}, "datasets": dlpFingerprintStore.DatasetsForTenant(tenant)})
	}))
	mux.HandleFunc("DELETE /admin/dlp-fingerprints", adminEndpoint("admin.dlp.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DLP fingerprints") {
			return
		}
		if dlpFeatureGate(w, r) {
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("name query parameter is required"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		if expected := r.URL.Query().Get("expected_tenant_id"); expected != "" && expected != tenant {
			writeError(w, http.StatusConflict, fmt.Errorf("the organization changed; reload the list before editing"))
			return
		}
		removed, err := dlpFingerprintStore.RemoveDatasetContext(r.Context(), tenant, name)
		if err != nil {
			logInfof("dlp_fingerprints_save_unconfirmed tenant=%s", tenant)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("saving the dataset deletion could not be confirmed; check the saved configuration before retrying"))
			return
		}
		logInfof("dlp_fingerprints_removed_by_admin tenant=%s dataset=%s removed=%t", tenant, name, removed)
		writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenant, "removed": removed, "datasets": dlpFingerprintStore.DatasetsForTenant(tenant)})
	}))
}

func refreshDLPStores(w http.ResponseWriter, stores ...interface{ RefreshShared() error }) bool {
	for _, store := range stores {
		if err := store.RefreshShared(); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("DLP configuration is temporarily unavailable"))
			return false
		}
	}
	return true
}

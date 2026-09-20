package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Observe-mode adoption plus the effective-policy read surface (per-device effective
// policy, tenant effective policies, egress effective rules, catalog groups,
// inspection posture). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerEffectivePolicyRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, policyStore policy.RuntimeStore, deviceStore deviceRuntimeStore, assetStore *assetcatalog.Store, ruleStore *policyrule.Store, recompileAuthoredRules func()) {
	mux.HandleFunc("POST /admin/east-west/observations/adopt", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		var reqBody struct {
			ObservationIDs []string `json:"observation_ids"`
		}
		if err := decodeLimitedJSONBody(w, r, &reqBody, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode adopt request: %w", err))
			return
		}
		if config.EastWestObserveStore == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("observation store unavailable"))
			return
		}
		if !refreshAuthoredStores(w, ruleStore, assetStore) {
			return
		}
		recompileAuthoredRules()
		// Effective rules for dedup: an observation already matched by ANY effective east-west rule needs no
		// adoption (covered flows are exactly what convergence already counts as handled).
		var effective []decision.EastWestRule
		if rr, ok := policyStore.(interface {
			EffectiveEastWestRules(string) []decision.EastWestRule
		}); ok {
			effective = rr.EffectiveEastWestRules(tenant)
		}
		covered := func(obs eastwestobserve.FlowObservation) bool {
			req := model.DecisionRequest{Destination: obs.Destination, ServiceFamily: obs.ServiceFamily, Protocol: "tcp", DestinationPort: obs.Port}
			if obs.Source != eastwestobserve.SourceAny {
				req.DeviceID = obs.Source
			}
			_, ok := decision.MatchedEastWestRule(effective, req)
			return ok
		}
		created := []string{}
		skippedCovered := []string{}
		skippedMissing := []string{}
		changed := false
		defer func() {
			if changed {
				recompileAuthoredRules()
			}
		}()
		for _, id := range reqBody.ObservationIDs {
			obs, ok := config.EastWestObserveStore.Get(tenant, id)
			if !ok {
				skippedMissing = append(skippedMissing, id)
				continue
			}
			if covered(obs) {
				skippedCovered = append(skippedCovered, id)
				continue
			}
			name := "Adopted: " + obs.Destination
			if obs.Port > 0 {
				name += ":" + strconv.Itoa(obs.Port)
			}
			// Materialize the observed destination as a first-class, GUI-visible, editable network endpoint and
			// reference it by id — NOT a raw IP (which is invisible in the Console, blocks re-editing, and
			// compiles to an empty→wildcard selector that would match any host). See adoptDestinationEndpointID.
			destID, derr := adoptDestinationEndpointID(r.Context(), assetStore, tenant, obs.Destination)
			if derr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("adopt %s: materialize destination endpoint: %w", id, derr))
				return
			}
			rule := policyrule.Rule{
				TenantID:    tenant,
				Plane:       policyrule.PlaneEastWest,
				Direction:   policyrule.DirectionOutbound,
				Priority:    100,
				Name:        name,
				Source:      []string{"*"},
				Destination: []string{destID},
				// Resolve the catalog service by the observed PORT (robust: 22→SSH, 445→SMB, 3389→RDP,
				// 5985→WinRM-HTTP), falling back to builtin-svc-<family> then to no service constraint
				// (destination-only rule) — all valid allow rules.
				ServiceID: adoptServiceIDForObservation(assetStore, tenant, obs.Port, obs.ServiceFamily),
				Action:    policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect},
			}
			stored, err := ruleStore.UpsertContext(r.Context(), rule)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, policyrule.ErrPersistence) {
					status = http.StatusInternalServerError
				}
				writeError(w, status, fmt.Errorf("adopt %s: %w", id, err))
				return
			}
			created = append(created, stored.ID)
			changed = true
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":  "admin_east_west_adopt.v1",
			"tenant_id":       tenant,
			"created":         created,
			"skipped_covered": skippedCovered,
			"skipped_missing": skippedMissing,
		})
	}))

	// Effective-Policy ("Why") view: the precedence-ordered, provenance-tagged decision basis for one
	// destination — every policy that competes (authored rules AND built-in base policies loaded via -policy),
	// in the exact order the engine evaluates them, with the winner and shadowed matches marked — PLUS the
	// inspect/bypass basis (decrypt-all default vs known-bypass / authored bypass). This
	// is the visibility that was missing on 2026-06-23, when an authored Authenticate rule silently lost a
	// priority tie to a built-in Google allow and we had to hand-curl /decisions/evaluate to find it. Read-only.
	mux.HandleFunc("GET /admin/effective-policy", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		destination := strings.TrimSpace(r.URL.Query().Get("destination"))
		if destination == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("destination query parameter is required (e.g. ?destination=accounts.google.com)"))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		q := effectivePolicyQuery{
			Destination:       destination,
			ActorType:         r.URL.Query().Get("actor_type"),
			ServiceFamily:     r.URL.Query().Get("service_family"),
			DestinationPort:   boundedIntQuery(r.URL.Query().Get("destination_port"), 443, 1, 65535),
			SaaSApplicationID: strings.TrimSpace(r.URL.Query().Get("saas_application_id")),
		}
		// Gather the live inspect/bypass sources: the engine's effective set is authoritative for the decision;
		// the per-source lists attribute WHY a host is bypassed (the hidden surfaces from
		// docs/invisible_effective_configuration.md).
		bypassSources := inspectionSources{KnownGroups: knownbypass.Groups, InterceptHosts: []string{"*"}}
		if config.NetworkExtensionLabTLS != nil {
			patterns := config.NetworkExtensionLabTLS.InspectionPatternsForTenant(tenant)
			bypassSources.EffectiveBypass, bypassSources.InterceptHosts = patterns.Bypass, patterns.Intercept
			bypassSources.DeviceIntercept, bypassSources.DeviceBypass = patterns.InterceptByDevice, patterns.BypassByDevice
		}
		bypassSources.AuthoredBypass = policyrule.EgressBypassFQDNs(tenant, ruleStore.List(tenant, policyrule.PlaneEgress), assetStore)
		// ★ The preview must be the answer THIS organization would get. Measured while operating inside a newly
		// created organization: the trace listed another organization's policies and named one of them as the
		// deciding policy. The enforcement path already refuses to match across organizations (evaluator.go,
		// review finding #1) — only this preview was showing what enforcement would never do.
		runtimeEvaluator := evaluatorForCaller(runtimeEvaluatorForPolicyStore(evaluator, policyStore), r)
		writeJSON(w, http.StatusOK, effectivePolicyForDestination(runtimeEvaluator, tenant, q, bypassSources))
	}))

	// The standing "all policies" listing: every policy the engine evaluates (authored rules AND built-in base
	// policies), in precedence order, source-tagged — so the full policy set is visible, not discoverable only
	// per-destination. Read-only.
	mux.HandleFunc("GET /admin/effective-policies", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, effectivePolicyList(evaluatorForCaller(runtimeEvaluatorForPolicyStore(evaluator, policyStore), r)))
	}))
	// The unified Egress view's data source: EVERY effective egress rule across all surfaces — authored rules,
	// the built-in default, the known-bypass OS/cert floor, and authored SaaS Optimize or
	// cert-pin bypass — normalized to one source → destination : service ⇒ access × inspection shape. An operator
	// expects the Egress view to reflect all egress decisions in one place, not just authored rules; this gathers
	// them (the edge owns every surface) so the Console renders a single list. Read-only aggregation.
	mux.HandleFunc("GET /admin/egress-effective-rules", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := adminTenantIDFromRequest(r)
		aliasByID := map[string]string{}
		for _, e := range assetStore.ListEndpoints(tenant) {
			aliasByID[e.ID] = e.Alias
		}
		for _, g := range assetStore.ListGroups(tenant) {
			aliasByID[g.ID] = g.Alias
		}
		egressRules := ruleStore.List(tenant, policyrule.PlaneEgress)
		sourceWarnings := map[string]string{}
		serviceWarnings := map[string]bool{}
		for _, rule := range egressRules {
			sourceWarnings[rule.ID] = policyrule.InspectionSourceWarning(tenant, rule, assetStore)
			serviceWarnings[rule.ID] = policyrule.EgressServiceUnresolved(tenant, rule.ServiceID, assetStore)
		}
		in := effectiveEgressInputs{
			Eval:                     evaluatorForCaller(runtimeEvaluatorForPolicyStore(evaluator, policyStore), r),
			Tenant:                   tenant,
			AuthoredRules:            egressRules,
			AliasByID:                aliasByID,
			KnownGroups:              knownbypass.Groups,
			UnresolvedRuleIDs:        unresolvedDestinationRuleIDs(egressRules, assetStore, tenant),
			InspectionSourceWarnings: sourceWarnings,
			UnresolvedServiceRuleIDs: serviceWarnings,
		}
		if config.NetworkExtensionLabTLS != nil {
			in.EffectiveBypass = config.NetworkExtensionLabTLS.InspectionPatternsForTenant(tenant).Bypass
		}

		if config.InspectionPosture != nil {
			in.KnownEnabled = config.InspectionPosture().KnownBypassEnabled
		}
		writeJSON(w, http.StatusOK, buildEffectiveEgressRules(in))
	}))
	// Built-in SaaS catalog groups presented as endpoint groups (Phase A of the unified policy model): the SaaS
	// sign-in / AI / collaboration decrypt groups and the Optimize bypass groups, as named host sets. Read-only.
	mux.HandleFunc("GET /admin/catalog-groups", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"groups": catalogGroups()})
	}))

	// Inspection posture: surface AND change the default — deployment mode (decrypt_all vs bypass_default), the
	// decrypt allowlist (explicit hosts + SaaS auth-group presets), and the curated known-bypass list. The
	// "make the hidden default visible and editable" of docs/invisible_effective_configuration.md.
	mux.HandleFunc("GET /admin/inspection-posture", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, inspectionPostureForRequest(config, r))
	}))
	// Change the inspection posture (partial update — only provided fields change). bypass_default decrypts ONLY
	// the allowlist and raw-forwards the rest (still steered + policy-gated); keep a SaaS auth group selected to
	// keep tenant restriction working. Persisted; the engine's intercept + bypass sets are re-applied instantly.
	var postureWriteMu sync.Mutex
	mux.HandleFunc("POST /admin/inspection-posture", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF IT (2026-08-23). The posture now travels in
		// the config bundle, so a change written here would be overwritten by the next poll — silently, and only
		// on the node that happened to receive it. Every other CP-authored surface already refuses; this one did
		// not, which is how one Edge came to enforce a posture its fleet did not have.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "inspection posture") {
			return
		}
		if !inspectionPostureMayWrite(r) {
			writeError(w, http.StatusForbidden, fmt.Errorf("only the deployment operator, outside a customer context, may change deployment inspection defaults"))
			return
		}
		if config.SetInspectionPosture == nil || config.InspectionPosture == nil {
			writeError(w, http.StatusConflict, fmt.Errorf("inspection posture storage is not configured on this server"))
			return
		}
		var body struct {
			Mode                   *string   `json:"mode"`
			DecryptAllowlistHosts  *[]string `json:"decrypt_allowlist_hosts"`
			DecryptAllowlistGroups *[]string `json:"decrypt_allowlist_groups"`
			BypassGroups           *[]string `json:"bypass_groups"`
			KnownBypassEnabled     *bool     `json:"known_bypass_enabled"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode posture request: %w", err))
			return
		}
		postureWriteMu.Lock()
		defer postureWriteMu.Unlock()
		before := config.InspectionPosture()
		next := before
		if body.Mode != nil {
			next.Mode = strings.TrimSpace(*body.Mode)
		}
		if body.DecryptAllowlistHosts != nil {
			next.DecryptAllowlistHosts = *body.DecryptAllowlistHosts
		}
		if body.DecryptAllowlistGroups != nil {
			next.DecryptAllowlistGroups = *body.DecryptAllowlistGroups
		}
		if body.BypassGroups != nil {
			next.BypassGroups = *body.BypassGroups
		}
		if body.KnownBypassEnabled != nil {
			next.KnownBypassEnabled = *body.KnownBypassEnabled
		}
		if next.Mode != inspectionposture.ModeDecryptAll && next.Mode != inspectionposture.ModeBypassDefault {
			writeError(w, http.StatusBadRequest, fmt.Errorf("mode must be %q or %q", inspectionposture.ModeDecryptAll, inspectionposture.ModeBypassDefault))
			return
		}
		next, err := inspectionposture.Validate(next)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Legacy selections are cleanup-only. Do not accept a dormant grant that a
		// different or older node could turn into a bypass during startup.
		for _, name := range next.BypassGroups {
			if !stringInSetFold(name, before.BypassGroups) {
				writeError(w, http.StatusConflict, fmt.Errorf("Legacy bypass selections can only be removed. Create a tenant Egress bypass rule through Inspection Settings or Internet Access."))
				return
			}
		}
		_, err = config.SetInspectionPosture(next, adminTenantIDFromRequest(r))
		result := "saved"
		if err != nil {
			result = "persistence_unconfirmed"
		}
		now := time.Now().UTC()
		_ = appendAdminAudit(r.Context(), writer, config.AdminAuditOutbox, inspectionPostureAuditLog(r, before, next, result, evaluator, now), now)
		if err != nil {
			if errors.Is(err, inspectionposture.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("Storage did not confirm the inspection change. The previous live settings remain active. Restore storage and retry."))
			} else {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("Inspection settings could not be updated. Reload and retry."))
			}
			return
		}
		writeJSON(w, http.StatusOK, inspectionPostureForRequest(config, r))
	}))

	// Predefined pinned-bypass catalog: the curated set of well-known un-interceptable services (no-decrypt
	// keep-steer by default). A tenant admin can override an individual entry (force_inspect / disabled), which
	// is finer-grained than the all-or-nothing known-bypass toggle on the inspection posture.
}

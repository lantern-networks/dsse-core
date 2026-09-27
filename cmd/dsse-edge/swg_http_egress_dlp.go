package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/fileextract"
	"github.com/lantern-networks/dsse-core/model"
)

// Minimal DLP on decrypted egress upload bodies. The engine (oss/dlp) scans the request body for a small,
// high-precision identifier set (My Number, Corporate Number, credit-card, API keys) and records a NON-SECRET
// dlp_match inspection event (identifier type + count, never the raw value). Two modes, chosen per tenant
// policy:
//   - observe (default / observe-only policy): the body is tee'd through a dlp.Scanner off the forwarding
//     critical path; traffic is never altered; the event is emitted best-effort at handler exit.
//   - block / authenticate (policy has an interrupting rule): the body is wrapped in a dlp.GuardReader
//     (hold-before-release) so a governed identifier is denied BEFORE it leaves; on trip the handler returns
//     403 (block) / 401 (authenticate) and never relays.
// Design: docs/dlp_minimal_design.md.

// dlpPolicyFromDecision builds a DLP policy from a dlp_inspect directive the evaluator surfaced on the decision
// (DLP configured as an egress-rule option, tied to the matched destination). instanceClass is the destination's
// classified instance ("corporate" / "personal" / "" unknown); a directive whose instance_scope does not apply to
// that class is skipped (instance-aware action). Returns false when the decision carries no applicable directive.
// DLP-Findings view served from the aggregation hot store (S2, event_log_design.md). The inspection_events
// stream carries the findings; the view scans a bounded recent window (newest-first) and the handler filters to
// DLP finding types + re-caps. The scan cap is generous for the lab; cardinality control (design/S4) is what
// keeps this cheap at production scale.
const (
	dlpFindingsHotStoreStream = "inspection_events"
	dlpFindingsHotStoreWindow = 30 * 24 * time.Hour
	dlpFindingsHotStoreScan   = 20000
)

// inspectionEventFromRow reconstructs a model.InspectionEvent from a hot-store row (the row IS the event's JSON,
// written via writer.Append("inspection_events.log.jsonl", event)). Returns false for a row that is not a
// well-formed inspection event, so a malformed line never breaks the findings view.
func inspectionEventFromRow(row map[string]any) (model.InspectionEvent, bool) {
	b, err := json.Marshal(row)
	if err != nil {
		return model.InspectionEvent{}, false
	}
	var ev model.InspectionEvent
	if err := json.Unmarshal(b, &ev); err != nil || strings.TrimSpace(ev.ID) == "" {
		return model.InspectionEvent{}, false
	}
	return ev, true
}

func dlpPolicyFromDecision(dec model.AccessDecision, instanceClass string, resolver dlpPolicyObjectResolver) (dlp.Policy, bool) {
	for _, a := range dec.Actions {
		if a.Type != "dlp_inspect" {
			continue
		}
		// S5: a directive may REFERENCE a named DLP Policy object — resolve it to detectors/action/instance-scope
		// (the reusable model). The inline directive fields are the fallback when there is no reference / it is
		// unresolvable.
		identifiers := dlpMetaStrings(a.Metadata, "identifiers")
		action := dlpMetaString(a.Metadata, "action")
		minCount := dlpMetaInt(a.Metadata, "min_count")
		instanceScope := dlpMetaString(a.Metadata, "instance_scope")
		ruleID := dlpMetaString(a.Metadata, "dlp_rule_id")
		if pid := dlpMetaString(a.Metadata, "dlp_policy_id"); pid != "" && resolver != nil {
			if obj, ok := resolver.Get(dec.TenantID, pid); ok && !strings.EqualFold(obj.Status, "disabled") {
				identifiers = obj.Identifiers
				action = obj.OnMatch
				minCount = obj.MinCount
				instanceScope = obj.InstanceScope
				ruleID = pid
			}
		}
		if !dlpInstanceScopeApplies(instanceScope, instanceClass) {
			continue // the policy is scoped to a different instance class than this destination
		}
		rule := dlp.Rule{ID: ruleID, Action: dlp.Action(action), MinCount: minCount}
		for _, id := range identifiers {
			rule.Identifiers = append(rule.Identifiers, dlp.IdentifierType(id))
		}
		return dlp.Policy{TenantID: dec.TenantID, Rules: []dlp.Rule{rule}}, true
	}
	return dlp.Policy{}, false
}

// dlpDeviceRiskConditionsFromDecision returns the composite device-risk conditions of the referenced DLP Policy
// (S4). Empty when the directive references no named policy or it has none.
func dlpDeviceRiskConditionsFromDecision(dec model.AccessDecision, resolver dlpPolicyObjectResolver) []model.DLPDeviceRiskCondition {
	if resolver == nil {
		return nil
	}
	for _, a := range dec.Actions {
		if a.Type != "dlp_inspect" {
			continue
		}
		if pid := dlpMetaString(a.Metadata, "dlp_policy_id"); pid != "" {
			if obj, ok := resolver.Get(dec.TenantID, pid); ok {
				return obj.DeviceRisk
			}
		}
	}
	return nil
}

// dlpInstanceClassFor classifies the decision's destination instance from the signed-in account + the tenant's
// verified corporate domains, for instance-aware DLP action. "" when it cannot be determined.
func dlpInstanceClassFor(config edgeSWGHTTPEgressHandlerConfig, dec model.AccessDecision) string {
	if config.CorporateDomains == nil {
		return ""
	}
	return dlpInstanceClass(dlpDecisionAccountEmail(dec), config.CorporateDomains(dec.TenantID))
}

func dlpMetaString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func dlpMetaInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func dlpMetaStrings(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// edgeSWGHTTPEgressDLPMethod reports whether a method can carry an upload body worth DLP-scanning.
func edgeSWGHTTPEgressDLPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

// teeReadCloser adapts a Reader (tee scanner or guard) back to a ReadCloser, preserving Close on the original body.
type teeReadCloser struct {
	io.Reader
	closer io.Closer
}

func (t teeReadCloser) Close() error { return t.closer.Close() }

// edgeSWGHTTPEgressDLPHook carries the DLP state for one request: the observe scanner or the block guard, plus
// enough context to emit the non-secret event and, on a block, respond.
type edgeSWGHTTPEgressDLPHook struct {
	config        edgeSWGHTTPEgressHandlerConfig
	dec           model.AccessDecision
	contentType   string
	policy        dlp.Policy
	scanner       *dlp.Scanner     // observe mode (streaming text)
	guard         *dlp.GuardReader // block/authenticate mode (streaming text)
	skipReason    string           // non-scannable body
	active        bool             // a scannable body is being inspected
	instanceClass string           // destination instance class (corporate/personal/""), for instance-aware action + findings
	destination   string           // upstream host the upload is going to (the finding's "where")
	// deviceRiskConditions are the matched DLP Policy's composite device-risk conditions (S4); a detection is fed
	// to the aggregator with these so a device is flagged only when a condition is fully satisfied.
	deviceRiskConditions []model.DLPDeviceRiskCondition
	// File path (buffered): Office/PDF/multipart uploads are buffered, text-extracted, and decided at install.
	fileHandled  bool          // the body was handled by the buffered file path
	fileFindings []dlp.Finding // findings from the extracted file text
	fileTripped  bool          // a block/authenticate rule fired on the file
	// fileUninspectable: the block fired because the file could NOT be extracted (encrypted/corrupt) under
	// DLPBlockUninspectableFiles — the deny response explains "could not be inspected", not "contains X".
	fileUninspectable bool
}

// edgeSWGHTTPEgressFileInspectCap bounds how much of a file upload is buffered for extraction. A larger file is
// forwarded uninspected (fail-open) and logged — inspection capacity must not break legitimate large uploads.
const edgeSWGHTTPEgressFileInspectCap = fileextract.DefaultMaxExtractedBytes

// isEdgeSWGHTTPEgressFileUpload reports whether a body is a file/multipart upload routed to the buffered file
// path (multipart is parsed part-by-part; a direct Office/PDF body is extracted whole).
func isEdgeSWGHTTPEgressFileUpload(contentType string) bool {
	mt := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	return strings.HasPrefix(mt, "multipart/") ||
		fileextract.IsOOXML("", contentType) ||
		fileextract.IsPDF("", contentType)
}

// dlpScanOptionsFor bundles the scan configuration for a flow, SCOPED to the detectors the rule selected (S2,
// policy-scoped detection): custom classifiers (slice C) and EDM datasets (slice E) are filtered to `selected` so
// only the rule's chosen detectors run — not every tenant detector. The allowlist (slice F) is global tuning and
// always applies. All are nil-safe. `selected` is the rule's identifier list (built-in + custom + EDM names).
func dlpScanOptionsFor(config edgeSWGHTTPEgressHandlerConfig, tenantID string, selected []string) dlp.Options {
	var opts dlp.Options
	if config.DLPClassifiers != nil {
		opts.Classifiers = config.DLPClassifiers.ClassifierSetForTenant(tenantID).Subset(selected)
	}
	if config.DLPFingerprints != nil {
		opts.Fingerprints = config.DLPFingerprints.FingerprintSetForTenant(tenantID).Subset(selected)
	}
	if config.DLPAllowlist != nil {
		opts.Allowlist = config.DLPAllowlist.AllowlistForTenant(tenantID)
	}
	return opts
}

// dlpSelectedIdentifiers returns the identifier names the matched rule selected (its detect list) — built-in,
// custom, and EDM names. Used to scope both the scan (which detectors run) and the recorded findings.
func dlpSelectedIdentifiers(policy dlp.Policy) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range policy.Rules {
		for _, id := range r.Identifiers {
			if s := string(id); s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// dlpFilterFindingsToSelected drops any finding whose identifier the rule did not select — so a rule that inspects
// for My Number does not also report an incidental credit-card the built-in pass happened to see. An empty
// `selected` means "no restriction" (defensive; a real directive always names identifiers).
func dlpFilterFindingsToSelected(findings []dlp.Finding, selected []string) []dlp.Finding {
	if len(selected) == 0 {
		return findings
	}
	want := make(map[string]bool, len(selected))
	for _, n := range selected {
		want[n] = true
	}
	out := findings[:0]
	for _, f := range findings {
		if want[string(f.Type)] {
			out = append(out, f)
		}
	}
	return out
}

// installEdgeSWGHTTPEgressDLP wires DLP onto the outbound request per the tenant policy. It returns a hook
// whose finalizeObserve must run at handler exit (defer) and whose blocked/respondBlocked are consulted right
// after the upstream Do. For a non-scannable or bodyless request it is inert (finalize may record a skip).
func installEdgeSWGHTTPEgressDLP(req *http.Request, config edgeSWGHTTPEgressHandlerConfig, dec model.AccessDecision) *edgeSWGHTTPEgressDLPHook {
	h := &edgeSWGHTTPEgressDLPHook{config: config, dec: dec}
	// License/entitlement gate: DLP is an optional paid feature — a tenant not entitled to it is never inspected,
	// regardless of any rule. nil Entitlements = everything entitled (no licensing).
	if config.Entitlements != nil && !config.Entitlements.Entitled(dec.TenantID, featureDLP) {
		return h
	}
	// Capture the upstream destination host from the request's target URL (the reliable "where" for a finding —
	// dec.FQDN/Destination are not populated on the in-process decrypt-all path). Non-secret (a hostname).
	if req != nil {
		if target, err := swgHTTPEgressTargetURLFromRequest(req); err == nil && target != nil {
			h.destination = target.Hostname()
		}
	}
	if req == nil || req.Body == nil || req.Body == http.NoBody || !edgeSWGHTTPEgressDLPMethod(req.Method) {
		return h
	}
	h.contentType = req.Header.Get("Content-Type")
	// DLP is a POLICY ACTION, not a global scanner (docs/dlp_policy_ux_integration.md): a flow is inspected ONLY
	// when a matching egress rule surfaced a dlp_inspect directive for it (per-destination, decrypt-gated,
	// instance-scoped). No directive → the flow is not DLP-scanned at all — no blanket scanning, so unscoped
	// destinations (e.g. the Edge's own telemetry) never generate false-positive findings. There is deliberately
	// no tenant-wide fallback: DLP is meaningful only when scoped to a destination.
	h.instanceClass = dlpInstanceClassFor(config, dec)
	p, ok := dlpPolicyFromDecision(dec, h.instanceClass, config.DLPPolicies)
	if !ok || len(p.Rules) == 0 {
		return h // no DLP rule governs this destination → inert
	}
	h.policy = p
	h.deviceRiskConditions = dlpDeviceRiskConditionsFromDecision(dec, config.DLPPolicies)
	// File / multipart uploads: buffer-with-cap, extract text, decide now (block is enforced before Do).
	if isEdgeSWGHTTPEgressFileUpload(h.contentType) {
		h.inspectFile(req)
		return h
	}
	scannable, skipReason := dlp.ShouldScan(h.contentType)
	if !scannable {
		// The declared Content-Type is CLIENT-ASSERTED (review #18): relabeling a JSON upload as
		// application/octet-stream skipped the scan entirely — a one-header DLP bypass on exactly the
		// destinations an operator chose to govern. Sniff the actual first bytes: a body that IS text is
		// scanned regardless of its label; genuinely binary bodies still skip.
		prefix := make([]byte, 512)
		n, _ := io.ReadFull(req.Body, prefix)
		req.Body = teeReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix[:n]), req.Body), closer: req.Body}
		if sniffedOK, _ := dlp.ShouldScan(http.DetectContentType(prefix[:n])); !sniffedOK {
			h.skipReason = skipReason
			return h
		}
	}
	h.active = true
	opts := dlpScanOptionsFor(config, dec.TenantID, dlpSelectedIdentifiers(h.policy))
	if h.policy.Interrupts() {
		h.guard = dlp.NewGuardReaderWithOptions(req.Body, h.policy.TripThresholds(), opts)
		req.Body = teeReadCloser{Reader: h.guard, closer: req.Body}
	} else {
		h.scanner = dlp.NewScannerWithOptions(opts)
		req.Body = teeReadCloser{Reader: io.TeeReader(req.Body, h.scanner), closer: req.Body}
	}
	return h
}

// inspectFile buffers a file/multipart upload (up to the cap), extracts its text, runs the detector, and — if
// an interrupting rule fires — marks it tripped so the handler denies it BEFORE forwarding (the file is never
// sent). Otherwise the buffered body is put back for forwarding and any findings are observed. A body larger
// than the cap is forwarded uninspected (fail-open) and logged. Never alters the forwarded bytes.
func (h *edgeSWGHTTPEgressDLPHook) inspectFile(req *http.Request) {
	orig := req.Body
	buf, _ := io.ReadAll(io.LimitReader(orig, edgeSWGHTTPEgressFileInspectCap+1))
	if len(buf) > edgeSWGHTTPEgressFileInspectCap {
		// Oversize: cannot fully buffer/inspect — which makes PADDING a governed secret past the cap a DLP
		// bypass on exactly the interrupting destinations (review #19). Same posture as the extract-error
		// case: fail LOUD always; fail CLOSED under -dlp-block-uninspectable-files when the governing rule
		// interrupts. Default stays forward-and-log (availability of large legitimate uploads wins).
		req.Body = teeReadCloser{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}
		h.skipReason = "oversize_not_inspected"
		if h.config.DLPBlockUninspectableFiles && h.policy.Interrupts() {
			h.fileTripped = true
			h.fileUninspectable = true
			logWarnf("dlp file upload BLOCKED as uninspectable (oversize; dest=%s type=%q cap=%d)", h.destination, h.contentType, edgeSWGHTTPEgressFileInspectCap)
			return
		}
		logWarnf("dlp file upload forwarded UNINSPECTED (oversize; dest=%s type=%q cap=%d)", h.destination, h.contentType, edgeSWGHTTPEgressFileInspectCap)
		return
	}
	// Put the buffered file back so it forwards unchanged (on observe/allow).
	req.Body = teeReadCloser{Reader: bytes.NewReader(buf), closer: orig}
	h.fileHandled = true
	text, inspected, err := fileextract.Extract(h.contentType, buf)
	if err != nil {
		// Extraction failed on a file the policy WANTED inspected (encrypted/corrupt/adversarial container).
		// This is not the benign "binary type we don't extract" case: a deliberately broken container is a
		// DLP bypass vehicle. Fail LOUD always; fail CLOSED when the operator opted in and the governing rule
		// interrupts (a pure observe rule never blocks).
		h.skipReason = "extract_error_not_inspected"
		if h.config.DLPBlockUninspectableFiles && h.policy.Interrupts() {
			h.fileTripped = true
			h.fileUninspectable = true
			logWarnf("dlp file upload BLOCKED as uninspectable (dest=%s type=%q): %v", h.destination, h.contentType, err)
			return
		}
		logWarnf("dlp file upload forwarded UNINSPECTED (extract failed; dest=%s type=%q): %v", h.destination, h.contentType, err)
		return
	}
	if !inspected {
		h.skipReason = "binary_not_inspected"
		return
	}
	selected := dlpSelectedIdentifiers(h.policy)
	findings := dlpFilterFindingsToSelected(dlp.DetectWithOptions([]byte(text), "text/plain", dlpScanOptionsFor(h.config, h.dec.TenantID, selected)), selected)
	if len(findings) == 0 {
		return
	}
	h.fileFindings = findings
	counts := map[dlp.IdentifierType]int{}
	for _, f := range findings {
		counts[f.Type] = f.Count
	}
	if action, _ := h.policy.Decide(counts); action == dlp.ActionBlock || action == dlp.ActionAuthenticate {
		h.fileTripped = true
	}
}

// blocked reports whether the upload was denied (a governed secret detected before it was forwarded) — either
// by the streaming guard (text) or by the buffered file path.
func (h *edgeSWGHTTPEgressDLPHook) blocked() bool {
	if h == nil {
		return false
	}
	if h.fileTripped {
		return true
	}
	return h.guard != nil && h.guard.Tripped()
}

// respondBlocked emits the dlp_match (with the enforced action) and writes the deny response: 403 for block,
// 401 for authenticate (step-up required). The detected secret was never forwarded.
func (h *edgeSWGHTTPEgressDLPHook) respondBlocked(w http.ResponseWriter, r *http.Request) {
	findings := h.fileFindings // already scoped in inspectFile
	if h.guard != nil {
		findings = dlpFilterFindingsToSelected(h.guard.Findings(), dlpSelectedIdentifiers(h.policy))
	}
	counts := map[dlp.IdentifierType]int{}
	for _, f := range findings {
		counts[f.Type] = f.Count
	}
	action, _ := h.policy.Decide(counts)
	if action == "" {
		action = dlp.ActionBlock
	}
	appendEdgeSWGHTTPEgressDLPMatch(r.Context(), h.config, h.dec, h.contentType, findings, string(action), h.instanceClass, h.destination, h.ruleID(), h.deviceRiskConditions, time.Now())
	setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomePolicyDenied)
	status := http.StatusForbidden
	decision := "dlp_blocked"
	if action == dlp.ActionAuthenticate {
		status = http.StatusUnauthorized
		decision = "dlp_authenticate_required"
	}
	// Coaching: a browser upload gets a branded, human-readable page saying WHAT was detected (non-secret — types
	// only) and why it was stopped; an API client gets the JSON. DLP that teaches, not just a bare 403.
	if wantsHTMLResponse(r) {
		title := "Upload blocked"
		if action == dlp.ActionAuthenticate {
			title = "Verification required"
		}
		detail := "This upload contains " + dlpHumanIdentifierList(findings) + ". Your organization does not permit sending this to this destination. Contact your administrator if you believe this is a mistake."
		if h.fileUninspectable {
			detail = "This file could not be inspected (it may be encrypted or corrupted), and your organization requires this destination's uploads to be inspected. Contact your administrator if you believe this is a mistake."
		}
		writeCeremonyDeniedHTML(w, status, title, detail)
		return
	}
	body := map[string]any{"decision": decision, "dlp_action": string(action), "dlp_findings": findings}
	if h.fileUninspectable {
		body["dlp_uninspectable"] = true
	}
	writeJSON(w, status, body)
}

// dlpHumanIdentifierList renders the detected identifier TYPES (never values) as a friendly English phrase for the
// coaching page, e.g. "My Number and credit-card numbers".
func dlpHumanIdentifierList(findings []dlp.Finding) string {
	names := map[dlp.IdentifierType]string{
		dlp.MyNumber:        "a My Number",
		dlp.CorporateNumber: "a Corporate Number",
		dlp.CreditCard:      "credit-card numbers",
		dlp.APIKey:          "API keys or secrets",
		dlp.Email:           "email addresses",
		dlp.Phone:           "phone numbers",
	}
	seen := map[string]bool{}
	var parts []string
	for _, f := range findings {
		n := names[f.Type]
		if n == "" {
			n = "sensitive data"
		}
		if !seen[n] {
			seen[n] = true
			parts = append(parts, n)
		}
	}
	switch len(parts) {
	case 0:
		return "sensitive data"
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}

// finalizeObserve emits the observe-mode dlp_match (or scan-skip) at handler exit. On a blocked upload it is a
// no-op — respondBlocked already emitted the enforcing event.
func (h *edgeSWGHTTPEgressDLPHook) finalizeObserve(ctx context.Context) {
	if h == nil {
		return
	}
	if h.skipReason != "" {
		// Non-scannable content (binary/compressed) is NOT logged. Recording a per-flow "did-not-scan" event is
		// pure noise — it is not a finding, and the flow itself is already recorded in the access stream (the
		// governance floor). The DLP-Findings view carries findings only. If DLP coverage ever needs surfacing it
		// belongs in an aggregate metric, not per-flow event rows.
		return
	}
	if h.blocked() {
		return
	}
	if !h.active && !h.fileHandled {
		return
	}
	var findings []dlp.Finding
	switch {
	case h.fileHandled:
		findings = h.fileFindings // already scoped to the selected identifiers in inspectFile
	case h.guard != nil:
		findings = dlpFilterFindingsToSelected(h.guard.Findings(), dlpSelectedIdentifiers(h.policy)) // sub-threshold findings in an interrupting policy are still observed
	case h.scanner != nil:
		findings = dlpFilterFindingsToSelected(h.scanner.Findings(), dlpSelectedIdentifiers(h.policy))
	}
	if len(findings) == 0 {
		return
	}
	// Non-interrupting path records the DECIDED action: observe (quiet) or warn (the "would-block" ramp rung).
	// Both allow the upload; only the recorded action + severity differ, so the DLP Findings view distinguishes them.
	counts := map[dlp.IdentifierType]int{}
	for _, f := range findings {
		counts[f.Type] = f.Count
	}
	action, _ := h.policy.Decide(counts)
	if action != dlp.ActionWarn {
		action = dlp.ActionObserve // sub-threshold / observe-only findings record as observe
	}
	appendEdgeSWGHTTPEgressDLPMatch(ctx, h.config, h.dec, h.contentType, findings, string(action), h.instanceClass, h.destination, h.ruleID(), h.deviceRiskConditions, time.Now())
}

// ruleID returns the id of the rule that governs this flow's DLP (for the finding's link back to policy).
func (h *edgeSWGHTTPEgressDLPHook) ruleID() string {
	if len(h.policy.Rules) > 0 {
		return string(h.policy.Rules[0].ID)
	}
	return ""
}

// appendEdgeSWGHTTPEgressDLPMatch records a dlp_match inspection event carrying only the non-secret findings
// (identifier type + count) and the enforced action. It never carries the matched value.
func appendEdgeSWGHTTPEgressDLPMatch(ctx context.Context, config edgeSWGHTTPEgressHandlerConfig, dec model.AccessDecision, contentType string, findings []dlp.Finding, action, instanceClass, destination, ruleID string, deviceRiskConditions []model.DLPDeviceRiskCondition, now time.Time) {
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		types = append(types, string(f.Type))
	}
	metadata := map[string]any{
		"dlp_event_version":             "s2.v1",
		"dlp_metadata_scope":            "non_secret",
		"edge_http_egress_handler_path": edgeplane.EdgeSWGHTTPEgressPath,
		"dlp_action":                    action,
		"dlp_findings":                  findings,
		"dlp_identifier_types":          types,
		"request_content_type":          contentType,
	}
	// The destination host (where the data was going) — the finding's most meaningful "where".
	if strings.TrimSpace(destination) != "" {
		metadata["dlp_destination"] = destination
	}
	// The rule that caught it — so the findings view links back to policy (S3).
	if strings.TrimSpace(ruleID) != "" {
		metadata["dlp_rule_id"] = ruleID
	}
	// Instance-aware action: record which destination instance class the decision applied to (non-secret), so the
	// findings view can show "blocked to a personal account" vs "observed to the corporate tenant".
	if strings.TrimSpace(instanceClass) != "" {
		metadata["dlp_instance_class"] = instanceClass
	}
	severity := "warning"
	if action == string(dlp.ActionBlock) {
		severity = "high"
	}
	emitEdgeSWGHTTPEgressDLPEvent(ctx, config, dec, "dlp_match", severity, metadata, now)
	// DLP → device risk (S4): feed this detection (types, destination, instance class) to the aggregator with the
	// DLP Policy's COMPOSITE conditions; the device is flagged only when a condition is fully satisfied
	// (enough distinct types + concentration + burst), and existing risk-based policy then acts.
	if config.DLPDeviceRisk != nil && len(deviceRiskConditions) > 0 {
		rec := dlpDetectionRecord{types: types, destination: destination, instanceClass: instanceClass}
		outcome := config.DLPDeviceRisk.Record(derefStringPtr(dec.DeviceID), rec, deviceRiskConditions, now)
		if outcome.ConditionSeverity != "" {
			result := "success"
			eventSeverity := "info"
			if !outcome.Applied {
				result, eventSeverity = "error", "high"
			} else if outcome.Err != nil || outcome.Persistence == "volatile" || outcome.Persistence == "saved_non_atomic" {
				result, eventSeverity = "partial", "warning"
			}
			log.Printf("dlp_device_risk device=%s condition_severity=%s applied=%t applied_severity=%s changed=%t persistence=%s result=%s",
				derefStringPtr(dec.DeviceID), outcome.ConditionSeverity, outcome.Applied, outcome.AutomaticRiskResult.Severity, outcome.Changed, outcome.Persistence, result)
			// Keep the original detection separate and recorded first. A failed risk
			// save must neither erase that finding nor count it twice in DLP Findings.
			riskMetadata := map[string]any{
				"dlp_event_version": "s2.v1", "dlp_metadata_scope": "non_secret",
				"dlp_rule_id": ruleID, "dlp_destination": destination,
				"condition_severity": outcome.ConditionSeverity, "applied": outcome.Applied,
				"applied_severity": outcome.AutomaticRiskResult.Severity, "changed": outcome.Changed,
				"persistence": outcome.Persistence, "result": result,
			}
			emitEdgeSWGHTTPEgressDLPEvent(ctx, config, dec, "dlp_device_risk", eventSeverity, riskMetadata, now)
		}
	}
}

// (The "did-not-scan" inspection event was abolished — a body that could not be scanned is a NON-finding, not a
// per-request record; recording it flooded the Inspection/DLP tab. Only real findings are emitted now.)
// emitEdgeSWGHTTPEgressDLPEvent writes a DLP inspection event on the best-effort audit path (a write failure
// is logged, never surfaced to the request — observe must not affect availability of the decrypt path). The
// event is non-secret: PayloadStored=false, Masked=true, and the metadata carries only types/counts.
func emitEdgeSWGHTTPEgressDLPEvent(ctx context.Context, config edgeSWGHTTPEgressHandlerConfig, dec model.AccessDecision, findingType, severity string, metadata map[string]any, now time.Time) {
	if config.Writer == nil || config.InspectionEvents == nil {
		return
	}
	// Carry the SOURCE (who/where the upload came from) onto the finding so the operator sees not just what was
	// detected and where it was going, but WHO sent it — the corporate identity, the device, and (from the
	// decision metadata) the OS/corporate user, the originating app, and the signed-in account. Non-secret.
	if metadata != nil {
		if v := derefStringPtr(dec.SourceIP); v != "" {
			metadata["dlp_source_ip"] = v
		}
		if v := stringMetadata(dec.Metadata, "ai_app"); v != "" {
			metadata["dlp_source_app"] = v // the app on the endpoint that originated the flow (steer OPEN "a=")
		}
		if v := stringMetadata(dec.Metadata, "corporate_user"); v != "" {
			metadata["dlp_corporate_user"] = v // the OS/corporate user mapped from the NE OS user
		}
		if v := stringMetadata(dec.Metadata, "ai_email"); v != "" {
			metadata["dlp_account"] = v // the signed-in account (email) the data was sent under
		} else if v := stringMetadata(dec.Metadata, "ai_account"); v != "" {
			metadata["dlp_account"] = v
		}
	}
	event := model.InspectionEvent{
		ID:               randomEdgeID("ie_dlp_", now),
		TenantID:         dec.TenantID,
		AccessDecisionID: stringPtr(dec.ID),
		ApplicationID:    stringPtr(dec.ApplicationID),
		SessionID:        dec.SessionID,
		UserID:           dec.UserID,   // corporate IdP identity (empty on device-only steered flows)
		DeviceID:         dec.DeviceID, // enrolled/transport device identity
		ContentType:      stringPtr("application/vnd.dsse.dlp-finding+json"),
		FindingType:      stringPtr(findingType),
		Severity:         stringPtr(severity),
		PayloadStored:    false,
		Masked:           true,
		Timestamp:        now.UTC().Format(time.RFC3339),
		Metadata:         metadata,
	}
	if err := normalizeInspectionEvent(&event, dec.TenantID, now); err != nil {
		log.Printf("dlp inspection event normalize failed (best-effort): %v", err)
		return
	}
	event = config.InspectionEvents.Upsert(event)
	if err := config.Writer.Append("inspection_events.log.jsonl", event); err != nil {
		log.Printf("dlp inspection event append failed (best-effort): %v", err)
		return
	}
	if envelope, err := domainEventOutboxEnvelopeFromInspectionEvent(event, now); err != nil {
		log.Printf("dlp inspection event outbox envelope (best-effort): %v", err)
	} else {
		appendDomainEventOutbox(ctx, config.DomainEventOutbox, envelope, now)
	}
}

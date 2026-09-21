package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	tenantca "github.com/lantern-networks/dsse-core/tenantca"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/edgeplane"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"
	inspection "github.com/lantern-networks/dsse-core/inspection"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/revocation"
	swg "github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/upstreamtrust"
	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

type edgeSWGHTTPEgressHandlerConfig struct {
	Evaluator   decision.Evaluator
	PolicyStore policy.RuntimeStore
	// PolicyCandidateStore records destinations seen on unmatched flows as allow-policy candidates an admin
	// can adopt. nil disables the capture.
	PolicyCandidateStore policycandidate.RuntimeStore
	Writer               *logs.Writer
	Registry             connectorRegistryStore
	// TenantCARegistry identifies WHICH organization a presented client certificate belongs to, from the CA
	// that issued it. A connector belongs to exactly one organization, so its certificate has to come from
	// that organization's CA and not merely from one this Edge happens to accept.
	TenantCARegistry *tenantca.TenantCARegistry
	ProxyClient      *http.Client

	// The authorities this flow's organization vouches for when this Edge verifies one of its private assets.
	// An interface, not the concrete store: asking for a concrete type is how three paths in one day were
	// turned off silently when the store was swapped for the durable one.
	InternalCAs        organizationInternalCAPool
	SWGRuntime         swg.RuntimeConfig
	SessionStore       *sessionstore.Store
	DeviceStore        deviceRuntimeStore
	HighRiskOverlay    *revocation.HighRiskOverlay // Phase 3 shared high-risk overlay
	EnrolledLedger     *enrolledinventory.Ledger   // device-group registry — for the group risk floor (union model)
	HumanApprovals     *humanapproval.Store
	DelegatedGrants    *delegatedgrant.Store
	NonHumanIdentities nhi.RuntimeStore
	DecisionStore      *accessdecision.Store
	InspectionEvents   *inspection.Store
	// DLPRules supplies runtime-authored DLP rules (/admin/dlp-rules) overlaid onto the bundle's DLPRules so
	// they surface as dlp_inspect directives (the unified DLP-as-egress-rule path). nil = bundle rules only.
	DLPRules dlpRuleRuntimeReader
	// DLPClassifiers supplies the operator-defined custom classifiers (/admin/dlp-classifiers) so the DLP scan
	// detects tenant-specific identifiers alongside the built-ins. nil = built-in identifiers only.
	DLPClassifiers dlpClassifierProvider
	// CorporateDomains returns a tenant's verified corporate domains (the sanctioned SaaS instances) so
	// instance-scoped DLP rules can tell corporate from personal/external destinations. nil = none (scoped rules
	// stay inert — never over-block an unclassifiable destination).
	CorporateDomains func(tenantID string) []string
	// DLPAllowlist supplies the operator-declared known-safe values (/admin/dlp-allowlist) whose matches the DLP
	// scan suppresses (false-positive tuning). nil = suppress nothing.
	DLPAllowlist dlpAllowlistProvider
	// DLPFingerprints supplies the operator's Exact-Data-Match datasets (/admin/dlp-fingerprints) so the scan
	// detects exact values from a fingerprinted sensitive dataset. nil = no EDM.
	DLPFingerprints dlpFingerprintProvider
	// Entitlements is the license/contract gate: DLP is inspected only for a tenant entitled to the "dlp" feature.
	// nil = everything entitled (backward compatible / no licensing).
	Entitlements entitlementReader
	// DLPDeviceRisk aggregates DLP detections per device and raises device risk on a threshold breach
	// (S4). nil = disabled.
	DLPDeviceRisk *dlpDeviceRiskAggregator
	// DLPPolicies resolves a referenced named DLP Policy object (S5). nil = no named policies (inline config only).
	DLPPolicies                   dlpPolicyObjectResolver
	DomainEventOutbox             domainEventOutboxWriter
	AdminAuditOutbox              adminAuditOutboxDeadReader
	UsageMeters                   usagemeter.UsageMeterRuntimeStore
	WorkloadAttestationSecret     string
	LabMode                       bool
	WorkloadAttestations          runtimeWorkloadAttestationNonceStore
	ConnectorSecret               string
	RequireConnectorRuntimeSecret bool
	// DeviceAuthenticatedInProcess marks the TRUSTED in-process caller: the macOS NE / Windows WFP
	// decrypt-all egress, which the edge serves by handing the decrypted request to this handler IN PROCESS
	// (NetworkExtensionLabTLS.SetHTTPHandler) after intercepting a steered flow. That flow already passed
	// (T) transport mTLS device authentication + enrolled-inventory admission upstream, so it is NOT a
	// connector and carries no connector credentials — the connector authorization gate does not apply to it.
	// This is set ONLY on the handler wired to SetHTTPHandler, never on the external /swg/http-egress route,
	// so it is structurally unforgeable: an external HTTP request can never reach the auth-skipping path
	// (it is not a header the caller can set). Before this flag, opening the NE egress required -lab-mode,
	// which also relaxed every other production guard (the GAP-1 reason the reference still set -lab-mode).
	DeviceAuthenticatedInProcess bool
	// FederatedAuthGate, when set, turns an "authenticate" decision on a steered browser flow into an IdP
	// redirect (via the clientless broker) instead of a bare 401, and allows the flow once a federated grant
	// exists. nil = no federated-auth front door (serve the status code as before).
	FederatedAuthGate *federatedAuthGate
	// StripAltSvc, when true (default), removes the Alt-Svc response header so the client stays on the
	// inspectable TCP path instead of switching to HTTP/3 (QUIC). QUIC is disabled by default for a
	// decrypt-all SSE; this is the clean, fast way to do it (no QUIC-timeout fallback for the client).
	StripAltSvc bool
	// DLPBlockUninspectableFiles (-dlp-block-uninspectable-files, default false): under an INTERRUPTING
	// (block/authenticate) DLP rule, a file upload that cannot be inspected — text extraction failed
	// (encrypted/corrupt/adversarial PDF or Office container) or the file exceeds the buffering cap
	// (oversize) — is BLOCKED instead of forwarded uninspected. Both are otherwise DLP bypass vehicles
	// (a broken container, or padding a secret past the cap) for exactly the destinations an operator
	// chose to interrupt. Off = forward-and-log (availability first); the skip is logged either way.
	DLPBlockUninspectableFiles bool
}

// stripQUICAdvertisement removes response headers that advertise HTTP/3 (QUIC) so the client keeps using
// the inspectable TCP path. Deleting Alt-Svc is safe — it only advertises optional alternative services.
func stripQUICAdvertisement(header http.Header) {
	header.Del("Alt-Svc")
}

type swgHTTPEgressOutcomeWriter interface {
	SetSWGHTTPEgressOutcome(string)
}

type swgHTTPEgressUpstreamErrorCategoryWriter interface {
	SetSWGHTTPEgressUpstreamErrorCategory(string)
}

type swgHTTPEgressWebSocketTunnelWriter interface {
	TunnelSWGHTTPEgressWebSocket(*http.Response) error
}

type edgeSWGHTTPEgressReadinessPrecondition struct {
	Checked                       bool
	LabMode                       bool
	Status                        string
	ReadinessDependency           string
	EgressForwarded               bool
	TLSReadinessStatusPath        string
	TLSReadinessStatusVersion     string
	DefaultTLSDecryptionRequired  bool
	DefaultTLSDecryptionObserved  bool
	DefaultTLSDecryptionStatus    string
	MacCATrustRequired            bool
	MacCATrustObserved            bool
	MacCATrustStatus              string
	TenantHeaderDependencyCount   int
	HeaderNamesVisible            []string
	OperatorConfigRefsVisible     []string
	PerDestinationTLSBypassNeeded bool
	TLSBypassRuleCount            int
	CurrentRequestTLSBypass       bool
	CurrentRequestTLSBypassRuleID string
	SuppressedByTLSBypass         bool
}

type edgeSWGHTTPEgressReadinessDependencyResponse struct {
	SchemaVersion                       string   `json:"schema_version"`
	Status                              string   `json:"status"`
	ReadinessDependency                 string   `json:"readiness_dependency"`
	EdgeHTTPegressHandlerPath           string   `json:"edge_http_egress_handler_path"`
	TLSReadinessStatusPath              string   `json:"tls_readiness_status_path"`
	TLSReadinessStatusVersion           string   `json:"tls_readiness_status_version"`
	TenantID                            string   `json:"tenant_id"`
	PolicyBundleID                      string   `json:"policy_bundle_id"`
	PolicyBundleVersion                 string   `json:"policy_bundle_version"`
	AccessDecisionID                    string   `json:"access_decision_id"`
	PolicyID                            string   `json:"policy_id"`
	ApplicationID                       string   `json:"application_id"`
	SaaSApplicationID                   string   `json:"saas_application_id"`
	LabMode                             bool     `json:"lab_mode"`
	EgressForwarded                     bool     `json:"egress_forwarded"`
	DefaultTLSDecryptionRequired        bool     `json:"default_tls_decryption_required"`
	DefaultTLSDecryptionObserved        bool     `json:"default_tls_decryption_observed"`
	DefaultTLSDecryptionStatus          string   `json:"default_tls_decryption_status"`
	MacCATrustRequired                  bool     `json:"mac_ca_trust_required"`
	MacCATrustObserved                  bool     `json:"mac_ca_trust_observed"`
	MacCATrustStatus                    string   `json:"mac_ca_trust_status"`
	TenantHeaderRewriteDependencyCount  int      `json:"tenant_header_rewrite_dependency_count"`
	HeaderNamesVisible                  []string `json:"header_names_visible"`
	OperatorConfigRefsVisible           []string `json:"operator_config_refs_visible"`
	PerDestinationTLSBypassRequired     bool     `json:"per_destination_tls_bypass_required"`
	TLSBypassRuleCount                  int      `json:"tls_bypass_rule_count"`
	CurrentRequestTLSBypassApplied      bool     `json:"current_request_tls_bypass_applied"`
	CurrentRequestTLSBypassRuleID       string   `json:"current_request_tls_bypass_rule_id"`
	TLSReadinessSuppressedByTLSBypass   bool     `json:"tls_readiness_dependency_suppressed_by_tls_bypass"`
	InspectionMetadataReadbackObserved  bool     `json:"inspection_metadata_readback_observed"`
	HeaderValueMaterialInDiagnostic     bool     `json:"header_value_material_in_diagnostic"`
	OperatorConfigValueMaterialInDiag   bool     `json:"operator_config_value_material_in_diagnostic"`
	RealTLSInterceptionRuntimeExecuted  bool     `json:"real_tls_interception_runtime_executed"`
	MacCATrustMutationStarted           bool     `json:"mac_ca_trust_mutation_started"`
	P4PackagingMDMSigningInstallStarted bool     `json:"p4_packaging_mdm_signing_install_started"`
	ShippingProductClaimed              bool     `json:"shipping_product_claimed"`
	ProductionScaleClaimed              bool     `json:"production_scale_claimed"`
	MVPPilotSuccessClaimed              bool     `json:"mvp_pilot_success_claimed"`
	WindowsWorkStarted                  bool     `json:"windows_work_started"`
	SecretLeakGate                      string   `json:"secret_leak_gate"`
	NoSecretAttestation                 bool     `json:"no_secret_attestation"`
}

func newEdgeSWGHTTPEgressHandler(config edgeSWGHTTPEgressHandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleSWGHTTPEgress(w, r, config)
	}
}

func handleSWGHTTPEgress(w http.ResponseWriter, r *http.Request, config edgeSWGHTTPEgressHandlerConfig) {
	runtimeEvaluator := runtimeEvaluatorForPolicyStore(config.Evaluator, config.PolicyStore)
	runtimeEvaluator = overlayRuntimeDLPRules(runtimeEvaluator, config.DLPRules)
	// Connector authorization applies to the EXTERNAL /swg/http-egress route (untrusted callers). The trusted
	// in-process NE/WFP decrypt-all forward (DeviceAuthenticatedInProcess) was already authenticated at the
	// (T) transport mTLS layer + admitted via the enrolled inventory, and is not a connector — so it skips
	// this gate. This is what lets decrypt-all egress run WITHOUT -lab-mode in production (GAP-1).
	if !config.DeviceAuthenticatedInProcess {
		if !authorizeEdgeRuntimeRequestForConnector(w, r, config.ConnectorSecret, config.LabMode, config.Registry, runtimeEvaluator.PolicyBundle.TenantID, config.RequireConnectorRuntimeSecret, config.TenantCARegistry) {
			return
		}
	}
	targetURL, err := swgHTTPEgressTargetURLFromRequest(r)
	if err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeBadRequest)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// ★★★ THE FLOW'S ORGANIZATION, NOT THIS NODE'S (2026-09-01). This built the decision request from the
	// policy bundle's tenant — the operator's, on any deployment that serves customers — so the decision, the
	// record and the upstream's connector lookup all belonged to the wrong organization. A decrypted flow to a
	// private asset was therefore routed by asking about somebody else, found no connector, and dialled the
	// private address directly into a timeout.
	//
	// The interception boundary now carries the organization across with the device identity beside it; a flow
	// that brings none leaves the bundle's value alone, which is right on a single-tenant deployment.
	flowBundle := runtimeEvaluator.PolicyBundle
	if tenant := edgeplane.FlowTenantFromContext(r.Context()); tenant != "" {
		flowBundle.TenantID = tenant
	}
	baseReq, err := decisionRequestForSWGHTTPEgress(r, targetURL, flowBundle)
	if err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeBadRequest)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req := enrichDecisionRequestWithSession(baseReq, config.SessionStore)
	req = enrichDecisionRequestWithTransportDevice(req, r.Context(), config.DeviceStore)
	req = enrichDecisionRequestWithRisk(req, config.DeviceStore, config.HighRiskOverlay, config.EnrolledLedger)
	req = deriveDecisionRequestActor(req, config.DelegatedGrants)
	var attestation runtimeWorkloadAttestationEvidence
	req, attestation, err = enrichDecisionRequestWithRuntimeAttestation(r, req, config.WorkloadAttestationSecret, config.LabMode, config.WorkloadAttestations, time.Now())
	if err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeUnauthorized)
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	dec := evaluateWithRuntimeEvidence(r.Context(), runtimeEvaluator, req, config.HumanApprovals, config.DelegatedGrants, config.NonHumanIdentities, time.Now())
	annotateRuntimeWorkloadAttestationMetadata(&dec, attestation)
	recordNonHumanIdentityRuntimeUse(r.Context(), config.NonHumanIdentities, &dec, time.Now())
	// An unmatched destination is recorded as a pending allow-policy candidate an admin can adopt into
	// explicit policy. Recording never enforces.
	//
	// This used to be gated on decision == "observe", which was Policy Learning's deferred default-deny. That
	// mechanism is gone (2026-08-05) and with it the "observe" decision, so the gate is now the condition it
	// was always really about: a request that matched NO policy. Keeping the capture matters more now, not
	// less — the same flow is denied rather than passed, so the candidate list is where an operator sees what
	// to adopt.
	if decision.IsDefaultDeny(dec) && config.PolicyCandidateStore != nil {
		if cs, ok := config.PolicyCandidateStore.(*policycandidate.Store); ok {
			_, _ = cs.ObserveUnmatchedFlow(candidateWriteContext(r.Context()), req.TenantID, req.FQDN, req.SNI, req.DestinationPort, "", time.Now().UTC())
		}
	}
	// Record the HTTP method (non-secret) so the AI-usage report can count "messages": a POST to an assistant is
	// a prompt / action, while GETs are page loads and polling. A finer "how much" than raw requests or sessions.
	if dec.Metadata == nil {
		dec.Metadata = map[string]any{}
	}
	dec.Metadata["http_method"] = strings.ToUpper(strings.TrimSpace(r.Method))
	// Per-request identity (log-all makes every request to a host a row; the path is what distinguishes them).
	// First-class method + path so the access log names the actual request, not just the host. The path comes from
	// the UPSTREAM target URL (targetURL), NOT r.URL — r.URL is the edge's own /swg/http-egress handler path. Path
	// only — the query string is deliberately dropped (tokens/PII, unbounded); gate it behind a logging policy.
	if m := strings.ToUpper(strings.TrimSpace(r.Method)); m != "" {
		dec.RequestMethod = &m
	}
	if targetURL != nil {
		p := targetURL.Path
		if p == "" {
			p = "/"
		}
		dec.RequestPath = &p
	}
	// The account the user is signed into the assistant with (from the request's JWT) — SEPARATE from the
	// corporate identity (dec.UserID). Recorded so the AI-usage dashboard shows BOTH; the two often differ (a
	// corporate user on a personal assistant account = shadow AI).
	// Read the AI-account identity with the SERVICE's fixed rule (precise per-service fields), not a generic
	// scan-every-token heuristic. email + name are separate columns (either blank when the service does not expose
	// it). ai_account (the single-value grouping) is email, else name, else the generic opaque-subject fallback.
	aiEmail, aiName := swgEgressIdentityForService(r, runtimeEvaluator.PolicyBundle.SaaSCatalog, saasApplicationIDFromDecision(dec))
	acct := aiEmail
	if acct == "" {
		acct = aiName
	}
	if acct == "" {
		acct = swgEgressUserFromRequest(r) // opaque subject / uncatalogued fallback (keeps a stable grouping key)
	}
	if acct != "" {
		dec.Metadata["ai_account"] = acct
	}
	if aiEmail != "" {
		dec.Metadata["ai_email"] = aiEmail
	}
	if aiName != "" {
		dec.Metadata["ai_name"] = aiName
	}
	// The app/process that originated the flow (endpoint agent, steer OPEN "a="): the "what tool" dimension.
	if app := edgeplane.SourceAppFromContext(r.Context()); app != "" {
		dec.Metadata["ai_app"] = app
	}
	// Pin the decision while THIS request is in flight so a live flow is never evicted (a same-flow inspection /
	// tool-call event can reference it mid-stream, and a thin-bandwidth download can run for hours). The defer
	// registered immediately below unpins it on EVERY exit — clean completion, early return, or abnormal
	// disconnect — starting the event-tail grace from completion. See docs/edge_decision_store_timeout_design.md.
	config.DecisionStore.MarkInFlight(dec)
	defer config.DecisionStore.MarkComplete(dec.ID)
	// The AI-usage report's "how much" is data VOLUME, not request / POST counts (which are HTTP chatter — one
	// chat is hundreds of polling/telemetry/asset requests). Record bytes SENT to the assistant (the prompt /
	// upload payload — a usage AND data-governance signal: how much data left for the AI) and bytes RECEIVED (the
	// model's output). Received is known only after the response streams, so the access-log append is DEFERRED to
	// the end and always runs (even on early return / denied), carrying the final byte counts. bytesSent is set
	// only once we actually forward (a denied request sent nothing to the AI). Fail-open on a log-write error:
	// availability of the decrypt path wins over a visibility log line.
	var bytesSent int64
	bytesReceived := new(int64)
	defer func() {
		// Policy-driven access logging: only policy ACTIONS and policy-designated categories (AI SaaS) earn a
		// row; a routine allow of unmarked traffic is NOT logged (that noise is ~99% of intercepted requests and
		// does not scale). -access-log-all restores full logging.
		if !shouldLogAccessDecision(dec) {
			return
		}
		if dec.Metadata == nil {
			dec.Metadata = map[string]any{}
		}
		if bytesSent > 0 {
			dec.Metadata["bytes_sent"] = bytesSent
		}
		if *bytesReceived > 0 {
			dec.Metadata["bytes_received"] = *bytesReceived
		}
		// The access log (the operator-facing audit record the Admin Console reads) names the RESOLVED SaaS
		// catalog application (a visible /admin/applications object), not the synthetic edgeplane.EdgeSWGEgressApplicationID
		// that the DecisionStore + readiness diagnostics keep as their internal SWG-egress marker. Uncatalogued
		// general web egress has no catalogued application, so it is logged with an empty application_id rather
		// than a phantom id that shows in the Console logs but corresponds to nothing an operator can open. A
		// shallow copy keeps the DecisionStore entry (and its by-application lookup) unchanged.
		logged := dec
		if saasApp := saasApplicationIDFromDecision(dec); saasApp != "" {
			logged.ApplicationID = saasApp
		} else if logged.ApplicationID == edgeplane.EdgeSWGEgressApplicationID {
			logged.ApplicationID = ""
		}
		if err := appendAccessDecisionLogs(r.Context(), config.Writer, config.DomainEventOutbox, logged, time.Now()); err != nil {
			log.Printf("swg_http_egress access log append failed: %v", err)
		}
	}()
	usagemeter.RecordUsageMeterDecision(config.UsageMeters, dec, time.Now())

	if !decisionPermitsConnectorRoute(dec.Decision) {
		// Steered browser "authenticate" flow: redirect to the tenant's IdP (via the clientless broker)
		// instead of a bare 401, and allow once a federated grant exists. Every other non-permitted decision
		// (deny, or a non-browser authenticate flow) serves its status code as before.
		if config.FederatedAuthGate != nil && config.FederatedAuthGate.isAuthRedirectCase(r, dec.Decision) {
			reqIdP, reqACR := authStepUpRequirements(dec)
			if !config.FederatedAuthGate.hasLiveGrantFor(dec.TenantID, edgeplane.TransportDeviceFromContext(r.Context()), reqACR) {
				setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomePolicyDenied)
				config.FederatedAuthGate.redirectToIdP(w, r, targetURL.String(), reqIdP, reqACR,
					edgeplane.TransportDeviceFromContext(r.Context()), dec.TenantID)
				return
			}
			// a live federated grant satisfies the authenticate requirement — fall through and forward.
		} else {
			setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomePolicyDenied)
			// ★★★ A NON-BROWSER HTTP CLIENT IS TOLD WHERE TO GO (2026-09-02; the justification CORRECTED
			// 2026-09-03 after the Windows box measured what actually happens).
			//
			// isAuthRedirectCase only redirects a flow whose Accept says text/html. Everything else got a
			// bare 401 carrying the decision and nothing else — no address at all — so this sets the header.
			//
			// ★★ WHAT IT DOES *NOT* DO, AND THE FIRST VERSION OF THIS COMMENT CLAIMED IT DID: reach a
			// steering agent. The agents mediate step-up on the STEERED NATIVE path — a native client cannot
			// follow a 302, so the Edge sends a mux STEPUP FRAME (see CONNECT /steer-mux) and the agent opens
			// the portal out of band. The Windows agent's header read is on CONNECT /steer, a single-flow
			// path this Edge does not serve at all any more. So the header here is read by the CLIENT
			// APPLICATION, not by an agent, and a browser ignores it because it already had the 302.
			//
			// That is still worth having — a curl, a CLI, an SDK is otherwise told a flow is refused and
			// nothing about how to satisfy it — but it is a smaller thing than "the agents already
			// understand this", which is what this comment said and was not true.
			if config.FederatedAuthGate != nil && decisionRequiresOIDCRedirect(dec.Decision) {
				reqIdP, reqACR := authStepUpRequirements(dec)
				if u := config.FederatedAuthGate.stepUpURLFor(targetURL.String(), reqIdP, reqACR,
					edgeplane.TransportDeviceFromContext(r.Context()), dec.TenantID); u != "" {
					w.Header().Set(stepUpChallengeHeader, u)
				}
			}
			writeJSON(w, statusForDecision(dec.Decision), dec)
			return
		}
	}
	// We are forwarding to the AI now — count the request body as data SENT to the assistant.
	if r.ContentLength > 0 {
		bytesSent = r.ContentLength
	}
	upstreamReq, err := newSWGHTTPEgressUpstreamRequest(r, targetURL)
	if err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeBadRequest)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rewritten, rewriteResult, err := rewriteEdgeSWGHTTPRequest(upstreamReq, dec, config.SWGRuntime, swghttprewrite.HeaderValueMap(runtimeEvaluator.TenantRestrictionHeaderValues))
	if err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeRewriteFailed)
		writeError(w, http.StatusBadGateway, err)
		return
	}
	tlsReadiness := swg.EdgeSWGTLSReadinessStatusFor(runtimeEvaluator, config.SWGRuntime, config.InspectionEvents, edgeplane.EdgeSWGHTTPEgressPath)
	precondition := edgeSWGHTTPEgressReadinessPreconditionFor(tlsReadiness, rewriteResult, config.LabMode)
	// The tenant-restriction rewrite is recorded ONCE, as an inspection event (below). The former audit twin
	// (swg_http_egress_rewrite) was removed : a header rewrite is an
	// inspection OUTCOME, not an admin action, and it flooded the admin-audit stream with per-request system
	// rows that buried real admin actions. The non-secret metadata + no-leak guarantee live on the inspection
	// event now.
	if _, err := appendEdgeSWGHTTPEgressInspectionEvent(r.Context(), config.Writer, config.InspectionEvents, config.DomainEventOutbox, dec, rewriteResult, precondition, time.Now()); err != nil {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeInternalError)
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if precondition.Status == "readiness_dependency" {
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeReadinessDependency)
		writeJSON(w, http.StatusPreconditionRequired, edgeSWGHTTPEgressReadinessDependencyResponseFor(dec, tlsReadiness, precondition))
		return
	}
	// DLP: observe (tee) or, when the tenant policy interrupts, block/authenticate (hold-before-release
	// guard). finalizeObserve emits the observe event at exit; a guard trip is handled right after Do.
	dlpHook := installEdgeSWGHTTPEgressDLP(rewritten, config, dec)
	defer func() { dlpHook.finalizeObserve(r.Context()) }()
	// A buffered file upload is decided at install (before forwarding): a block denies it here so the file is
	// never sent upstream.
	if dlpHook.blocked() {
		dlpHook.respondBlocked(w, r)
		return
	}
	// ★★★ THE ORGANIZATION THIS FLOW BELONGS TO RIDES WITH IT (2026-09-01). The upstream client is built once
	// at startup and holds the tenant of the policy bundle THIS EDGE pulled — the operator's, on any
	// deployment that serves customers. Its connector lookup therefore found no connector for any customer's
	// destination, fell through to the direct dialer, and was refused by the SSRF guard with advice to publish
	// the destination behind a connector, which it already was. See edgeplane.WithFlowTenant.
	if tenant := strings.TrimSpace(req.TenantID); tenant != "" {
		rewritten = rewritten.WithContext(edgeplane.WithFlowTenant(rewritten.Context(), tenant))
	}
	// ★★★ The Edge is the TLS CLIENT to whatever this flow reaches, and for a private asset that means an
	// authority only this organization knows. Widening happens per flow because the organization is per flow —
	// see the_edge_is_a_client_to_the_private_asset.go. Public destinations are untouched.
	upstreamClient := swgHTTPEgressProxyClient(config.ProxyClient, swgHTTPEgressNetworkExtensionRuntimeUsed(r))
	if flowTenant := edgeplane.FlowTenantFromContext(r.Context()); flowTenant != "" {
		upstreamClient.Transport = upstreamTransportTrustingTheOrganizationsPrivateAssets(
			upstreamClient.Transport, config.InternalCAs, flowTenant, time.Now().UTC())
	}
	if rewritten.URL.Scheme == "https" {
		upstreamClient.Transport = upstreamtrust.ForHost(upstreamClient.Transport, rewritten.URL.Hostname())
	}
	resp, err := upstreamClient.Do(rewritten)
	// A DLP guard trip denies the upload before the secret leaves: emit the enforcing event and respond
	// (403 block / 401 authenticate) WITHOUT relaying. Checked via guard state so it is robust to how the
	// client wraps the aborted-body error.
	if dlpHook.blocked() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		dlpHook.respondBlocked(w, r)
		return
	}
	if err != nil {
		// An origin the edge cannot cleanly intercept on egress can't be inspected. The notable non-fixable
		// case is the non-standard TLS `unrecognized_name` warning an origin sends for its OWN SNI (seen on some
		// IDN hosts, e.g. xn--t8jx73hngb.com [お名前.com]): strict TLS stacks — Go here, and macOS LibreSSL —
		// reject it; lenient ones (Chrome/BoringSSL) tolerate it. Since the edge (Go) can't decrypt such an
		// origin, surface it as a cert-pinning bypass CANDIDATE so an admin can adopt a decrypt-bypass in the
		// Pinned Sites view — then the client's own TLS reaches the origin. Detection only proposes; it NEVER
		// auto-bypasses (no inspection is silently dropped).
		if swgEgressIsUnrecognizedName(err) {
			if cs, ok := config.PolicyCandidateStore.(*policycandidate.Store); ok {
				_, _ = cs.ObserveCertPinFailure(candidateWriteContext(r.Context()), req.TenantID, req.FQDN, req.SNI, req.DestinationPort, "egress_tls_unrecognized_name", time.Now().UTC())
			}
		}
		setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed)
		setSWGHTTPEgressUpstreamRequestErrorCategory(w, err)
		log.Printf("swg egress: upstream request failed host=%s transport=%T ne_runtime=%v: %v",
			r.Host, swgHTTPEgressProxyClient(config.ProxyClient, swgHTTPEgressNetworkExtensionRuntimeUsed(r)).Transport,
			swgHTTPEgressNetworkExtensionRuntimeUsed(r), err)
		// ★★★ THE PERSON READING THIS LOST A PAGE (2026-08-30). Until now the guard's own words went to the
		// browser: "ssrf egress guard: egress to internal/link-local/loopback/metadata address 10.30.1.221 is
		// blocked" — written for whoever is trying to pivot this gateway into somebody's network, and handed
		// instead to an administrator whose managed Mac had just stopped being able to open their own
		// deployment's Console. On a fleet where every device is steered, which is the point of the product,
		// this is the sentence that decides whether the next hour is spent on the right thing.
		//
		// It says what happened and what the answer is. The raw error stays in the log above, where the
		// operator of the deployment can read it and the person at the browser cannot.
		if swgHTTPEgressUpstreamRequestErrorCategory(err) == edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryInternalDestination {
			writeError(w, http.StatusBadGateway, fmt.Errorf(
				"%s is on an internal network, and this gateway carries traffic to the public internet only. "+
					"Internal destinations are reached as applications published through a connector — publish it "+
					"there, or, for devices that can already route to it on their own network, add it to this "+
					"organization's Sites to Bypass", r.Host))
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	setSWGHTTPEgressOutcome(w, edgeplane.EdgeSWGHTTPEgressOutcomeUpstreamResponse)
	if swgHTTPEgressIsWebSocketUpgrade(r) && resp.StatusCode == http.StatusSwitchingProtocols {
		if tunnelWriter, ok := w.(swgHTTPEgressWebSocketTunnelWriter); ok {
			if err := tunnelWriter.TunnelSWGHTTPEgressWebSocket(resp); err != nil {
				setSWGHTTPEgressUpstreamRequestErrorCategory(w, err)
				log.Printf("proxy SWG HTTP egress websocket tunnel: %v", err)
			}
			return
		}
		writeError(w, http.StatusBadGateway, fmt.Errorf("websocket tunnel response writer is not supported"))
		return
	}
	// Reconcile the upstream Content-Encoding with what the DOWNSTREAM client actually accepts. The browser-mimic
	// egress can make Cloudflare return br (a Chrome-fingerprint optimization) to a non-browser client that never
	// advertised it — that client then can't decode the body ("error decoding response body"; a Rust reqwest-based client sign-in
	// failure, handoff_edge_browser_mimic_content_encoding_mismatch.md). Decompress-to-identity in that case; a
	// browser that accepts br is passed through unchanged. MUST run before copying headers / relaying the body.
	edgeplane.ReconcileSWGEgressContentEncoding(r, resp)
	copySWGEgressResponseHeaders(w.Header(), resp.Header)
	if config.StripAltSvc {
		// Keep the client on the inspectable TCP path: drop the Alt-Svc header so it never switches to
		// HTTP/3 (QUIC). QUIC is un-interceptable, so a decrypt-all SSE disables it by default (matching the
		// endpoint UDP/443 drop) and avoids the QUIC-timeout fallback that slows QUIC-preferring clients.
		stripQUICAdvertisement(w.Header())
	}
	if swgHTTPEgressSkipsUpstreamBody(r.Method, resp.StatusCode) {
		suppressSWGEgressResponseBodyHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		return
	}
	w.WriteHeader(resp.StatusCode)
	// Count the response body as bytes RECEIVED from the assistant (the deferred access-log append reads this).
	respBody := &swgEgressCountingReader{r: resp.Body, n: bytesReceived}
	if swgEgressResponseShouldStreamIncrementally(resp) {
		// Unknown-length (chunked / EOF-framed) response — flush each chunk so a token / SSE stream reaches the
		// browser AS IT ARRIVES instead of stalling in the recorder's buffer (Google AI Mode "something went
		// wrong"). The recorder only switched to write-through on an explicit Flush, a text/event-stream
		// Content-Type, or once buffered bytes crossed a threshold; a slow non-SSE token stream hit none in time.
		if err := streamSWGEgressResponseBody(w, respBody); err != nil {
			logSWGEgressRelayError("stream", err)
		}
	} else {
		// Fixed Content-Length response: buffered relay so the recorder can Content-Length-frame it and keep the
		// connection alive — avoids forcing Connection: close on every response (a per-request socket storm under
		// decrypt-all).
		if _, err := io.Copy(w, respBody); err != nil {
			logSWGEgressRelayError("buffered", err)
		}
	}
}

// logSWGEgressRelayError reports a failure relaying an upstream response to the client.
//
// Both call sites used the SAME literal ("proxy SWG HTTP egress response: %v") on two different branches, so the
// line could not tell an operator WHICH relay failed — and the branch is the diagnostic point: the streaming path
// exists specifically for unknown-length token/SSE streams, and a failure there means something different from a
// failure copying a fixed Content-Length body (, "same message twice — deduplicate the literal").
//
// The level split matters more than the string. A client that navigates away or cancels mid-response aborts the
// relay, and that is NORMAL: measured live, this fired as "context canceled" during ordinary browsing. Logging it
// at WARN/ERROR would train the operator to ignore the line — which is how the genuine relay failure (the one
// worth waking up for) gets missed.
func logSWGEgressRelayError(relay string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) || edgeplane.NetworkExtensionLabTLSBenignTunnelCopyError(err) {
		logDebugf("swg_egress_relay_aborted relay=%s category=%s", relay, edgeplane.NetworkExtensionLabTLSErrorCategory(err))
		return
	}
	logWarnf("swg_egress_relay_failed relay=%s category=%s err=%v", relay, edgeplane.NetworkExtensionLabTLSErrorCategory(err), err)
}

// swgEgressCountingReader tallies bytes read (the response body relayed to the client) into *n, for the AI-usage
// report's data-volume metric.
type swgEgressCountingReader struct {
	r io.Reader
	n *int64
}

func (c *swgEgressCountingReader) Read(p []byte) (int, error) {
	m, err := c.r.Read(p)
	if m > 0 && c.n != nil {
		*c.n += int64(m)
	}
	return m, err
}

// swgEgressResponseShouldStreamIncrementally reports whether the upstream response must be flushed to the client
// chunk-by-chunk rather than buffered. True for an UNKNOWN-LENGTH response (ContentLength < 0 = chunked /
// EOF-framed, e.g. a streaming token feed) whose bytes must reach the browser as they arrive — buffering stalls
// them and the page errors out. Also true for text/event-stream. A fixed Content-Length response stays buffered
// so it can be length-framed and keep-alive'd.
func swgEgressResponseShouldStreamIncrementally(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.ContentLength < 0 {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	return strings.HasPrefix(ct, "text/event-stream")
}

// streamSWGEgressResponseBody relays the upstream body to the client, FLUSHING after each chunk so an
// incremental / streaming response (SSE, a chunked AI-mode token stream, long-poll, gRPC-web) reaches the browser
// AS IT ARRIVES. The Flush drives the interception recorder into write-through mode. Mirrors
// net/http/httputil.ReverseProxy's streaming flush. A plain io.Copy (no flush) buffers and breaks such streams.
func streamSWGEgressResponseBody(w http.ResponseWriter, body io.Reader) error {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

func swgHTTPEgressProxyClient(base *http.Client, stabilizeNetworkExtensionRuntime bool) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	if stabilizeNetworkExtensionRuntime {
		client.Transport = stableSWGHTTPEgressNetworkExtensionRuntimeTransport(client.Transport)
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// stableSWGHTTPEgressNetworkExtensionRuntimeTransport returns the SHARED, pooled upstream transport for the NE
// decrypt-and-forward path. It is built ONCE per base transport and cached: previously it cloned a fresh
// transport on every request (so the connection pool was always empty) AND disabled keep-alives, so every
// intercepted subresource — every image on a page like rakuten.co.jp — paid a brand-new TCP+TLS handshake to
// the origin. A page with dozens of images from one CDN therefore did dozens of handshakes and felt sluggish /
// dropped images under concurrency. Reuse is safe: net/http pools per origin host:port, and each request is
// independently policy-checked + rewritten BEFORE it is sent, so a shared connection to the SAME public origin
// carries no per-user/per-tenant state.
var stableNETransportCache sync.Map // base http.RoundTripper -> http.RoundTripper

func stableSWGHTTPEgressNetworkExtensionRuntimeTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if cached, ok := stableNETransportCache.Load(base); ok {
		return cached.(http.RoundTripper)
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		stableNETransportCache.Store(base, base)
		return base
	}
	stable := transport.Clone()
	// Enable HTTP/2 to the upstream. SaaS auth hosts such as accounts.google.com are
	// effectively HTTP/2-only: when offered http/1.1 they still reply with HTTP/2
	// frames, which Go's HTTP/1.x transport reports as a malformed response
	// (http2_handshake_failed → the SWG returns 502). Restoring automatic HTTP/2
	// negotiation lets the decrypt-and-forward path reach those upstreams. The
	// recorder buffers the full response via io.Copy, so the upstream wire protocol
	// is independent of how the response is relayed back to the browser.
	stable.ForceAttemptHTTP2 = true
	stable.TLSNextProto = nil
	// Pool + reuse origin connections so a multi-resource page does not pay a fresh TCP+TLS handshake per
	// subresource. Bounded so a fan-out cannot exhaust file descriptors. Keyed per origin host:port by net/http;
	// with ForceAttemptHTTP2 most CDNs collapse to one multiplexed h2 connection per host.
	stable.DisableKeepAlives = false
	stable.MaxIdleConns = 256
	stable.MaxIdleConnsPerHost = 32
	stable.MaxConnsPerHost = 64
	stable.IdleConnTimeout = 90 * time.Second
	var result http.RoundTripper = stable
	actual, _ := stableNETransportCache.LoadOrStore(base, result)
	return actual.(http.RoundTripper)
}

// swgEgressIsUnrecognizedName reports whether err is the origin's TLS unrecognized_name alert (RFC 6066). Go's
// crypto/tls surfaces this warning-level alert as a fatal handshake error ("remote error: tls: unrecognized
// name"); browsers/curl ignore it. We detect it to retry the egress without SNI.
func swgEgressIsUnrecognizedName(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unrecognized name")
}

func setSWGHTTPEgressOutcome(w http.ResponseWriter, outcome string) {
	outcome = strings.TrimSpace(outcome)
	if outcome == "" {
		return
	}
	if writer, ok := w.(swgHTTPEgressOutcomeWriter); ok {
		writer.SetSWGHTTPEgressOutcome(outcome)
	}
}

func setSWGHTTPEgressUpstreamRequestErrorCategory(w http.ResponseWriter, err error) {
	category := swgHTTPEgressUpstreamRequestErrorCategory(err)
	if writer, ok := w.(swgHTTPEgressUpstreamErrorCategoryWriter); ok {
		writer.SetSWGHTTPEgressUpstreamErrorCategory(category)
	}
}

func swgHTTPEgressUpstreamRequestErrorCategory(err error) string {
	if err == nil {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNone
	}
	if errors.Is(err, context.Canceled) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError
	}
	var unknownAuthorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &unknownAuthorityError) ||
		errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalidError) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryCertificateError
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNRESET:
			return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionReset
		case syscall.ECONNREFUSED:
			return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionRefused
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNetworkUnreachable
		}
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection
	}
	var tlsRecordHeaderError tls.RecordHeaderError
	if errors.As(err, &tlsRecordHeaderError) {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError
	}
	msg := strings.ToLower(err.Error())
	switch {
	// ★ BEFORE THE CERTIFICATE ARM, which "internal/link-local/loopback/metadata" would not hit but a future
	// wording might: the guard's answer is a routing decision with a remedy, and any other category sends the
	// reader somewhere else. Matched on the guard's own prefix rather than a sentinel error because the text
	// crosses a process boundary on the broker path (see swg.CheckEgressDestination).
	case strings.Contains(msg, "ssrf egress guard"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryInternalDestination
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "unknown authority"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryCertificateError
	case strings.Contains(msg, "tls") && strings.Contains(msg, "handshake"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError
	case strings.Contains(msg, "server gave http response to https client"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError
	case strings.Contains(msg, "connection reset"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionReset
	case strings.Contains(msg, "connection refused"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionRefused
	case strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryNetworkUnreachable
	case strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "client connection lost") ||
		strings.Contains(msg, "unexpected eof"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection
	case strings.Contains(msg, "stream error:") ||
		strings.Contains(msg, "http2:") ||
		strings.Contains(msg, "http/2"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryHTTP2Transport
	case strings.Contains(msg, "malformed http") || strings.Contains(msg, "malformed response"):
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryMalformedResponse
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.EqualFold(opErr.Op, "dial") && strings.Contains(strings.ToLower(opErr.Net), "tcp") {
		return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryTCPConnectError
	}
	return edgeplane.EdgeSWGHTTPEgressUpstreamErrorCategoryOtherNonSecret
}

func rewriteEdgeSWGHTTPRequest(r *http.Request, dec model.AccessDecision, runtime swg.RuntimeConfig, snapshots ...swghttprewrite.HeaderValueResolver) (*http.Request, swghttprewrite.RewriteResult, error) {
	var resolver swghttprewrite.HeaderValueResolver = runtime.TenantRestrictionResolver
	if len(snapshots) > 0 {
		resolver = tenantRestrictionSnapshotResolver{snapshots[0], resolver}
	}
	rewritten, result, err := swghttprewrite.RewriteRequestFromDecisionWithOptions(r, dec, resolver, swghttprewrite.RewriteRequestOptions{EdgeRuntimeRewritePathObserved: true})
	networkExtensionRuntimeUsed := swgHTTPEgressNetworkExtensionRuntimeUsed(r)
	result.RuntimeTLSDecryptionObserved = result.RuntimeTLSDecryptionObserved || runtime.RuntimeTLSDecryptionObserved
	result.RuntimeHeaderInjectionObserved = result.RuntimeHeaderInjectionObserved || runtime.RuntimeHeaderInjectionObserved || (networkExtensionRuntimeUsed && result.HeaderApplied)
	result.NetworkExtensionRuntimeUsed = result.NetworkExtensionRuntimeUsed || runtime.NetworkExtensionRuntimeUsed || networkExtensionRuntimeUsed
	return rewritten, result, err
}

func appendEdgeSWGHTTPEgressRewriteAudit(ctx context.Context, writer *logs.Writer, outbox adminAuditOutboxDeadReader, dec model.AccessDecision, result swghttprewrite.RewriteResult, precondition edgeSWGHTTPEgressReadinessPrecondition, now time.Time) error {
	targetType := "swg_http_egress_rewrite"
	targetID := dec.ID
	action := "rewrite"
	auditResult := "success"
	reason := "Edge SWG HTTP egress rewrite result recorded as non-secret metadata."
	audit := model.AuditLog{
		ID:               randomEdgeID("audit_swg_http_egress_rewrite_", now),
		TenantID:         dec.TenantID,
		EventType:        edgeplane.EdgeSWGHTTPEgressRewriteEvent,
		TargetType:       &targetType,
		TargetID:         &targetID,
		Action:           &action,
		Result:           &auditResult,
		Reason:           &reason,
		AccessDecisionID: &dec.ID,
		PolicyID:         &dec.PolicyID,
		PolicyBundleID:   &dec.PolicyBundleID,
		EdgeRegionID:     dec.EdgeRegionID,
		EdgeClusterID:    dec.EdgeClusterID,
		Timestamp:        now.UTC().Format(time.RFC3339),
		Metadata:         edgeSWGHTTPEgressRewriteAuditMetadata(result, precondition),
	}
	return appendAdminAudit(ctx, writer, outbox, audit, now)
}

// edgeSWGHTTPEgressInspectionEventMeaningful reports whether the tenant-restriction inspection event carries a
// real OUTCOME worth a row, vs a per-request no-op. The vast majority of intercepted flows have NO tenant
// restriction configured for their destination — recording "inspected, nothing to enforce, forwarded" per
// request floods the Inspection/DLP tab with identical info rows and hides the real findings (the access log
// already records that the flow was decrypted — no visibility gap). A row is meaningful only when an enforcement
// or an operational decision actually happened: a restriction header was injected, a TLS bypass was applied, or
// egress was BLOCKED on a readiness dependency. See
func edgeSWGHTTPEgressInspectionEventMeaningful(result swghttprewrite.RewriteResult, precondition edgeSWGHTTPEgressReadinessPrecondition) bool {
	if result.HeaderApplied || result.TLSBypassApplied {
		return true
	}
	if dep := strings.TrimSpace(precondition.ReadinessDependency); dep != "" && dep != "none" {
		return true
	}
	return strings.TrimSpace(precondition.Status) == "readiness_dependency"
}

func appendEdgeSWGHTTPEgressInspectionEvent(ctx context.Context, writer *logs.Writer, store *inspection.Store, outbox domainEventOutboxWriter, dec model.AccessDecision, result swghttprewrite.RewriteResult, precondition edgeSWGHTTPEgressReadinessPrecondition, now time.Time) (model.InspectionEvent, error) {
	if writer == nil {
		return model.InspectionEvent{}, fmt.Errorf("inspection event writer is not configured")
	}
	if store == nil {
		return model.InspectionEvent{}, fmt.Errorf("inspection event store is not configured")
	}
	// Suppress the per-request no-op: only record when an enforcement / bypass / readiness block actually
	// happened. A plain intercepted-and-forwarded flow with no restriction leaves no inspection row.
	if !edgeSWGHTTPEgressInspectionEventMeaningful(result, precondition) {
		return model.InspectionEvent{}, nil
	}
	// Context so the row says WHO was inspected accessing WHAT (not just "a rewrite happened"): the identity,
	// device, and destination from the decision. Non-secret (ids + a hostname). The destination rides metadata
	// because model.InspectionEvent has no destination field; the Console reads it from there for the Resource
	// column.
	inspMeta := edgeSWGHTTPEgressInspectionEventMetadata(result, precondition)
	if dst := strings.TrimSpace(stringPtrValue(dec.Destination)); dst != "" {
		inspMeta["destination"] = dst
	}
	inspUser := strings.TrimSpace(stringPtrValue(dec.SubjectUserID))
	if inspUser == "" {
		inspUser = strings.TrimSpace(stringPtrValue(dec.UserID))
	}
	var inspUserPtr *string
	if inspUser != "" {
		inspUserPtr = &inspUser
	}
	event := model.InspectionEvent{
		ID:                  randomEdgeID("ie_swg_http_egress_rewrite_", now),
		TenantID:            dec.TenantID,
		AccessDecisionID:    stringPtr(dec.ID),
		UserID:              inspUserPtr,
		DeviceID:            dec.DeviceID,
		ApplicationID:       stringPtr(dec.ApplicationID),
		InspectionProfileID: stringPtr(stringPtrValue(dec.InspectionProfileID)),
		InspectionMode:      stringPtr(stringPtrValue(dec.InspectionMode)),
		ContentType:         stringPtr("application/vnd.dsse.swg-rewrite-metadata+json"),
		FindingType:         stringPtr("saas_tenant_restriction_rewrite"),
		Severity:            stringPtr("info"),
		PayloadStored:       false,
		Masked:              true,
		Timestamp:           now.UTC().Format(time.RFC3339),
		Metadata:            inspMeta,
	}
	if err := normalizeInspectionEvent(&event, dec.TenantID, now); err != nil {
		return model.InspectionEvent{}, err
	}
	event = store.Upsert(event)
	if err := writer.Append("inspection_events.log.jsonl", event); err != nil {
		return model.InspectionEvent{}, err
	}
	if envelope, err := domainEventOutboxEnvelopeFromInspectionEvent(event, now); err != nil {
		log.Printf("domain event outbox SWG inspection envelope: %v", err)
	} else {
		appendDomainEventOutbox(ctx, outbox, envelope, now)
	}
	return event, nil
}

func edgeSWGHTTPEgressRewriteAuditMetadata(result swghttprewrite.RewriteResult, precondition edgeSWGHTTPEgressReadinessPrecondition) map[string]any {
	metadata := map[string]any{
		"swg_rewrite_audit_version":                      "v1",
		"swg_rewrite_metadata_recorded_scope":            "non_secret",
		"edge_http_egress_handler_path":                  edgeplane.EdgeSWGHTTPEgressPath,
		"edge_runtime_rewrite_path_observed":             result.EdgeRuntimeRewritePathObserved,
		"local_http_rewrite_harness_observation":         result.LocalHTTPRewriteHarnessObservation,
		"decision_id":                                    result.DecisionID,
		"policy_id":                                      result.PolicyID,
		"saas_application_id":                            result.SaaSApplicationID,
		"header_name":                                    result.HeaderName,
		"operator_config_ref":                            result.HeaderValueRef,
		"header_value_kind":                              result.HeaderValueKind,
		"operator_config_ref_resolved":                   result.HeaderValueResolved,
		"header_rewrite_applied":                         result.HeaderApplied,
		"inject_action_seen":                             result.InjectActionSeen,
		"tls_bypass_applied":                             result.TLSBypassApplied,
		"tls_bypass_rule_id":                             result.TLSBypassRuleID,
		"header_injection_suppressed_by_bypass":          result.HeaderInjectionSuppressedByBypass,
		"inspection_route_category":                      result.InspectionRouteCategory,
		"inspection_execution_scope":                     result.InspectionExecutionScope,
		"edge_tls_policy_decision":                       result.EdgeTLSPolicyDecision,
		"google_workspace_rewrite_outcome":               edgeSWGHTTPEgressRewriteOutcome(result, "saas_google_workspace"),
		"microsoft_365_rewrite_outcome":                  edgeSWGHTTPEgressRewriteOutcome(result, "saas_microsoft_365"),
		"tls_bypass_suppression_outcome":                 edgeSWGHTTPEgressTLSBypassSuppressionOutcome(result),
		"header_value_material_logged":                   result.HeaderValueMaterialLogged,
		"header_value_material_in_audit":                 false,
		"header_value_material_in_api_readback":          false,
		"header_value_material_in_report":                false,
		"operator_config_value_material_logged":          result.HeaderValueMaterialLogged,
		"operator_config_value_material_in_audit":        false,
		"operator_config_value_material_in_api_readback": false,
		"operator_config_value_material_in_report":       false,
		"runtime_tls_decryption_observed":                result.RuntimeTLSDecryptionObserved,
		"runtime_header_injection_observed":              result.RuntimeHeaderInjectionObserved,
		"network_extension_runtime_used":                 result.NetworkExtensionRuntimeUsed,
		"swg_runtime_traffic_observed":                   false,
		"real_tls_interception_runtime_executed":         false,
		"mac_ca_trust_mutated":                           false,
		"p4_packaging_mdm_signing_install_started":       false,
		"shipping_product_claimed":                       false,
		"production_scale_claimed":                       false,
		"mvp_pilot_success_claimed":                      false,
		"windows_work_started":                           false,
	}
	mergeSWGHTTPEgressReadinessPreconditionMetadata(metadata, precondition)
	return metadata
}

func edgeSWGHTTPEgressInspectionEventMetadata(result swghttprewrite.RewriteResult, precondition edgeSWGHTTPEgressReadinessPrecondition) map[string]any {
	metadata := map[string]any{
		"swg_inspection_event_version":                   "swg_inspection.v1",
		"swg_inspection_metadata_recorded_scope":         "non_secret",
		"source_audit_event_type":                        edgeplane.EdgeSWGHTTPEgressRewriteEvent,
		"edge_http_egress_handler_path":                  edgeplane.EdgeSWGHTTPEgressPath,
		"edge_runtime_rewrite_path_observed":             result.EdgeRuntimeRewritePathObserved,
		"local_http_rewrite_harness_observation":         result.LocalHTTPRewriteHarnessObservation,
		"access_decision_id":                             result.DecisionID,
		"policy_id":                                      result.PolicyID,
		"saas_application_id":                            result.SaaSApplicationID,
		"header_name":                                    result.HeaderName,
		"operator_config_ref":                            result.HeaderValueRef,
		"header_value_kind":                              result.HeaderValueKind,
		"operator_config_ref_resolved":                   result.HeaderValueResolved,
		"header_rewrite_applied":                         result.HeaderApplied,
		"inject_action_seen":                             result.InjectActionSeen,
		"tls_bypass_applied":                             result.TLSBypassApplied,
		"tls_bypass_rule_id":                             result.TLSBypassRuleID,
		"header_injection_suppressed_by_bypass":          result.HeaderInjectionSuppressedByBypass,
		"inspection_route_category":                      result.InspectionRouteCategory,
		"inspection_execution_scope":                     result.InspectionExecutionScope,
		"edge_tls_policy_decision":                       result.EdgeTLSPolicyDecision,
		"google_workspace_rewrite_outcome":               edgeSWGHTTPEgressRewriteOutcome(result, "saas_google_workspace"),
		"microsoft_365_rewrite_outcome":                  edgeSWGHTTPEgressRewriteOutcome(result, "saas_microsoft_365"),
		"tls_bypass_suppression_outcome":                 edgeSWGHTTPEgressTLSBypassSuppressionOutcome(result),
		"header_value_material_logged":                   result.HeaderValueMaterialLogged,
		"header_value_material_in_inspection_event":      false,
		"header_value_material_in_api_readback":          false,
		"header_value_material_in_report":                false,
		"operator_config_value_material_logged":          result.HeaderValueMaterialLogged,
		"operator_config_value_material_in_inspection":   false,
		"operator_config_value_material_in_api_readback": false,
		"operator_config_value_material_in_report":       false,
		"runtime_tls_decryption_observed":                result.RuntimeTLSDecryptionObserved,
		"runtime_header_injection_observed":              result.RuntimeHeaderInjectionObserved,
		"network_extension_runtime_used":                 result.NetworkExtensionRuntimeUsed,
		"swg_runtime_traffic_observed":                   false,
		"real_tls_interception_runtime_executed":         false,
		"mac_ca_trust_mutated":                           false,
		"p4_packaging_mdm_signing_install_started":       false,
		"shipping_product_claimed":                       false,
		"production_scale_claimed":                       false,
		"mvp_pilot_success_claimed":                      false,
		"windows_work_started":                           false,
	}
	mergeSWGHTTPEgressReadinessPreconditionMetadata(metadata, precondition)
	return metadata
}

func edgeSWGHTTPEgressReadinessPreconditionFor(status swg.EdgeSWGTLSReadinessStatus, result swghttprewrite.RewriteResult, devMode bool) edgeSWGHTTPEgressReadinessPrecondition {
	dependency := "none"
	preconditionStatus := "satisfied"
	egressForwarded := true
	suppressedByTLSBypass := false
	if result.TLSBypassApplied {
		preconditionStatus = "tls_bypass_exempted"
		suppressedByTLSBypass = true
	} else if status.DefaultTLSDecryptionRequired && !status.DefaultTLSDecryptionObserved {
		dependency = edgeplane.EdgeSWGHTTPEgressReadinessReason
		if devMode {
			preconditionStatus = "lab_mode_diagnostic_only"
		} else {
			preconditionStatus = "readiness_dependency"
			egressForwarded = false
		}
	} else if status.MacCATrustRequired && !status.MacCATrustObserved {
		dependency = edgeplane.EdgeSWGHTTPEgressMacCAReason
		if devMode {
			preconditionStatus = "lab_mode_diagnostic_only"
		} else {
			preconditionStatus = "readiness_dependency"
			egressForwarded = false
		}
	} else if status.MacCATrustRequired && status.MacCATrustObserved {
		preconditionStatus = "mac_ca_trust_observed"
	} else if status.DefaultTLSDecryptionRequired && status.DefaultTLSDecryptionObserved {
		preconditionStatus = "tls_readiness_observed"
	}
	return edgeSWGHTTPEgressReadinessPrecondition{
		Checked:                       true,
		LabMode:                       devMode,
		Status:                        preconditionStatus,
		ReadinessDependency:           dependency,
		EgressForwarded:               egressForwarded,
		TLSReadinessStatusPath:        status.ReadbackPath,
		TLSReadinessStatusVersion:     status.SchemaVersion,
		DefaultTLSDecryptionRequired:  status.DefaultTLSDecryptionRequired,
		DefaultTLSDecryptionObserved:  status.DefaultTLSDecryptionObserved,
		DefaultTLSDecryptionStatus:    status.DefaultTLSDecryptionStatus,
		MacCATrustRequired:            status.MacCATrustRequired,
		MacCATrustObserved:            status.MacCATrustObserved,
		MacCATrustStatus:              status.MacCATrustStatus,
		TenantHeaderDependencyCount:   status.TenantHeaderRewriteDependencyCount,
		HeaderNamesVisible:            edgeSWGTLSReadinessHeaderNames(status),
		OperatorConfigRefsVisible:     edgeSWGTLSReadinessOperatorConfigRefs(status),
		PerDestinationTLSBypassNeeded: status.PerDestinationTLSBypassRequired,
		TLSBypassRuleCount:            status.TLSBypassRuleCount,
		CurrentRequestTLSBypass:       result.TLSBypassApplied,
		CurrentRequestTLSBypassRuleID: result.TLSBypassRuleID,
		SuppressedByTLSBypass:         suppressedByTLSBypass,
	}
}

func edgeSWGHTTPEgressReadinessDependencyResponseFor(dec model.AccessDecision, status swg.EdgeSWGTLSReadinessStatus, precondition edgeSWGHTTPEgressReadinessPrecondition) edgeSWGHTTPEgressReadinessDependencyResponse {
	return edgeSWGHTTPEgressReadinessDependencyResponse{
		SchemaVersion:                       edgeplane.EdgeSWGHTTPEgressReadinessSchema,
		Status:                              "readiness_dependency",
		ReadinessDependency:                 precondition.ReadinessDependency,
		EdgeHTTPegressHandlerPath:           edgeplane.EdgeSWGHTTPEgressPath,
		TLSReadinessStatusPath:              precondition.TLSReadinessStatusPath,
		TLSReadinessStatusVersion:           precondition.TLSReadinessStatusVersion,
		TenantID:                            dec.TenantID,
		PolicyBundleID:                      dec.PolicyBundleID,
		PolicyBundleVersion:                 status.PolicyBundleVersion,
		AccessDecisionID:                    dec.ID,
		PolicyID:                            dec.PolicyID,
		ApplicationID:                       dec.ApplicationID,
		SaaSApplicationID:                   saasApplicationIDFromDecision(dec),
		LabMode:                             precondition.LabMode,
		EgressForwarded:                     precondition.EgressForwarded,
		DefaultTLSDecryptionRequired:        precondition.DefaultTLSDecryptionRequired,
		DefaultTLSDecryptionObserved:        precondition.DefaultTLSDecryptionObserved,
		DefaultTLSDecryptionStatus:          precondition.DefaultTLSDecryptionStatus,
		MacCATrustRequired:                  precondition.MacCATrustRequired,
		MacCATrustObserved:                  precondition.MacCATrustObserved,
		MacCATrustStatus:                    precondition.MacCATrustStatus,
		TenantHeaderRewriteDependencyCount:  precondition.TenantHeaderDependencyCount,
		HeaderNamesVisible:                  append([]string{}, precondition.HeaderNamesVisible...),
		OperatorConfigRefsVisible:           append([]string{}, precondition.OperatorConfigRefsVisible...),
		PerDestinationTLSBypassRequired:     precondition.PerDestinationTLSBypassNeeded,
		TLSBypassRuleCount:                  precondition.TLSBypassRuleCount,
		CurrentRequestTLSBypassApplied:      precondition.CurrentRequestTLSBypass,
		CurrentRequestTLSBypassRuleID:       precondition.CurrentRequestTLSBypassRuleID,
		TLSReadinessSuppressedByTLSBypass:   precondition.SuppressedByTLSBypass,
		InspectionMetadataReadbackObserved:  status.InspectionMetadataReadbackObserved,
		HeaderValueMaterialInDiagnostic:     false,
		OperatorConfigValueMaterialInDiag:   false,
		RealTLSInterceptionRuntimeExecuted:  false,
		MacCATrustMutationStarted:           false,
		P4PackagingMDMSigningInstallStarted: false,
		ShippingProductClaimed:              false,
		ProductionScaleClaimed:              false,
		MVPPilotSuccessClaimed:              false,
		WindowsWorkStarted:                  false,
		SecretLeakGate:                      "ok",
		NoSecretAttestation:                 true,
	}
}

func mergeSWGHTTPEgressReadinessPreconditionMetadata(metadata map[string]any, precondition edgeSWGHTTPEgressReadinessPrecondition) {
	if metadata == nil || !precondition.Checked {
		return
	}
	metadata["tls_readiness_precondition_checked"] = true
	metadata["tls_readiness_precondition_status"] = precondition.Status
	metadata["readiness_dependency"] = precondition.ReadinessDependency
	metadata["egress_forwarded"] = precondition.EgressForwarded
	metadata["lab_mode"] = precondition.LabMode
	metadata["tls_readiness_status_path"] = precondition.TLSReadinessStatusPath
	metadata["tls_readiness_status_version"] = precondition.TLSReadinessStatusVersion
	metadata["default_tls_decryption_required"] = precondition.DefaultTLSDecryptionRequired
	metadata["default_tls_decryption_observed"] = precondition.DefaultTLSDecryptionObserved
	metadata["default_tls_decryption_status"] = precondition.DefaultTLSDecryptionStatus
	metadata["mac_ca_trust_required"] = precondition.MacCATrustRequired
	metadata["mac_ca_trust_observed"] = precondition.MacCATrustObserved
	metadata["mac_ca_trust_status"] = precondition.MacCATrustStatus
	metadata["tenant_header_rewrite_dependency_count"] = precondition.TenantHeaderDependencyCount
	metadata["header_names_visible"] = append([]string{}, precondition.HeaderNamesVisible...)
	metadata["operator_config_refs_visible"] = append([]string{}, precondition.OperatorConfigRefsVisible...)
	metadata["per_destination_tls_bypass_required"] = precondition.PerDestinationTLSBypassNeeded
	metadata["tls_bypass_rule_count"] = precondition.TLSBypassRuleCount
	metadata["current_request_tls_bypass_applied"] = precondition.CurrentRequestTLSBypass
	metadata["current_request_tls_bypass_rule_id"] = precondition.CurrentRequestTLSBypassRuleID
	metadata["tls_readiness_dependency_suppressed_by_tls_bypass"] = precondition.SuppressedByTLSBypass
	metadata["header_value_material_in_diagnostic"] = false
	metadata["operator_config_value_material_in_diagnostic"] = false
}

func saasApplicationIDFromDecision(dec model.AccessDecision) string {
	if dec.SaaSContext == nil {
		return ""
	}
	return dec.SaaSContext.SaaSApplicationID
}

func edgeSWGTLSReadinessHeaderNames(status swg.EdgeSWGTLSReadinessStatus) []string {
	values := []string{}
	for _, dep := range status.TenantHeaderRewriteDependencies {
		values = swg.AppendUniqueNonEmpty(values, dep.HeaderName)
	}
	return values
}

func edgeSWGTLSReadinessOperatorConfigRefs(status swg.EdgeSWGTLSReadinessStatus) []string {
	values := []string{}
	for _, dep := range status.TenantHeaderRewriteDependencies {
		values = swg.AppendUniqueNonEmpty(values, dep.OperatorConfigRef)
	}
	return values
}

func edgeSWGHTTPEgressRewriteOutcome(result swghttprewrite.RewriteResult, saasApplicationID string) string {
	if result.SaaSApplicationID != saasApplicationID {
		return "not_applicable"
	}
	if result.HeaderInjectionSuppressedByBypass {
		return "suppressed_by_tls_bypass"
	}
	if result.HeaderApplied && result.HeaderValueResolved && strings.TrimSpace(result.HeaderValueRef) != "" {
		return "rewritten_by_operator_config_ref"
	}
	if result.InjectActionSeen {
		return "rewrite_not_applied"
	}
	return "not_applicable"
}

func edgeSWGHTTPEgressTLSBypassSuppressionOutcome(result swghttprewrite.RewriteResult) string {
	if result.HeaderInjectionSuppressedByBypass {
		return "header_injection_suppressed"
	}
	if result.TLSBypassApplied {
		return "tls_bypass_without_tenant_header"
	}
	return "not_applied"
}

func swgHTTPEgressTargetURLFromRequest(r *http.Request) (*url.URL, error) {
	raw := strings.TrimSpace(r.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader))
	if raw == "" && r.URL != nil {
		raw = strings.TrimSpace(r.URL.Query().Get("target_url"))
	}
	if raw == "" && r.URL != nil && r.URL.IsAbs() {
		raw = r.URL.String()
	}
	if raw == "" {
		return nil, fmt.Errorf("swg target URL is required")
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse swg target URL: %w", err)
	}
	if target.Scheme != "https" && target.Scheme != "http" {
		return nil, fmt.Errorf("swg target URL scheme must be http or https")
	}
	if strings.TrimSpace(target.Hostname()) == "" {
		return nil, fmt.Errorf("swg target URL host is required")
	}
	return target, nil
}

func decisionRequestForSWGHTTPEgress(r *http.Request, target *url.URL, bundle model.PolicyBundle) (model.DecisionRequest, error) {
	host := normalizedSWGEgressHost(target.Hostname())
	if host == "" {
		return model.DecisionRequest{}, fmt.Errorf("swg target host is required")
	}
	port, err := swgEgressTargetPort(target)
	if err != nil {
		return model.DecisionRequest{}, err
	}
	sourceIP, sourcePort := sourceEndpointFromRequest(r)
	return model.DecisionRequest{
		TenantID:      bundle.TenantID,
		ActorType:     "human",
		ApplicationID: edgeplane.EdgeSWGEgressApplicationID,
		// NOTE: UserID is intentionally NOT set from the request here. It is the CORPORATE IdP identity, filled by
		// enrichDecisionRequestWithSession from the active session. The account the user logged into the assistant
		// with (a JWT — possibly a personal address) is a SEPARATE fact recorded as ai_account metadata below, so
		// the dashboard shows both: who they are (corporate) AND what account they used (shadow-AI signal).
		SourceIP:        sourceIP,
		SourcePort:      sourcePort,
		Destination:     host,
		DestinationPort: port,
		Protocol:        "tcp",
		SteeringMode:    "network_extension",
		FQDN:            host,
		SNI:             host,
		ServiceFamily:   target.Scheme,
	}, nil
}

// swgEgressUserFromRequest extracts the end-user identity FROM the decrypted request — possible only because
// the edge decrypts (decrypt-all). It reads a JWT from Authorization: Bearer or a JWT-shaped cookie: a JWT is
// SIGNED, not encrypted, so its middle segment is base64url JSON claims and email / upn / preferred_username /
// sub read out directly. This covers OIDC-based SaaS (Google Workspace, M365, Okta-backed, …) with NO per-SaaS
// parser. Best-effort attribution for the usage log only (no signature verification — it is not an auth
// decision); empty when no readable token is present. Non-JWT/opaque-token SaaS fall back to other attribution.
// accessLogAllDecisions is the sovereign-SSE baseline: log EVERY egress decision (full forensic record, paired
// with tier-to-cold retention). -access-log-all=false opts into policy-driven selective logging — see
// shouldLogAccessDecision.
var accessLogAllDecisions bool

// shouldLogAccessDecision decides whether an egress decision earns an access-log row. Policy-driven: the access
// log is NOT a copy of all intercepted traffic (decrypt-all sees everything; logging each request buries the
// signal and does not scale — see docs/policy_driven_access_logging_design.md). Log a POLICY ACTION (anything
// but a plain allow — deny / authenticate / step-up / bypass-with-reason), or a policy-designated LOGGED CATEGORY
// (today: a classified AI service, the AI-usage dashboard's logging policy). A routine allow of unmarked traffic
// gets NO row. The `-access-log-all` override restores full logging.
func shouldLogAccessDecision(dec model.AccessDecision) bool {
	if accessLogAllDecisions {
		return true
	}
	if !strings.EqualFold(strings.TrimSpace(dec.Decision), "allow") {
		return true // policy action — always audited (a rule's log=false cannot suppress a deny/step-up)
	}
	// Per-rule explicit choice wins for a plain allow: the matched egress rule decides whether its traffic is
	// logged (metadata "log_traffic", set by the evaluator from the rule's Log flag).
	if v, ok := decLogTraffic(dec); ok {
		return v
	}
	// Default when the rule did not specify: log a classified AI service (the AI-usage dashboard's logging
	// policy); drop everything else.
	if appID := saasApplicationIDFromDecision(dec); appID != "" {
		if _, isAI := knownAIServiceDefaults[appID]; isAI {
			return true
		}
	}
	return false // routine allow of unmarked traffic — no row
}

// decLogTraffic reads the matched rule's explicit log choice, if the evaluator set one.
func decLogTraffic(dec model.AccessDecision) (value bool, set bool) {
	if dec.Metadata == nil {
		return false, false
	}
	if v, ok := dec.Metadata["log_traffic"].(bool); ok {
		return v, true
	}
	return false, false
}

func swgEgressUserFromRequest(r *http.Request) string {
	// A request can carry SEVERAL identity tokens (an authenticated bearer + session cookies). Prefer a STRONG
	// identity (email / display name) over an opaque subject ACROSS all of them — else an anonymous / opaque
	// token can win over the real one. Observed: Microsoft Copilot sends an authenticated bearer with
	// email=<user> AND a __Host-copilot-anon cookie with sub=<opaque>, splitting one user across two accounts.
	toks := []string{}
	auth := r.Header.Get("Authorization")
	for _, pfx := range []string{"Bearer ", "bearer "} {
		if strings.HasPrefix(auth, pfx) {
			toks = append(toks, strings.TrimPrefix(auth, pfx))
		}
	}
	for _, c := range r.Cookies() {
		// Skip anonymous-session tokens — an anonymous session is not a user identity (e.g. __Host-copilot-anon).
		if strings.Contains(strings.ToLower(c.Name), "anon") {
			continue
		}
		toks = append(toks, c.Value)
	}
	fallback := ""
	for _, t := range toks {
		id, strong := identityFromJWT(t)
		if id == "" {
			continue
		}
		if strong {
			return id
		}
		if fallback == "" {
			fallback = id
		}
	}
	return fallback
}

func userFromJWT(tok string) string {
	id, _ := identityFromJWT(tok)
	return id
}

// identityFromJWT decodes a JWT and returns the best identity plus whether it is STRONG. Strong = a human-
// meaningful email or display name (unique/verifiable enough to prefer across a request's other tokens); weak =
// an opaque subject (uuid / google-oauth2|… / anon session id), returned only as a last resort. id is "" when
// the token is not a decodable JWT or has no usable claim.
func identityFromJWT(tok string) (id string, strong bool) {
	claims := jwtClaims(tok)
	if claims == nil {
		return "", false
	}
	// Prefer a REAL email (unique + human-meaningful), then a display name, both STRONG; last a stable-but-opaque
	// subject, WEAK. (Extraction of email/name is shared with the structured identity path.)
	if e := emailFromClaims(claims); e != "" {
		return e, true
	}
	if n := nameFromClaims(claims); n != "" {
		return n, true
	}
	for _, k := range []string{"preferred_username", "upn", "unique_name", "sub"} {
		if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), false
		}
	}
	return "", false
}

// jwtClaims decodes a JWT's payload to a claims map, or nil if tok is not a decodable JWT.
func jwtClaims(tok string) map[string]any {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 { // header.payload.signature
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil
		}
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
}

// emailFromClaims returns a real email from standard, namespaced ("https://…/email"), or nested claims — else "".
// Auth0 / OpenAI / Okta commonly carry the email under a namespaced key or nested profile a top-level lookup misses.
func emailFromClaims(claims map[string]any) string {
	for _, k := range []string{"email", "preferred_username", "upn", "unique_name"} {
		if v, ok := claims[k].(string); ok && looksLikeEmail(v) {
			return strings.TrimSpace(v)
		}
	}
	return findEmailInClaims(claims, 0)
}

// nameFromClaims returns a human display name (name / nickname / given+family) — else "". Claude's session JWT
// carries a name but no email; some IdPs likewise.
func nameFromClaims(claims map[string]any) string {
	for _, k := range []string{"name", "nickname"} {
		if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if gn, ok := claims["given_name"].(string); ok && strings.TrimSpace(gn) != "" {
		fn, _ := claims["family_name"].(string)
		return strings.TrimSpace(strings.TrimSpace(gn) + " " + strings.TrimSpace(fn))
	}
	return ""
}

// swgEgressIdentityFromRequest extracts the end-user identity as SEPARATE fields — email AND display name — from
// the decrypted request. Both are returned when present; an AI service may expose only one (Claude gives a name
// but no email; ChatGPT gives an email), so either may be "". Scans the bearer + non-anon cookies and takes the
// first of each across all tokens (an authenticated bearer's email + a session cookie's name compose one user).
func swgEgressIdentityFromRequest(r *http.Request) (email, name string) {
	toks := []string{}
	auth := r.Header.Get("Authorization")
	for _, pfx := range []string{"Bearer ", "bearer "} {
		if strings.HasPrefix(auth, pfx) {
			toks = append(toks, strings.TrimPrefix(auth, pfx))
		}
	}
	for _, c := range r.Cookies() {
		if strings.Contains(strings.ToLower(c.Name), "anon") { // an anonymous session is not a user
			continue
		}
		toks = append(toks, c.Value)
	}
	for _, t := range toks {
		claims := jwtClaims(t)
		if claims == nil {
			continue
		}
		if email == "" {
			email = emailFromClaims(claims)
		}
		if name == "" {
			name = nameFromClaims(claims)
		}
		if email != "" && name != "" {
			break
		}
	}
	return email, name
}

// swgEgressIdentityForService extracts email + name using the SERVICE's fixed rule — per-service and precise: it
// reads exactly the source+claim that service exposes, so an unrelated token (a third-party embed, an analytics
// cookie) cannot mis-attribute. An uncatalogued service uses the generic best-effort rule. Either result may be ""
// (the service exposes only one field, or neither — e.g. Claude has a name but no email; Gemini has neither).
func swgEgressIdentityForService(r *http.Request, catalog []model.SaaSCatalogEntry, appID string) (email, name string) {
	rule := aiServiceIdentityRuleFor(catalog, appID)
	return readIdentityField(r, rule.EmailFrom, true), readIdentityField(r, rule.NameFrom, false)
}

// readIdentityField runs a rule field's ordered sources and returns the first value found. wantEmail requires the
// value to look like an email, so a mis-configured claim cannot drop a name into the email column.
func readIdentityField(r *http.Request, sources []model.SaaSIdentitySource, wantEmail bool) string {
	for _, s := range sources {
		for _, tok := range identityTokensForSource(r, s) {
			claims := jwtClaims(tok)
			if claims == nil {
				continue
			}
			v := claimValue(claims, s.Claim)
			if v == "" || (wantEmail && !looksLikeEmail(v)) {
				continue
			}
			return v
		}
	}
	return ""
}

// identityTokensForSource returns the candidate JWTs for a rule source: the bearer token, or the non-skipped cookies.
func identityTokensForSource(r *http.Request, s model.SaaSIdentitySource) []string {
	var toks []string
	switch s.Source {
	case "bearer":
		auth := r.Header.Get("Authorization")
		for _, pfx := range []string{"Bearer ", "bearer "} {
			if strings.HasPrefix(auth, pfx) {
				toks = append(toks, strings.TrimPrefix(auth, pfx))
			}
		}
	case "cookie":
		for _, c := range r.Cookies() {
			if cookieNameMatchesAny(c.Name, s.SkipCookiePatterns) {
				continue
			}
			toks = append(toks, c.Value)
		}
	}
	return toks
}

func cookieNameMatchesAny(name string, patterns []string) bool {
	ln := strings.ToLower(name)
	for _, p := range patterns {
		if p != "" && strings.Contains(ln, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// claimValue reads a single claim by EXACT key (no deep scan — that precision is the point); "given_family"
// composes given_name + family_name.
func claimValue(claims map[string]any, key string) string {
	if key == "given_family" {
		gn, _ := claims["given_name"].(string)
		if strings.TrimSpace(gn) == "" {
			return ""
		}
		fn, _ := claims["family_name"].(string)
		return strings.TrimSpace(strings.TrimSpace(gn) + " " + strings.TrimSpace(fn))
	}
	if v, ok := claims[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// enrichDecisionRequestWithTransportDevice records the flow's two endpoint-reported facts, keeping them distinct:
//   - the verified (T) transport DEVICE identity -> req.DeviceID (the MACHINE dimension). NOT used to derive the
//     user: a device is not 1:1 with a user (shared workstations; one user, many devices).
//   - the PER-FLOW logged-in OS user the agent reported (steer OPEN "u=") -> req.UserID (the authoritative WHO).
//     Per-flow, so it is correct even when several users share one device. Only set when a session identity
//     (enrichDecisionRequestWithSession) has not already provided the user.
func enrichDecisionRequestWithTransportDevice(req model.DecisionRequest, ctx context.Context, deviceStore deviceRuntimeStore) model.DecisionRequest {
	if deviceID := edgeplane.TransportDeviceFromContext(ctx); deviceID != "" && req.DeviceID == "" {
		req.DeviceID = deviceID
	}
	if req.UserID == "" {
		if osUser := edgeplane.OSUserFromContext(ctx); osUser != "" {
			req.UserID = osUser
		}
	}
	return req
}

// splitSteerAuthorityMeta splits a steer OPEN authority — "host:port" optionally followed by a \x00-delimited
// per-flow metadata section ("u=<os-user> a=<app>") the endpoint agent attaches — into the bare host:port and
// the parsed logged-in OS user + originating app. BOTH the single-flow CONNECT /steer handler and the
// multiplexed /steer-mux OPEN handler use it, so the two transports cannot diverge: /steer previously omitted
// this parse and silently dropped the OS user (a "host:port\x00u=..." authority also failed net.SplitHostPort).
// Non-interactive / system / daemon accounts are blanked so they are neither shown as the user nor attributed
// as the actor.
func splitSteerAuthorityMeta(authority string) (hostPort, osUser, sourceApp string) {
	hostPort = authority
	if i := strings.IndexByte(authority, 0); i >= 0 {
		meta := authority[i+1:]
		osUser = parseSteerOpenOSUser(meta)
		sourceApp = parseSteerOpenApp(meta)
		hostPort = authority[:i]
	}
	if isNonInteractiveAccount(osUser) {
		osUser = ""
	}
	return hostPort, osUser, sourceApp
}

// parseSteerOpenOSUser / parseSteerOpenApp extract the OS user ("u=") and originating app ("a=") from the steer
// OPEN frame's per-flow metadata section (space-separated key=value). Sanitized + length-bounded so a hostile
// agent cannot inject log / identity noise.
func parseSteerOpenOSUser(meta string) string { return steerOpenMetaValue(meta, "u") }
func parseSteerOpenApp(meta string) string    { return steerOpenMetaValue(meta, "a") }

// isNonInteractiveAccount reports whether an OS account name is a system / service / daemon account rather than a
// logged-in interactive user — those must not be shown as the "logged-in user" or attributed as the acting user.
// Covers macOS daemon accounts (leading "_", root/daemon/nobody) and Windows service principals (NT AUTHORITY\…,
// NT SERVICE\…, *\SYSTEM / *\LOCAL SERVICE / *\NETWORK SERVICE, and the bare "NT" left when "NT AUTHORITY\SYSTEM"
// is split on its embedded space by the OPEN-frame parser).
func isNonInteractiveAccount(user string) bool {
	u := strings.TrimSpace(user)
	if u == "" {
		return false
	}
	if strings.HasPrefix(u, "_") { // macOS daemon users
		return true
	}
	lu := strings.ToLower(u)
	switch lu {
	case "root", "daemon", "nobody", "nt", "system":
		return true
	}
	if strings.HasPrefix(lu, "nt authority\\") || strings.HasPrefix(lu, "nt service\\") {
		return true
	}
	if strings.HasSuffix(lu, "\\system") || strings.HasSuffix(lu, "\\local service") || strings.HasSuffix(lu, "\\network service") {
		return true
	}
	return false
}

func steerOpenMetaValue(meta, key string) string {
	for _, tok := range strings.Fields(meta) {
		if strings.HasPrefix(tok, key+"=") {
			return sanitizeOSUser(strings.TrimPrefix(tok, key+"="))
		}
	}
	return ""
}

func sanitizeOSUser(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 128 {
		s = s[:128]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func looksLikeEmail(s string) bool {
	s = strings.TrimSpace(s)
	at := strings.LastIndex(s, "@")
	return at > 0 && at < len(s)-1 && strings.Contains(s[at+1:], ".")
}

// findEmailInClaims searches JWT claims — including URL-namespaced keys and nested objects/arrays — for the first
// value that lives under an "email"-ish key AND looks like an email address. Depth-limited (tokens are shallow).
func findEmailInClaims(o any, depth int) string {
	if depth > 3 {
		return ""
	}
	switch v := o.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok && strings.Contains(strings.ToLower(k), "email") && looksLikeEmail(s) {
				return strings.TrimSpace(s)
			}
		}
		for _, val := range v {
			if e := findEmailInClaims(val, depth+1); e != "" {
				return e
			}
		}
	case []any:
		for _, val := range v {
			if e := findEmailInClaims(val, depth+1); e != "" {
				return e
			}
		}
	}
	return ""
}

func newSWGHTTPEgressUpstreamRequest(r *http.Request, target *url.URL) (*http.Request, error) {
	if r.Method == http.MethodConnect {
		return nil, fmt.Errorf("swg http egress CONNECT is not handled by this path")
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		return nil, fmt.Errorf("build swg upstream request: %w", err)
	}
	req.ContentLength = r.ContentLength
	req.TransferEncoding = append([]string(nil), r.TransferEncoding...)
	req.Header = swgEgressForwardHeadersForRequest(r)
	return req, nil
}

func swgEgressTargetPort(target *url.URL) (int, error) {
	if raw := strings.TrimSpace(target.Port()); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port <= 0 || port > 65535 {
			return 0, fmt.Errorf("swg target port is invalid")
		}
		return port, nil
	}
	if target.Scheme == "https" {
		return 443, nil
	}
	return 80, nil
}

func normalizedSWGEgressHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return strings.TrimSpace(host)
}

func sourceEndpointFromRequest(r *http.Request) (string, int) {
	host, portValue, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr), 0
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		port = 0
	}
	return host, port
}

func swgEgressForwardHeaders(src http.Header) http.Header {
	dst := src.Clone()
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		edgeplane.EdgeSWGHTTPEgressTargetURLHeader,
		edgeplane.EdgeSWGHTTPEgressNERuntimeHeader,
		connectorSecretHeader,
		connectorIDHeader,
		workloadAttestationStateHeader,
		workloadAttestationTimestampHeader,
		workloadAttestationNonceHeader,
		workloadAttestationSignatureHeader,
	} {
		dst.Del(name)
	}
	return dst
}

func swgEgressForwardHeadersForRequest(r *http.Request) http.Header {
	if r == nil {
		return http.Header{}
	}
	dst := swgEgressForwardHeaders(r.Header)
	if swgHTTPEgressIsWebSocketUpgrade(r) {
		dst.Set("Connection", "Upgrade")
		dst.Set("Upgrade", "websocket")
	}
	return dst
}

func swgHTTPEgressIsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return headerTokenContains(r.Header, "Connection", "upgrade") &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

func headerTokenContains(header http.Header, name string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(token)) == want {
				return true
			}
		}
	}
	return false
}

func swgHTTPEgressNetworkExtensionRuntimeUsed(r *http.Request) bool {
	if r == nil {
		return false
	}
	if edgeplane.SWGNERuntimeUsedFromContext(r.Context()) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get(edgeplane.EdgeSWGHTTPEgressNERuntimeHeader))) {
	case "true", "1", "runtime_copy_lab_tls":
		return true
	default:
		return false
	}
}

func copySWGEgressResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func swgHTTPEgressSkipsUpstreamBody(method string, status int) bool {
	if strings.EqualFold(strings.TrimSpace(method), http.MethodHead) {
		return true
	}
	if status >= 300 && status < 400 {
		return true
	}
	switch status {
	case http.StatusNoContent, http.StatusNotModified:
		return true
	default:
		return false
	}
}

func suppressSWGEgressResponseBodyHeaders(header http.Header) {
	header.Del("Content-Length")
	header.Del("Transfer-Encoding")
	header.Del("Content-Encoding")
	header.Set("Content-Length", "0")
}

// A managed reference must resolve from the SAME immutable snapshot as its rule.
// Never fall back to a different tenant or a newer mutable configuration.
type tenantRestrictionSnapshotResolver struct {
	snapshot, legacy swghttprewrite.HeaderValueResolver
}

func (r tenantRestrictionSnapshotResolver) ResolveHeaderValue(ref string) (string, bool) {
	if strings.HasPrefix(ref, "operator_config_ref:tenant_restriction/") {
		if r.snapshot == nil {
			return "", false
		}
		return r.snapshot.ResolveHeaderValue(ref)
	}
	if r.legacy == nil {
		return "", false
	}
	return r.legacy.ResolveHeaderValue(ref)
}

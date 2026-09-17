package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Device admission / enrollment admin routes — the W-7 transport-admission kill-switch
// (explicit admin action only), revocation list/report, the revocation-mesh ingress,
// device concerns, enrolled-device lifecycle, device groups, and the enrolment-token +
// licensing sub-registrations that belong to this surface — moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Takes serverConfig whole: this
// surface reads ~20 enrollment/licensing/mesh config fields.
func registerDeviceAdmissionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, deviceStore deviceRuntimeStore, registry connectorRegistryStore, tcaReg *tenantca.TenantCARegistry, tenantModelStore adminTenantModelRuntimeStore, configSourceURL string, configBundleEpoch string) {
	mux.HandleFunc("GET /admin/transport-admission", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		// Scoped like every other per-device read (same sweep). A kill-switch list names devices and says they
		// were cut off, which is a statement about another customer's incident when it is not the caller's.
		//
		// NOT the same as GET /admin/revocations next door, which is deliberately left whole: that one is the
		// FEED a pulling Edge applies, its caller is the deployment rather than a customer, and filtering it by
		// a human's tenant would silently stop propagating other tenants' kill-switches — a fix that turns a
		// disclosure into an enforcement failure. The two look alike and are not the same act.
		if config.AdmissionRevocations == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("transport admission overlay not configured"))
			return
		}
		callerTenant := adminTenantIDFromRequest(r)
		revoked := []string{}
		unattributable := 0
		if config.AdmissionRevocations != nil {
			for _, identity := range config.AdmissionRevocations.List() {
				belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, identity, callerTenant)
				if !placeable {
					// A revoked identity the ledger cannot place — including one revoked and then deleted, which
					// is an ordinary end state. Counted so the list never quietly reads as "nothing is blocked".
					unattributable++
					continue
				}
				if belongs {
					revoked = append(revoked, identity)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":          "admin_transport_admission.v1",
			"tenant_id":               callerTenant,
			"revoked_identities":      revoked,
			"withheld_unattributable": unattributable,
			"no_secret_attestation":   true,
		})
	}))
	// Phase 3 shared revocation overlay: the control plane serves its node-local revocation set (admin
	// kill-switches + its own auto-revocations) as a fast-pulled feed; each Edge applies it so a revocation
	// bites fleet-wide. Generation + epoch mirror the config bundle (re-baseline on a CP restart). Read-only.
	mux.HandleFunc("GET /admin/revocations", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		// ★★ THIS FEED IS FOR A NODE, NOT FOR A PERSON (2026-08-17, measured as a customer administrator: 200,
		// with the whole deployment's revoked identities in it — every organization's blocked devices, named).
		//
		// The note below says the caller here is the deployment rather than a customer, and that filtering it
		// by a human's tenant would silently stop propagating other tenants' kill-switches — a fix that turns a
		// disclosure into an enforcement failure. Both halves are right, and they are not in tension: the
		// PULLER is an Edge presenting a machine credential, and no screen in this Console calls this route at
		// all. So the sentence in that note becomes the condition, rather than a reason to leave it open.
		//
		// ★ AND THE DISCRIMINATOR IS NOT "SESSION vs TOKEN". The first version of this refused sessions only,
		// which the test caught immediately: a customer can hold an API token too, and then read the whole feed
		// again. What actually separates the puller from a customer is WHOSE credential it is — an Edge pulls
		// with a credential belonging to the node's own organization, and a customer never does.
		//
		// An operator answering for the deployment passes as well. A caller with no resolvable tenant is an
		// unscoped deployment, which is the same answer every other boundary here gives.
		if identity, ok := adminIdentityFromRequest(r); ok {
			caller := strings.TrimSpace(identity.TenantID)
			node := strings.TrimSpace(evaluator.PolicyBundle.TenantID)
			_, wholeDeployment := adminAnswerScope(r)
			if caller != "" && node != "" && !strings.EqualFold(caller, node) && !wholeDeployment {
				writeError(w, http.StatusForbidden, fmt.Errorf(
					"the revocation feed is what a node pulls to enforce this deployment's blocks; the devices "+
						"blocked in your organization are at GET /admin/transport-admission"))
				return
			}
		}
		// Only the control plane may say "this is the complete set". That claim is what lets a pulling Edge
		// treat an EMPTY set as a real release rather than as a blank answer, so a node that is merely echoing
		// what it pulled must not make it.
		feed := revocationFeed{Epoch: configBundleEpoch, Revoked: map[string]string{}, HighRisk: map[string]string{}, Authoritative: edgeIsControlPlane}
		if config.AdmissionRevocations != nil {
			feed.Generation += config.AdmissionRevocations.ConfigGeneration()
			// FeedSnapshot = origin revocations UNIONED with cross-region mesh-received ones, so a device
			// revoked in a PEER region is denied on this region's edges too.
			feed.Revoked = config.AdmissionRevocations.FeedSnapshot()
		}
		if config.HighRiskOverlay != nil {
			feed.Generation += config.HighRiskOverlay.ConfigGeneration() // aggregate: a high-risk change advances the feed too
			devices, users, err := config.HighRiskOverlay.CheckedSnapshot()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("risk state is not available"))
				return
			}
			feed.HighRisk = devices
			feed.UserRiskVersion = 1
			feed.UserRisk = users
		}
		writeJSON(w, http.StatusOK, feed)
	}))
	// Cross-region revocation mesh receive side ( step 4): a PEER region's CP pushes an origin revocation
	// here; we fold it into the cross-region layer so it denies on THIS region's edges (via the feed) but is
	// never re-pushed (no-loop — only an origin region pushes). Authenticated by the shared mesh secret; fail-SAFE
	// (it can only DENY — restore stays admin-only at the origin region).
	mux.HandleFunc("POST /revocation-mesh/admission", func(w http.ResponseWriter, r *http.Request) {
		// Self-gate: only serve when this CP is configured to receive cross-region revocations (an allowed-peer
		// set, or a revocation-mesh secret in lab). An unconfigured edge never exposes this DoS-sensitive surface
		// (an accepted push can DENY any identity).
		if len(config.MeshIngressAllowedPeers) == 0 && config.RevocationMeshSecret == "" {
			writeError(w, http.StatusNotFound, fmt.Errorf("revocation mesh ingress is not enabled on this edge"))
			return
		}
		// Authenticate the peer CP. With an allowlist configured this requires a VERIFIED mTLS identity that is an
		// AUTHORIZED sibling (secret fallback disabled) — an empty/any-cert push could revoke ANY identity.
		peerIdentity, authenticated := meshIngressAuth(r, config.MeshIngressAllowedPeers, config.RevocationMeshSecret, "x-revocation-mesh-secret")
		if !authenticated {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("revocation mesh push requires an authorized peer mTLS identity (allowlisted) or, in lab, a valid x-revocation-mesh-secret"))
			return
		}
		if config.AdmissionRevocations == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("revocation overlay is not enabled"))
			return
		}
		body, err := readLimitedBody(w, r, maxEdgeRuntimeJSONBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read revocation mesh item: %w", err))
			return
		}
		// Anti-replay: when a revocation-mesh secret is configured, the push must carry a fresh, single-use,
		// HMAC-signed stamp. Rejects a captured push being replayed to re-apply a stale revocation.
		if err := verifyMeshAntiReplay(r.Header, config.RevocationMeshSecret, body, revocationMeshReplayGuard, time.Now().UTC()); err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("revocation mesh anti-replay: %w", err))
			return
		}
		var item revocationMeshItem
		if err := json.Unmarshal(body, &item); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode revocation mesh item: %w", err))
			return
		}
		if strings.TrimSpace(item.Identity) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("revocation mesh item requires an identity"))
			return
		}
		changed, saveErr := config.AdmissionRevocations.RevokeFromMeshChecked(item.Identity, item.Reason)
		identity := strings.ToLower(strings.TrimSpace(item.Identity))
		// A failed save must not drain the sender's retry queue. A fresh delivery
		// resaves even an unchanged item, without re-firing callbacks or mesh pushes.
		// OriginRegion is a claim in the payload, not the authenticated peer identity.
		if saveErr != nil {
			log.Printf("revocation mesh: persistence unconfirmed; identity=%q peer=%q claimed_origin=%q changed=%t applied_locally=true", identity, peerIdentity, item.OriginRegion, changed)
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("cross-region revocation is applied locally, but saving was not confirmed; retry with a fresh authenticated request"))
			return
		}
		log.Printf("revocation mesh: accepted; identity=%q peer=%q claimed_origin=%q changed=%t", identity, peerIdentity, item.OriginRegion, changed)
		writeJSON(w, http.StatusOK, map[string]any{"applied": changed})
	})
	// Node→CP reporting. A node that observes something alarming about a device says so HERE, and that is all
	// it does: the report is recorded and surfaced, and it does NOT revoke.
	//
	// It used to. An Edge shipped its own automatic revocation (W-2 agent-dark) and the control plane merged it
	// into the authoritative set and redistributed it fleet-wide, so a device one node decided was dark was
	// denied everywhere, with no administrator involved anywhere in the chain. The automatic producer was
	// removed after it deadlocked — a device revoked for being silent cannot come back to stop being silent —
	// but this ingest stayed open, still named and documented for automatic use, so the mechanism to kill a
	// device without a human remained a POST away.
	//
	// Cutting a device off is a decision about someone's ability to work, and it is not one an inference gets to
	// make. Automatic signals may refuse NEW admission on the node that sees them; only an explicit
	// administrator block revokes, and only that block tears down established sessions. This route now stops at
	// the line: it tells an operator what a node saw, and the operator decides.
	//
	// The reports are in-memory on purpose. They are a signal rather than enforcement, so losing them on restart
	// costs a notification and nothing else — the opposite of a revocation, where forgetting is the failure.
	mux.HandleFunc("POST /admin/revocations/report", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Identity string `json:"identity"`
			Reason   string `json:"reason"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode revocation report: %w", err))
			return
		}
		if strings.TrimSpace(req.Identity) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("identity is required"))
			return
		}
		// ★★★ AND THE DEVICE HAS TO BE THEIRS — THE REPORT, NOT ONLY THE ACT (2026-08-22, measured with
		// tenant_northwind's own administrator, a principal holding no cross-tenant permission).
		//
		// The 2026-08-17 sweep scoped the two neighbours: GET /admin/device-concerns withholds a report about
		// somebody else's device, and POST /admin/transport-admission/revoke refuses to cut one off. It left
		// the WRITE that fills the list. Measured: Northwind's administrator posted a concern naming the lab
		// organization's mac-dev-1, on both nodes, and got 202 — and the LAB's own administrator then read it
		// on both nodes as a finding about their own laptop, with the reason string exactly as Northwind wrote
		// it.
		//
		// That list is what an administrator reviews before throwing the one switch that tears down established
		// sessions. Being able to plant "this device is a concern", with free text, on another customer's
		// review screen is an injection into their decision, not a disclosure of ours.
		//
		// The same rule and the same 404 as the revoke path beside it: whether an identity exists on this node
		// is itself withheld, and an identity the ledger cannot place is refused rather than recorded — a
		// concern nobody can attribute is one nobody can act on.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			callerTenant := adminTenantIDFromRequest(r)
			if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, req.Identity, callerTenant); !placeable || !belongs {
				writeError(w, http.StatusNotFound, fmt.Errorf("no enrolled device %q in your organization", req.Identity))
				return
			}
		}
		reason := valueOrDefault(strings.TrimSpace(req.Reason), "node_reported_concern")
		reportedDeviceConcerns.record(strings.TrimSpace(req.Identity), reason, time.Now().UTC())
		log.Printf("device_concern_reported identity=%q reason=%q — RECORDED, NOT ENFORCED. Blocking a device is an explicit administrator act (POST /admin/transport-admission/revoke).", strings.TrimSpace(req.Identity), reason)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"schema_version": "admission_revocation_report.v2",
			"recorded":       true,
			"enforced":       false,
			"identity":       strings.TrimSpace(req.Identity),
			"reason":         reason,
			"note":           "Recorded for an administrator to review. Nothing was blocked: only an explicit administrator block revokes a device.",
		})
	}))
	// The reports, on their own route. Deliberately NOT folded into GET /admin/revocations: that endpoint is the
	// feed pulling Edges apply, and anything appearing in it is enforcement by definition. Mixing observations
	// into it would make the exact confusion this change exists to remove — and would risk a node treating a
	// machine's guess as an administrator's decision.
	mux.HandleFunc("GET /admin/device-concerns", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		// Scoped to the caller's tenant, found in the same sweep as /admin/device-runtime and
		// /admin/device-certificates and unscoped for the same reason: this list is keyed by device identity
		// and a report carries no tenant, so with one tenant on the node a filtered read and an unfiltered one
		// are the same answer. A concern names a device AND says what is wrong with it, which is a sharper
		// disclosure than presence — "this device is failing attestation" is a sentence about another
		// customer's security posture.
		callerTenant := adminTenantIDFromRequest(r)
		concerns := []reportedDeviceConcern{}
		unattributable := 0
		for _, c := range reportedDeviceConcerns.snapshot() {
			belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, c.Identity, callerTenant)
			if !placeable {
				unattributable++
				continue
			}
			if belongs {
				concerns = append(concerns, c)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_device_concerns.v1",
			"concerns":       concerns,
			"count":          len(concerns),
			// Reports about devices the enrolled ledger cannot place. Counted rather than dropped: a concern
			// list that quietly shrinks is read as a fleet with nothing wrong with it.
			"withheld_unattributable": unattributable,
			"note":                    "Observations reported by nodes. None of these is enforced. Blocking a device is an explicit administrator act.",
		})
	}))
	// Dismissing a report is how an administrator says "seen". It is a separate act from blocking, on purpose:
	// deciding an observation was not worth acting on is a real decision and should not require pretending to
	// act on it. Clearing a report never touches enforcement in either direction.
	mux.HandleFunc("DELETE /admin/device-concerns/{identity}", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		identity := strings.TrimSpace(r.PathValue("identity"))
		if identity == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("identity is required"))
			return
		}
		// ★ AND THE SAME BOUNDARY ON THE WAY IN. The read beside this one leaked another tenant's devices; this
		// one let an admin DISMISS another tenant's report — silencing a customer's own notification about their
		// own device, from an account with no relationship to it. A named identity is enough to do it, and the
		// read next door supplied the names. 404 rather than 403: whether an identity exists on this node is
		// itself the answer being withheld.
		callerTenant := adminTenantIDFromRequest(r)
		if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, identity, callerTenant); !placeable || !belongs {
			writeError(w, http.StatusNotFound, fmt.Errorf("no reported concern for %q", identity))
			return
		}
		dismissed := reportedDeviceConcerns.clear(identity)
		logInfof("device_concern_dismissed identity=%q found=%v (enforcement unchanged)", identity, dismissed)
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_device_concerns.v1", "dismissed": dismissed, "identity": identity,
		})
	}))
	mux.HandleFunc("POST /admin/transport-admission/revoke", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		// Phase 3: the revocation overlay is CP-authoritative + fleet-distributed, so author kill-switches on
		// the control plane (a puller's local revoke would not propagate). The node-local W-2 auto-revocation
		// path is separate and not gated.
		if configWriteRejectedWhenSourced(w, configSourceURL, "admission revocations (kill-switch)") {
			return
		}
		if config.AdmissionRevocations == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("transport admission overlay not configured"))
			return
		}
		var req struct {
			Identity string `json:"identity"`
			Reason   string `json:"reason"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode transport admission revoke: %w", err))
			return
		}
		if strings.TrimSpace(req.Identity) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("identity is required"))
			return
		}
		// ★★★ AND THE DEVICE HAS TO BE THEIRS (2026-08-17, measured with tenant_northwind's own administrator,
		// a principal holding no cross-tenant permission). This is the ONE path allowed to tear down ESTABLISHED
		// (T) sessions, and it took an identity string with no tenant check at all: naming another
		// organization's device cut it off, immediately, from an account with no relationship to it. The LIST
		// beside it was scoped in the same sweep that missed this; the read was the disclosure and this is the
		// act.
		//
		// 404 rather than 403, like the neighbouring refusal: whether an identity exists on this node is itself
		// the answer being withheld. An identity the ledger cannot place is refused too — a kill-switch you
		// cannot show is yours is one you do not get to throw.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			callerTenant := adminTenantIDFromRequest(r)
			if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, req.Identity, callerTenant); !placeable || !belongs {
				writeError(w, http.StatusNotFound, fmt.Errorf("no enrolled device %q in your organization", req.Identity))
				return
			}
		}
		reason := valueOrDefault(strings.TrimSpace(req.Reason), "admin_kill_switch")
		saveErr := config.AdmissionRevocations.RevokeChecked(req.Identity, reason)
		// The ONE place allowed to tear down established (T) sessions: an explicit administrator block. Every
		// other revocation path (CP feed, mesh, node-reported automatic) only denies NEW handshakes. See the
		// invariant on transportConns where the registry is created.
		if config.TransportConnRegistry != nil {
			config.TransportConnRegistry.logCloseIdentity(req.Identity, reason)
		}
		logInfof("transport_admission_revoked_by_admin identity=%q reason=%q", req.Identity, reason)
		tenantID := adminTenantIDFromRequest(r)
		if config.EnrolledLedger != nil {
			if entry, ok := config.EnrolledLedger.EntryFor(req.Identity); ok && strings.TrimSpace(entry.TenantID) != "" {
				tenantID = entry.TenantID
			}
		}
		record := transportAdmissionAuditLog(r, tenantID, "revoke", req.Identity, reason, evaluator, time.Now().UTC())
		if saveErr != nil {
			record.Result = stringPtr("partial")
			record.Metadata["applied_locally"] = true
			record.Metadata["persistence_confirmed"] = false
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, record, time.Now().UTC())
		if saveErr != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("device blocked locally, but saving was not confirmed; repair storage and retry the block before restarting"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_transport_admission.v1", "revoked": true, "tenant_id": adminTenantIDFromRequest(r), "identity": strings.TrimSpace(req.Identity), "reason": reason})
	}))
	mux.HandleFunc("POST /admin/transport-admission/restore", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if configWriteRejectedWhenSourced(w, configSourceURL, "admission revocations (restore)") {
			return
		}
		if config.AdmissionRevocations == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("transport admission overlay not configured"))
			return
		}
		var req struct {
			Identity string `json:"identity"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode transport admission restore: %w", err))
			return
		}
		if strings.TrimSpace(req.Identity) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("identity is required"))
			return
		}
		// The same boundary, for the same reason. Restoring is the gentler direction, but "somebody else may
		// undo your block" is still an act on another organization's enforcement — and a block that anyone can
		// lift is not a block.
		if _, wholeDeployment := adminAnswerScope(r); !wholeDeployment {
			callerTenant := adminTenantIDFromRequest(r)
			if belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, req.Identity, callerTenant); !placeable || !belongs {
				writeError(w, http.StatusNotFound, fmt.Errorf("no enrolled device %q in your organization", req.Identity))
				return
			}
		}
		saveErr := config.AdmissionRevocations.RestoreChecked(req.Identity)
		// Restore removes only the locally authored block. A peer or pulled block can
		// still deny admission. This is a current local observation, not a fleet ACK.
		_, transportRevoked := config.AdmissionRevocations.IsRevoked(req.Identity)
		tenantID := adminTenantIDFromRequest(r)
		if config.EnrolledLedger != nil {
			if entry, ok := config.EnrolledLedger.EntryFor(req.Identity); ok && strings.TrimSpace(entry.TenantID) != "" {
				tenantID = entry.TenantID
			}
		}
		record := transportAdmissionAuditLog(r, tenantID, "restore", req.Identity, "", evaluator, time.Now().UTC())
		record.Metadata["transport_revoked"] = transportRevoked
		if saveErr == nil && transportRevoked {
			record.Result = stringPtr("partial")
		}
		if saveErr != nil {
			record.Result = stringPtr("error")
			record.Metadata["applied_locally"] = false
			record.Metadata["persistence_confirmed"] = false
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, record, time.Now().UTC())
		if saveErr != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("device restore was not applied locally because saving was not confirmed; reconcile storage and retry the intended state before restarting"))
			return
		}
		logInfof("transport_admission_restored_by_admin identity=%q", strings.TrimSpace(req.Identity))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_transport_admission.v1", "restored": true, "tenant_id": adminTenantIDFromRequest(r), "identity": strings.TrimSpace(req.Identity), "transport_revoked": transportRevoked})
	}))
	// management ledger: the Admin Console device list for the Enrolled Inventory. Enroll a device,
	// disable it (the manual revocation path), re-enable, or remove it — consulted live at the (T) handshake,
	// no restart. Replaces the static signed-file inventory with a managed ledger (cert-profile enforcement
	// is intentionally NOT included — out of scope).
	enrolledLedgerOr503 := func(w http.ResponseWriter) bool {
		if config.EnrolledLedger == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("enrolled inventory ledger not configured"))
			return false
		}
		return true
	}
	// Device enrollment issuance (M4c): register POST /enroll only when a device-identity CA was configured
	// (config.EnrollSigner != nil), so existing deployments are unaffected. Signs device CSRs → CP-authoritative
	// device cert + tenant/group, records the admission in the enrolled ledger.
	if config.EnrollSigner != nil {
		registerEnrollEndpointWithIdP(mux, config.EnrollSigner, config.EnrolledLedger,
			config.EnrolmentTokens, config.EnrolmentLicensing, config.EnrollToken,
			evaluator.PolicyBundle.TenantID, config.EnrollDefaultGroup, config.EnrollCertTTL, tenantModelStore,
			// The Site store, so a connector can prove itself with its Site's bootstrap secret and be issued
			// the certificate the Edge then requires it to present — see connector_enrolment_identity.go.
			config.EnrollIdPEligibility, config.EnrolmentCPReporter, config.SiteStore, log.Printf)
		// Renewal, authenticated by the certificate being renewed rather than by the bootstrap token. Without
		// this, the 60-day certificates /enroll issues would expire fleet-wide with nothing to re-issue them.
		registerEnrollRenewEndpoint(mux, config.EnrollSigner, config.EnrolledLedger,
			evaluator.PolicyBundle.TenantID, config.EnrollCertTTL, log.Printf)
	}
	registerAdminEnrolmentTokenEndpoints(mux, config.EnrolmentTokens, config.EnrolmentTokenPolicy, adminEndpoint, enrolledLedgerOr503,
		// The organization this node's /enroll actually issues for — see enrolsForTenant.
		// Resolve the approving administrator's name at issuance. The Edge already holds the account list this
		// answers from; nothing about the auth contract needs to change for a record to name a person.
		func(tenantID, principalID string) string {
			if config.LocalCredentials == nil || strings.TrimSpace(principalID) == "" {
				return ""
			}
			for _, account := range config.LocalCredentials.List(strings.TrimSpace(tenantID)) {
				if strings.EqualFold(strings.TrimSpace(account.PrincipalID), strings.TrimSpace(principalID)) {
					return strings.TrimSpace(account.Email)
				}
			}
			return ""
		}, evaluator.PolicyBundle.TenantID, config.TenantModelStore,
		// ★★★ THE SAME QUESTION /enroll ASKS, ANSWERED FROM WHICHEVER SOURCE THIS NODE HAS. A control plane
		// HOLDS the per-organization device authorities; an Edge holds the signers the control plane installed
		// in it. The screen that issues enrolment tokens is served by the control plane, so a check written
		// against the Edge's signers alone reported every organization as unable to enrol — on a deployment
		// whose /enroll answers 200 for them.
		func(tenant string) bool {
			return nodeIssuesDeviceIdentitiesFor(config.TenantDeviceAuthority, tenant)
		}, config.ConfigSourceURL, config.OperatorTenantID)
	registerAdminLicenseEndpoints(mux, adminLicenseDeps{
		licence:     config.VendorLicense,
		allocations: config.SeatAllocations,
		licensing:   config.EnrolmentLicensing,
		ledger:      config.EnrolledLedger,
		displayName: func(tenantID string) string {
			if tenantModelStore == nil {
				return ""
			}
			t, err := tenantModelStore.Get(context.Background(), tenantID)
			if err != nil {
				return ""
			}
			return t.DisplayName
		},
		acceptedKeys:  config.LicenseAcceptedKeys,
		recipientKey:  config.LicenseRecipientKey,
		msspID:        config.LicenseMSSPID,
		oversubscribe: config.LicenseAllowOversubscription,
	}, adminEndpoint)
	mux.HandleFunc("GET /admin/enrolled-devices", adminEndpoint("admin.enrollment.read", func(w http.ResponseWriter, r *http.Request) {
		if !pinnedTenantContextMatches(w, r) {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		// effective_risk per device: resolve the SAME risk the decision path acts on, so the Console Risk column
		// can't drift below enforcement. enrichDecisionRequestWithRisk folds in the shared high-risk overlay, the
		// device-store metadata risk_state_severity, AND the device-group risk floor — the third of which the
		// Console previously never saw (it only overlaid the risk-signals map + group floor), so an operator could
		// read "normal" while the decision saw "high". Computing it server-side with the decision's own helper closes
		// that observability gap by construction.
		// agent_version per device, joined here for the same reason effective_risk is: the Console must not be
		// able to show a version that differs from the one the rollout acts on. It is also the RUNNING version
		// rather than an installed marker — the value comes from the agent's own heartbeat, so the process that
		// reports it is the process that is executing. That distinction is the whole point on a box holding new
		// bytes and running old ones (a driver that could not be unloaded, an extension replaced on restart),
		// which is exactly the box an operator is looking for in this list.
		//
		// last_seen_at travels with it because a version with no recency is a trap: a device that stopped
		// reporting last month shows its last known version indefinitely, and "it says 0.1.0" then means
		// "it said 0.1.0 once", which reads identically and is not the same claim.
		// ★★★ AN OPERATOR MAY NAME AN ORGANIZATION HERE, AND UNTIL NOW COULD NOT (2026-09-01, found on the
		// night this deployment was going to be destroyed). -who-depends — the tool whose whole purpose is to
		// answer "who would this destroy" immediately before an irreversible act — holds the deployment
		// administrator's token, so it read the OPERATOR's roster, found it empty, and reported "nothing is
		// enrolled here, so no machine depends on this deployment" while four devices were enrolled and one of
		// them was carrying every flow on the operator's own laptop. The next line of the same report said
		// "45 device(s) across 6 node(s)", so it contradicted itself and still rendered a tick.
		//
		// Same rule as everywhere else: an operator may name an organization, a customer naming another is
		// refused rather than quietly redirected into its own.
		callerTenant, callerTenantErr := adminTenantForWrite(r, r.URL.Query().Get("tenant_id"))
		if callerTenantErr != nil {
			writeError(w, http.StatusForbidden, callerTenantErr)
			return
		}
		entries := config.EnrolledLedger.List()
		type enrolledDeviceDTO struct {
			enrolledinventory.Entry
			EffectiveRisk string `json:"effective_risk,omitempty"`
			AgentVersion  string `json:"agent_version,omitempty"`
			LastSeenAt    string `json:"last_seen_at,omitempty"`
		}
		// One store read for the whole list rather than a lookup per device: the list is rendered on every
		// Console refresh, and a per-row query against a Postgres-backed store turns one page view into N.
		runtimeByID := map[string]model.Device{}
		if devices, err := devicesForTenant(deviceStore, callerTenant); err == nil {
			runtimeByID = runtimeDevicesByIdentity(devices, callerTenant)
		} else {
			// Deliberately not fatal, and deliberately logged. The enrolment list is the answer to "which
			// devices exist", and refusing to render it because the telemetry join failed would take away the
			// page an operator uses to diagnose. The columns come back empty, which reads as "not reported"
			// rather than as a wrong version.
			log.Printf("admin enrolled-devices: agent version/last-seen join unavailable (%v); those columns will be blank", err)
		}
		out := make([]enrolledDeviceDTO, 0, len(entries))
		// unassigned is what this answer WITHHELD because it belongs to no tenant. Counted rather than dropped:
		// withholding without saying so is a device that vanished, and a fleet nobody can act on is exactly the
		// thing an operator needs to be told about.
		unassigned := 0
		// Connectors enrol like devices and belong in the ledger; they are not endpoints, and a screen that
		// says "devices" must not carry them. See a_connector_is_not_a_device_on_the_devices_screen.go.
		connectors := connectorIdentitiesFor(registry, callerTenant)
		withheldConnectors := 0
		for _, e := range entries {
			if isConnectorIdentity(connectors, e.Identity) {
				withheldConnectors++
				continue
			}
			// Tenant isolation: only devices in the caller's tenant. An entry with NO tenant belongs to no
			// tenant and is in nobody's list — see deviceGroupVisibleToTenant for why the two empties are
			// different questions.
			if strings.TrimSpace(e.TenantID) == "" && strings.TrimSpace(callerTenant) != "" {
				unassigned++
				continue
			}
			if !deviceGroupVisibleToTenant(e.TenantID, callerTenant) {
				continue
			}
			eff := enrichDecisionRequestWithRisk(
				model.DecisionRequest{DeviceID: e.Identity, TenantID: e.TenantID},
				deviceStore, config.HighRiskOverlay, config.EnrolledLedger,
			).RiskStateSeverity
			dto := enrolledDeviceDTO{Entry: e, EffectiveRisk: eff}
			if d, ok := runtimeByID[enrolledinventory.NormalizeIdentity(e.Identity)]; ok {
				dto.AgentVersion = d.AgentVersion
				dto.LastSeenAt = d.LastSeenAt
			}
			out = append(out, dto)
		}
		body := map[string]any{"schema_version": "admin_enrolled_inventory.v1", "tenant_id": callerTenant,
			"devices": out, "no_secret_attestation": true}
		if unassigned > 0 {
			body["unassigned"] = unassigned
		}
		// Said rather than silently omitted: an operator who counts three agents and sees one device is owed
		// the reason, and the Connectors screen is where the other two live.
		if withheldConnectors > 0 {
			body["connectors_not_listed_here"] = withheldConnectors
		}
		writeJSON(w, http.StatusOK, body)
	}))
	mux.HandleFunc("POST /admin/enrolled-devices", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		// The enrolled SET (incl. enable/disable) is bundle-distributed, so author it on the CP. Phase 1
		// distributes a disable at config latency; the emergency kill-switch (revocation.AdmissionRevocations overlay) is
		// a separate node-local path (Phase 3), not this ledger.
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		var req struct {
			Identity string `json:"identity"`
			Note     string `json:"note"`
			Group    string `json:"group"` // M7: optional CP-assigned device group (union-model scope selector)
			// MachineRef arrives only from an ISSUING node reporting an enrolment it performed. It is what
			// lets this deployment tell a machine from its namesake, and it has to be stored HERE because
			// this ledger is what every Edge's copy is rebuilt from. See RecordReportedMachine.
			MachineRef string `json:"machine_ref,omitempty"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode enroll device: %w", err))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		// ★ ENROLLING AN IDENTITY THAT ALREADY EXISTS WAS A TAKEOVER (2026-08-12, seventeenth review). This
		// route calls the ledger on whatever identity arrives, and the enrol write OVERWRITES the entry's
		// TenantID with the caller's — re-enabling it on the way past. So an admin of tenant A who knew a
		// device id belonging to tenant B could POST it and move that machine into their own fleet, disabled
		// devices included. Knowing an identifier is not authority over the thing it names.
		//
		// ★ AND THE CHECK BELONGS INSIDE THE LOCK (2026-08-12, eighteenth review). The first fix read the
		// entry, decided, and then wrote — two acquisitions, so two tenants POSTing the same UNREGISTERED id
		// at once both saw "does not exist" and the later write took the device. Same race between a new
		// machine's first enrolment and an attacker's POST. EnrollGroupForTenant answers ownership and writes
		// in one critical section.
		//
		// An UNASSIGNED entry belongs to nobody, and adopting one is an operator action: a tenant-scoped admin
		// cannot even see it, so `claimant` is the caller's tenant and an operator (unscoped, or holding
		// admin.tenant.admin with X-Operate-Tenant) passes empty and may assign it.
		entry, err := config.EnrolledLedger.EnrollGroupForTenant(req.Identity, tenantID, tenantID, req.Group,
			req.Note, time.Now().UTC().Format(time.RFC3339), adminCallerIsOperator(r))
		if errors.Is(err, enrolledinventory.ErrIdentityUnassigned) {
			// ★ THIS BRANCH USED TO BE UNREACHABLE (2026-08-12, eighteenth review). The Console tells an
			// operator that unassigned devices are theirs to assign, and no call could do it: a tenant-scoped
			// caller was refused before getting here, and an unscoped one re-saved the empty tenant. It is a
			// real path now — an operator (unscoped, or admin.tenant.admin with X-Operate-Tenant) adopts the
			// device into the tenant they are operating within — and this refusal is what a TENANT admin gets.
			writeError(w, http.StatusConflict, err)
			return
		}
		if errors.Is(err, enrolledinventory.ErrIdentityOwnedByAnotherTenant) {
			// Not 403: whether a device exists in another tenant is not this caller's to learn, and it is the
			// same answer the delete path gives.
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", req.Identity))
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Reported, not authored: an issuing node saying which machine it issued to. Recorded after the
		// identity exists and only when this deployment does not already know — never as a way to move a name
		// to a different machine.
		if ref := strings.TrimSpace(req.MachineRef); ref != "" {
			if merr := config.EnrolledLedger.RecordReportedMachine(entry.Identity, ref,
				time.Now().UTC().Format(time.RFC3339)); merr != nil {
				// Not fatal to the enrolment: the device is admitted either way, and losing this costs the
				// deployment a distinction rather than a machine. Said out loud so it is not lost silently.
				logWarnf("enrolled_inventory: the machine reported for %q was not recorded (%v) — this "+
					"deployment cannot yet tell that machine from another of the same name", entry.Identity, merr)
			} else if e, ok := config.EnrolledLedger.EntryFor(entry.Identity); ok {
				entry = e
			}
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(tenantID, "enroll", entry, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "device": entry})
	}))
	// ★ RE-ENROLMENT IS ITS OWN OPERATION (2026-08-12, twenty-first review). It used to be a side effect of
	// the ordinary enrol POST, so an admin fixing a note or assigning a group re-opened enrolment for that
	// device — and the audit line said `enrolled_inventory_enroll`, exactly as it would for a first
	// pre-approval. A decision nobody can find in the record is one nobody can review; this one is worth
	// finding, because it is what lets a machine obtain a certificate in an existing device's name.
	mux.HandleFunc("POST /admin/enrolled-devices/{identity}/allow-reenrolment", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		identity := strings.TrimSpace(r.PathValue("identity"))
		tenantID := adminTenantIDFromRequest(r)
		// The before-image comes back from the same lock as the write, so what the record says this grant
		// replaced is what it replaced — a separate EntryFor could be overtaken by another enrolment or re-arm
		// between the read and the write, in the one record whose purpose is naming what it superseded.
		entry, before, err := config.EnrolledLedger.AllowReenrolment(identity, tenantID, time.Now().UTC().Format(time.RFC3339))
		if errors.Is(err, enrolledinventory.ErrIdentityNotFound) ||
			errors.Is(err, enrolledinventory.ErrIdentityOwnedByAnotherTenant) {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Its own audit action, carrying what was replaced: the enrolment this permission supersedes, and the
		// grant number, so "who let this device enrol again, and which certificate did that invalidate the
		// exclusivity of" is answerable from the record alone.
		record := enrolledInventoryAuditLog(tenantID, "allow_reenrolment", entry, evaluator, sourceIPFromRequest(r))
		if record.Metadata == nil {
			record.Metadata = map[string]any{}
		}
		record.Metadata["reenrolment_grant"] = entry.ReenrolmentNonce
		// ★ AND WHETHER THIS LIFTED A REMOVAL, which is a different act from re-arming an enrolment
		// (2026-08-25). Until today a removal could not be lifted at all — the tombstone was permanent and
		// every route answered success while nothing changed. Now that it can be, the record has to say
		// which of the two happened, or the audit reads the same for "let this device enrol again" and
		// "bring a device an administrator deleted back into the fleet".
		if strings.TrimSpace(before.RemovedAt) != "" {
			record.Metadata["removal_lifted"] = true
			record.Metadata["removed_at"] = before.RemovedAt
		}
		if strings.TrimSpace(before.DeviceEnrolledAt) != "" {
			record.Metadata["superseded_device_enrolled_at"] = before.DeviceEnrolledAt
		}
		record.Metadata["superseded_reenrolment_grant"] = before.ReenrolmentNonce
		// ★ THROUGH THE AUDITED APPEND, NOT writer.Append (2026-08-12, twenty-second review). The direct call
		// discards its error and never reaches the audit outbox, so the one record that says WHICH grant
		// replaced WHICH enrolment could vanish without a word — leaving the middleware's generic line, which
		// has the path and the status and neither of those facts. This is the permission that lets a machine
		// obtain a certificate in an existing device's name; it is the last record that should be best-effort.
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, record, time.Now().UTC())
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "device": entry})
	}))
	mux.HandleFunc("POST /admin/enrolled-devices/{identity}/enable", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		adminSetEnrolledDeviceEnabled(w, r, config.EnrolledLedger, writer, adminAuditOutbox, evaluator, enrolledLedgerOr503, true)
	}))
	mux.HandleFunc("POST /admin/enrolled-devices/{identity}/disable", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		adminSetEnrolledDeviceEnabled(w, r, config.EnrolledLedger, writer, adminAuditOutbox, evaluator, enrolledLedgerOr503, false)
	}))
	// M7: assign/change a device's CP-authoritative group (Device Groups and their ASSIGNMENT — the union-model scope selector
	// the agent-policy/agent-tuning resolution reads via cpAuthoritativeGroup). An empty group clears the
	// assignment (tenant-scope only). Same admin-scope + config-sourced guard as the other ledger mutations.
	mux.HandleFunc("POST /admin/enrolled-devices/{identity}/group", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		var req struct {
			Group string `json:"group"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode assign group: %w", err))
			return
		}
		identity := strings.TrimSpace(r.PathValue("identity"))
		tenantID := adminTenantIDFromRequest(r)
		// Tenant isolation (review finding #2): a device in another tenant is not-found (don't reassign it).
		if cur, ok := config.EnrolledLedger.EntryFor(identity); !ok || !deviceGroupVisibleToTenant(cur.TenantID, tenantID) {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		entry, ok, perr := config.EnrolledLedger.SetGroup(identity, req.Group, time.Now().UTC().Format(time.RFC3339))
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		if perr != nil {
			// ★ THE WAVE GROUP DECIDES WHICH RING THIS DEVICE UPDATES IN (2026-08-13, thirty-first review #8).
			// Answering 200 to a move that did not reach the disk means the next control-plane restart puts the
			// device back in its old ring — pilot, taking a release on wave 0, which is the ring that exists to
			// catch a bad build before the fleet does. The change IS in force until then, and the caller is told
			// what it has to do about it.
			writeError(w, http.StatusInternalServerError, fmt.Errorf("%s is in group %q on this node and the "+
				"change was NOT stored durably (%w) — it will revert on the next restart, so apply it again once "+
				"the store is healthy", identity, req.Group, perr))
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(tenantID, "assign_group", entry, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "device": entry})
	}))
	// Declare what an identity IS. A connector holds a transport certificate and is admitted from this same
	// ledger, but it runs no agent and reports no posture — so "enrolled and silent" means something entirely
	// different for it than for a laptop, and the posture gate needs to be told which it is looking at.
	// Declared, never inferred: see enrolledinventory.Entry.Kind for why absence must not be the signal.
	mux.HandleFunc("POST /admin/enrolled-devices/{identity}/kind", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		var req struct {
			Kind string `json:"kind"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode set kind: %w", err))
			return
		}
		identity := strings.TrimSpace(r.PathValue("identity"))
		tenantID := adminTenantIDFromRequest(r)
		if cur, ok := config.EnrolledLedger.EntryFor(identity); !ok || !deviceGroupVisibleToTenant(cur.TenantID, tenantID) {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		entry, ok, perr := config.EnrolledLedger.SetKind(identity, req.Kind, time.Now().UTC().Format(time.RFC3339))
		if perr != nil && !ok {
			// An unknown kind: refuse rather than store it. A typo must not quietly become "not an endpoint",
			// because that is the reading under which silence stops being a finding.
			writeError(w, http.StatusBadRequest, perr)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		if perr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("%s is kind %q on this node and the change "+
				"was NOT stored durably (%w) — it reverts on the next restart, and until it does the posture gate "+
				"reads this identity under the old kind", identity, req.Kind, perr))
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(tenantID, "set_kind", entry, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "device": entry})
	}))
	mux.HandleFunc("DELETE /admin/enrolled-devices/{identity}", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "enrolled inventory") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		identity := strings.TrimSpace(r.PathValue("identity"))
		tenantID := adminTenantIDFromRequest(r)
		// Tenant isolation (review finding #2): a device in another tenant is not-found (don't delete it).
		if cur, ok := config.EnrolledLedger.EntryFor(identity); !ok || !deviceGroupVisibleToTenant(cur.TenantID, tenantID) {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		if !config.EnrolledLedger.Remove(identity, time.Now().UTC().Format(time.RFC3339)) {
			writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(tenantID, "remove", enrolledinventory.Entry{Identity: enrolledinventory.NormalizeIdentity(identity)}, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "removed": true, "identity": enrolledinventory.NormalizeIdentity(identity)})
	}))
	// Device-group REGISTRY (first-class groups). Distinct from the per-device assignment (Entry.Group): this is
	// the authoritative catalog of groups that EXIST, so the Console offers created groups for tab-select
	// assignment instead of free-form typing. Reuses the enrolled ledger's durable store (no new plumbing).
	mux.HandleFunc("GET /admin/device-groups", adminEndpoint("admin.enrollment.read", func(w http.ResponseWriter, r *http.Request) {
		if !enrolledLedgerOr503(w) {
			return
		}
		callerTenant := adminTenantIDFromRequest(r)
		// device_count per group: match the per-device assignment string (Entry.Group) to the registry name
		// (normalized), since a device assignment still records its group by name. Scoped to the caller's tenant so
		// a cross-tenant device can't inflate another tenant's count (M2).
		counts := map[string]int{}
		for _, e := range config.EnrolledLedger.List() {
			if !deviceGroupVisibleToTenant(e.TenantID, callerTenant) {
				continue
			}
			if g := enrolledinventory.NormalizeGroupName(e.Group); g != "" {
				counts[g]++
			}
		}
		type groupDTO struct {
			enrolledinventory.Group
			DeviceCount int `json:"device_count"`
		}
		// M2 tenant isolation: only surface groups belonging to the caller's tenant (empty tenant on either side is
		// unscoped/legacy and stays visible — lockout-safe for the single-tenant edge).
		groups := config.EnrolledLedger.ListGroups()
		out := make([]groupDTO, 0, len(groups))
		for _, g := range groups {
			if !deviceGroupVisibleToTenant(g.TenantID, callerTenant) {
				continue
			}
			out = append(out, groupDTO{Group: g, DeviceCount: counts[enrolledinventory.NormalizeGroupName(g.Name)]})
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_group_registry.v1", "tenant_id": callerTenant, "groups": out})
	}))
	mux.HandleFunc("POST /admin/device-groups", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "device group registry") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Risk        string `json:"risk"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode create group: %w", err))
			return
		}
		tenantID := adminTenantIDFromRequest(r)
		g, err := config.EnrolledLedger.CreateGroup(req.Name, tenantID, req.Description, req.Risk, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(tenantID, "create_group", enrolledinventory.Entry{Identity: g.ID, Group: g.Name}, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_group_registry.v1", "group": g})
	}))
	mux.HandleFunc("DELETE /admin/device-groups/{id}", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "device group registry") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		callerTenant := adminTenantIDFromRequest(r)
		grp, ok := config.EnrolledLedger.GroupByID(id)
		// M2 tenant isolation: a group in another tenant is treated as NOT FOUND (don't leak its existence or let
		// this admin delete it).
		if !ok || !deviceGroupVisibleToTenant(grp.TenantID, callerTenant) {
			writeError(w, http.StatusNotFound, fmt.Errorf("device group %q not found", id))
			return
		}
		// Refuse to delete a group that still has devices assigned (would orphan the assignment), unless
		// ?force=true: reassign first, or force. Match by normalized name (assignment is by name), scoped to the
		// caller's tenant.
		if r.URL.Query().Get("force") != "true" {
			assigned := 0
			for _, e := range config.EnrolledLedger.List() {
				if !deviceGroupVisibleToTenant(e.TenantID, callerTenant) {
					continue
				}
				if enrolledinventory.NormalizeGroupName(e.Group) == enrolledinventory.NormalizeGroupName(grp.Name) {
					assigned++
				}
			}
			if assigned > 0 {
				writeError(w, http.StatusConflict, fmt.Errorf("device group %q still has %d assigned device(s); reassign them first or pass ?force=true", grp.Name, assigned))
				return
			}
		}
		removed, derr := config.EnrolledLedger.DeleteGroup(id)
		if !removed {
			writeError(w, http.StatusNotFound, fmt.Errorf("device group %q not found", id))
			return
		}
		if derr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("device group %q was removed on this node and "+
				"the change was NOT stored durably (%w) — it will come back, with every device's membership of it, "+
				"on the next restart", id, derr))
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(callerTenant, "delete_group", enrolledinventory.Entry{Identity: id, Group: grp.Name}, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_group_registry.v1", "removed": true, "id": id})
	}))
	mux.HandleFunc("PATCH /admin/device-groups/{id}", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "device group registry") {
			return
		}
		if !enrolledLedgerOr503(w) {
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		callerTenant := adminTenantIDFromRequest(r)
		// M2 tenant isolation: a group in another tenant is NOT FOUND (don't leak its existence or let this admin
		// edit it) — checked BEFORE UpdateGroup so a cross-tenant PATCH never mutates.
		if grp, ok := config.EnrolledLedger.GroupByID(id); !ok || !deviceGroupVisibleToTenant(grp.TenantID, callerTenant) {
			writeError(w, http.StatusNotFound, fmt.Errorf("device group %q not found", id))
			return
		}
		// Partial update (design): each field is a pointer so an omitted key leaves it unchanged; the id is
		// immutable. A rename cascades to member device assignments (by-name) inside UpdateGroup so the floor stays
		// attached.
		var req struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
			Risk        *string `json:"risk"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode update group: %w", err))
			return
		}
		g, reassigned, err := config.EnrolledLedger.UpdateGroup(id, req.Name, req.Description, req.Risk, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			// Absent id → 404; empty name / name collision → 409 (mirrors CreateGroup's conflict handling).
			if _, ok := config.EnrolledLedger.GroupByID(id); !ok {
				writeError(w, http.StatusNotFound, err)
				return
			}
			writeError(w, http.StatusConflict, err)
			return
		}
		_ = writer.Append("audit.log.jsonl", enrolledInventoryAuditLog(callerTenant, "update_group", enrolledinventory.Entry{Identity: g.ID, Group: g.Name}, evaluator, sourceIPFromRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_group_registry.v1", "group": g, "reassigned_devices": reassigned})
	}))
	// admin DNS-policy API: read + hot-apply the Edge DNS ruleset (deny/sinkhole/stub/ECH-strip) at
	// runtime. API-first management surface for DNS control; without it the ruleset was env-built only.
}

// nodeIssuesDeviceIdentitiesFor answers the question /enroll answers before it refuses: can THIS deployment
// sign a device certificate for that organization?
//
// ★★★ THE TWO ROLES ANSWER IT FROM DIFFERENT PLACES, AND A CHECK THAT KNEW ONE WAS WRONG ON THE NODE THAT
// SERVES THE SCREEN (2026-08-28, measured on the lab after shipping the first version of this). A control plane
// HOLDS the per-organization device authorities; an Edge holds the signers a control plane installed in it. The
// enrolment-token screen is served by the control plane, so asking only the Edge's signer map reported every
// organization as unable to enrol — on a deployment whose /enroll answers 200 for them, which is the very
// defect the message was being corrected for.
func nodeIssuesDeviceIdentitiesFor(authority *tenantDeviceAuthority, tenant string) bool {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return false
	}
	if authority != nil {
		if _, known := authority.Row(tenant); known {
			return true
		}
	}
	return tenantDeviceIdentity.For(tenant) != nil
}

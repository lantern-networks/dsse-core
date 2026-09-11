package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agenttuning"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Device-facing steer/bootstrap data-plane routes — signed agent policy (+pubkey/
// effective/posture), agent tuning, server-initiated inbound export, the signed trust
// bundle, and residency-filtered region endpoints — moved verbatim out of
// newServerWithConfig (Phase 2 route-registration split). Takes serverConfig whole:
// this surface reads the signing/trust-bundle/exclusion config set.
func registerSteerAgentPolicyRoutes(mux *http.ServeMux, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, deviceStore deviceRuntimeStore, edgeRenewBefore *renewBeforeSetting, policyStore policy.RuntimeStore, tenantModelStore adminTenantModelRuntimeStore) {
	// Assigned during route registration, before this handler can serve requests.
	// The hint and bootstrap response must read the same per-tenant envelope.
	var offeredTrustBundle func(string) (agentpolicy.Envelope, bool)
	mux.HandleFunc("GET /steer/agent-policy/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if config.AgentPolicySigner == nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("agent-policy signing is not enabled"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"key_id":     config.AgentPolicySigner.KeyID(),
			"public_key": config.AgentPolicySigner.PublicKeyHex(),
		})
	})

	// (T) transport: a registered device pulls its ADMIN-RESOLVED steer-exclusion set, keyed to the identity
	// the mTLS client cert PROVES (not a client-claimed id). Served only to a verified (T) client, so a device
	// cannot request another device's policy and an unauthenticated caller gets nothing. The agent applies the
	// server-issued set and ignores any local list (slice 2 of docs/admin_managed_steer_exclusions_design.md).
	mux.HandleFunc("GET /steer/agent-policy", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		// The DEVICE's tenant, not this node's — see steerDeviceTenant. Handing an organization the material of
		// whichever organization happens to own the Edge is how a second customer received the first one's
		// enforcement.
		tenantID := steerDeviceTenant(r, config, identity, evaluator.PolicyBundle.TenantID)
		if strings.TrimSpace(tenantID) == "" {
			// See steerDeviceTenant: two authoritative questions, neither answered, and the node's own
			// organization is not a third answer. Refused rather than served somebody else's configuration.
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"this deployment cannot say which organization %q belongs to: its certificate chains to no "+
					"registered Tenant CA and no organization's enrolled inventory holds it. Enrol it, or "+
					"register its organization's Tenant CA on this node", identity))
			return
		}
		// CP-AUTHORITATIVE group (enrollment-assigned, from the ledger) — NOT deviceStore.Metadata, which a device
		// can self-assert via heartbeat. The group selects the steer-exclusion set (an ENFORCEMENT control: which
		// apps bypass steering), so a device-spoofable group would let a device pick a more permissive set.
		group := cpAuthoritativeGroup(config.EnrolledLedger, identity)
		// ★★★ SAID, NOT REFUSED — see the_second_door_admits_devices_the_first_one_refuses.go. The transport
		// port turns away a device the enrolled ledger does not admit; this port has no such check, so a
		// disabled laptop keeps collecting the organization's enforcement configuration while every screen
		// says it is disabled. Measured 2026-08-22. Closed properly by the enrolment fold.
		unadmittedDeviceReports.noteAnsweredWithoutAdmission("/steer/agent-policy", identity, tenantID,
			deviceIsAdmitted(config.EnrolledLedger, identity), time.Now(), logInfof)
		excluded := []string{}
		if config.SteerExclusions != nil {
			excluded = config.SteerExclusions.ResolveForDevice(tenantID, identity, group)
		}
		payload := map[string]any{
			"schema_version":           agentpolicy.EnvelopeType,
			"tenant_id":                tenantID,
			"device_identity":          identity,
			"device_group":             group,
			"excluded_app_signing_ids": excluded,
		}
		// A declaration, not a command: any certificate older than this is stale and should be replaced. An
		// agent that has already renewed holds a newer one, so the statement stops applying to it by itself —
		// which is why there is nothing to acknowledge and no way to renew twice. Omitted entirely when nothing
		// is being asked, so an agent that never sees the field behaves exactly as before.
		if cutoff := edgeRenewBefore.RFC3339(); cutoff != "" {
			payload["renew_certificates_issued_before"] = cutoff
		}
		// Which interception roots to look for in the local trust store. This is a QUESTION, not a change to
		// what the device trusts, so it belongs on the document the agent fetches every minute rather than on
		// the trust bundle — that one is gated behind a monotonic serial, correctly, and an agent therefore
		// only ever saw these when the trust set itself changed, which in a deployment that is not rotating is
		// never. Verified live: nothing reported until this moved here.
		//
		// ★★★ AND IT MUST BE THIS DEVICE'S ORGANIZATION'S ROOT, NOT THE NODE'S (2026-08-19, reported from
		// win-dev-1 and reproduced here). This asked for the node-wide answer — the deployment's own root —
		// while an organization with an issuer of its own has its traffic
		// signed under ITS root. So the Edge told that organization's devices to look for a certificate nothing
		// signs with, and said nothing about the one that does.
		//
		// What that cost, measured on the box: with steering armed, github.com arrived signed by "Lab Tenant
		// Interception Issuing CA 2028" under "Lab Tenant Interception Root 2028", a root in no store on that
		// machine — schannel refused it too, so EVERY HTTPS request on the machine failed at once. And the
		// signal built to prevent exactly that reported interception_root_trust wanted=1 found=1 in the same
		// window, because the box does hold the root it was TOLD to look for. Nothing compared the announced
		// root with the signing one.
		//
		// The tenant-aware answer already existed and was already used by the trust bundle (see
		// interceptionRootFingerprintsForTenant). Both agent-facing documents now use it, so the announcement
		// is derived from what signs rather than kept in step with it by hand.
		if roots := interceptionRootFingerprintsForTenant(config, tenantID, evaluator.PolicyBundle.TenantID); len(roots) > 0 {
			payload["interception_root_sha256"] = roots
		}
		// Sign the policy so the NE applies only the server-issued set (verified against the trusted-keyring
		// public key) and ignores any locally-edited list. Unsigned only when no key is provisioned.
		if config.AgentPolicySigner != nil {
			env, serr := config.AgentPolicySigner.Sign(payload, time.Now())
			if serr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("sign agent policy: %w", serr))
				return
			}
			writeJSON(w, http.StatusOK, env)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})

	// M7: GET /steer/agent-tuning — the live signed tuning policy (captive timing) resolved per device by its
	// group (tenant → group → device overlay), signed with the SAME key as agent-policy so the agent pins one
	// key. Mirrors the agent-policy handler (verified transport identity → group lookup → sign). The agent's
	// tuner (M5c) fetches this; a bad/absent bundle keeps its current settings.
	mux.HandleFunc("GET /steer/agent-tuning", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		// The DEVICE's tenant, not this node's — see steerDeviceTenant. Handing an organization the material of
		// whichever organization happens to own the Edge is how a second customer received the first one's
		// enforcement.
		tenantID := steerDeviceTenant(r, config, identity, evaluator.PolicyBundle.TenantID)
		if strings.TrimSpace(tenantID) == "" {
			// See steerDeviceTenant: two authoritative questions, neither answered, and the node's own
			// organization is not a third answer. Refused rather than served somebody else's configuration.
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"this deployment cannot say which organization %q belongs to: its certificate chains to no "+
					"registered Tenant CA and no organization's enrolled inventory holds it. Enrol it, or "+
					"register its organization's Tenant CA on this node", identity))
			return
		}
		// CP-AUTHORITATIVE group: read the enrollment-assigned group from the ledger keyed by the mTLS-verified
		// identity — NEVER deviceStore.Metadata["device_group"], which the device can self-assert via heartbeat.
		group := cpAuthoritativeGroup(config.EnrolledLedger, identity)
		policy := agenttuning.Resolve(tenantID, group, identity, config.AgentTuningScoped)
		if config.AgentPolicySigner != nil {
			env, serr := config.AgentPolicySigner.Sign(policy, time.Now())
			if serr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("sign agent tuning: %w", serr))
				return
			}
			writeJSON(w, http.StatusOK, env)
			return
		}
		writeJSON(w, http.StatusOK, policy)
	})

	// DEVICE-facing server-initiated inbound export: the endpoint agent pulls ITS OWN inbound policy over the
	// (T) transport, authorized by the mTLS device identity — no admin secret on endpoints (the admin route
	// GET /admin/legacy-exceptions/export stays admin-only for operators / agentless FW export). Same
	// server_initiated_export.v1 body + the same toggle reflection as the admin route, so the Windows firewall
	// backend just points --inbound-export-url here and drops the admin token. Resolves the handoff
	// gap (docs/handoff_windows_server_initiated_firewall_done.md): the admin export is unreachable/401 from an
	// endpoint after admin-auth centralization, so there was no device route for the inbound policy.
	mux.HandleFunc("GET /steer/server-initiated-export", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		// The DEVICE's tenant, not this node's — see steerDeviceTenant. Handing an organization the material of
		// whichever organization happens to own the Edge is how a second customer received the first one's
		// enforcement.
		tenantID := steerDeviceTenant(r, config, identity, evaluator.PolicyBundle.TenantID)
		if strings.TrimSpace(tenantID) == "" {
			// See steerDeviceTenant: two authoritative questions, neither answered, and the node's own
			// organization is not a third answer. Refused rather than served somebody else's configuration.
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"this deployment cannot say which organization %q belongs to: its certificate chains to no "+
					"registered Tenant CA and no organization's enrolled inventory holds it. Enrol it, or "+
					"register its organization's Tenant CA on this node", identity))
			return
		}
		var exs []model.LegacyException
		if s, ok := policyStore.(interface {
			LegacyExceptionsFor(string) []model.LegacyException
		}); ok {
			exs = s.LegacyExceptionsFor(tenantID)
		}
		exp := buildServerInitiatedExport(exs, time.Now())
		if s, ok := policyStore.(interface {
			ServerInitiatedEnabledFor(string) bool
		}); ok && !s.ServerInitiatedEnabledFor(tenantID) {
			exp.DefaultAction = "allow" // toggle off = DSSE not managing inbound (agent withdraws its rules)
		}
		writeJSON(w, http.StatusOK, exp)
	})

	// (T) transport, reverse telemetry (G2): a registered device REPORTS the merged effective exclusion set it
	// is actually applying (floor + dev scaffold + admin set), keyed to the identity its mTLS client cert
	// PROVES — never a body-claimed id, so a device cannot report on another device's behalf. Observability
	// only: the Edge caches the latest report for the admin console (GET /admin/steer-exclusions/observed); it
	// never feeds enforcement. Best-effort: an agent that cannot report still steers correctly.
	mux.HandleFunc("POST /steer/agent-policy/effective", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		if config.ObservedExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("steer-exclusion telemetry is not enabled"))
			return
		}
		var body struct {
			Platform                string   `json:"platform"`
			EffectiveAppSigningIDs  []string `json:"effective_app_signing_ids"`
			ServerAppSigningIDCount int      `json:"server_app_signing_id_count"`
			// What the device received and deliberately did not apply. Reporter-declared and optional: an older
			// agent omits it, and absence must read as "did not say", never as "ignored nothing".
			IgnoredAppSigningIDs []string `json:"ignored_app_signing_ids"`
			// Device steering state (Phase 1, advisory display fields keyed to the verified device identity).
			Posture                  string `json:"posture"`
			FailOpenConfigured       bool   `json:"fail_open_configured"`
			RegionFailoverEnabled    bool   `json:"region_failover_enabled"`
			ActiveRegion             string `json:"active_region"`
			ServerInitiatedRuleCount int    `json:"server_initiated_rule_count"`
			// SHA-256 of every transport CA the device pins — the readiness signal for a CA rotation.
			PinnedTransportCASHA256 []string `json:"pinned_transport_ca_sha256"`
			// Which distribution those anchors came from. Fingerprints say what a device holds; only the serial
			// says whether it is holding the CURRENT set, and a device still on an older one is not ready
			// however good its fingerprints look (2026-08-01).
			AdoptedTrustSerial int64 `json:"adopted_trust_serial"`
			// The recovery name this device holds from the bundle — the fact the fold's last step turns on. Reported by
			// Windows since 0.2.10 and by macOS since 2026-08-19; empty means the agent did not say, which the
			// readiness measurement counts as "not yet" and never as ready.
			RenewalRecoverySNISent string `json:"renewal_recovery_sni_sent"`
			// ★★★ The SNI this device actually presents on its transport connection — the evidence the
			// enrolment fold turns on, reported by the agent and discarded here until 2026-08-22.
			TransportServerNameSent string `json:"transport_server_name_sent"`
			// ★★★ AND WHERE IT WOULD ACTUALLY DIAL — WHICH NOTHING READ (2026-08-20, measured on the lab).
			//
			// The readiness rule was extended on 2026-08-19 to require this: holding the name was being treated
			// as evidence of reaching it, and on one platform those were two pieces of code, so a box reported
			// the name and would still have dialled the port that had just been closed. The rule, the entry
			// field and the Postgres column all landed. THIS STRUCT DID NOT — so every device counted as silent
			// for ever, the fold's measurement could never say "holds", and the dedicated port was already
			// closed underneath it.
			//
			// Exactly the defect reported_recovery_name_reaches_the_store_test.go was written for, one field
			// later and one day later: "a reported field with no reader is the same silence as no field". A gate
			// now counts the entry's fields against this struct, because writing it down twice did not work.
			RenewalRecoveryTarget string `json:"renewal_recovery_target"`
			// Which of the interception roots this deployment advertised the device actually found in its own
			// trust store. Without it, switching that root is blind and breaks every site at once on any
			// machine that missed the distribution.
			PinnedInterceptionRootSHA256 []string `json:"pinned_interception_root_sha256"`
			// The ONE root this agent was installed pinned to — see observedExclusionEntry. Reported so the
			// Edge can tell whether ending a replacement overlap would strand this device.
			InterceptionRootPin string `json:"interception_root_pin_sha256"`
			// What this device REFUSED to trust, carried late. See observedTrustRefusal.
			TrustRefusals []observedTrustRefusal `json:"trust_refusals"`
			// ★★★ AND WHAT ITS OWN PROBE FOUND WRONG WITH THE CERTIFICATES INTERCEPTION SERVED IT
			// (2026-08-22). A different question from the line above, which is about the EDGE's certificate.
			// win-dev-1 ships this in 0.2.21; without this line every one of them was discarded at the door —
			// the third reported field to arrive here with no reader. See observedExclusionEntry.
			InterceptionRefusals []observedTrustRefusal `json:"interception_refusals"`
			// The client certificate this device would FALL BACK to if its renewed identity stopped
			// working. The retire gate consumes it — see observedExclusionEntry.FallbackClientCertPEM.
			FallbackClientCertPEM string `json:"fallback_client_cert_pem"`
			// The policy-signing keys this device would accept (pin + adopted). The signal the config-signing
			// key rotation turns on — see observedExclusionEntry.AgentPolicyPublicKeys.
			AgentPolicyPublicKeys []string `json:"agent_policy_public_keys"`

			// ★ Device posture on THIS channel, because the channel that carried it was the wrong one.
			//
			// Disk encryption and firewall arrived only as headers on the steer-mux CONNECT, so a device
			// reported them as a side effect of CARRYING TRAFFIC. Measured here on 2026-08-10: mac-dev-1 had no
			// device-runtime record at all while win-dev-1 had a full one, and the Console said the NE reported
			// neither signal. The collector was fine; nothing was ever asking it on a channel that runs.
			//
			// This report arrives every 15 s from an enrolled device whether or not it is steering anything, so
			// it is where a fleet view should learn both presence and posture. Pointers: absent means the agent
			// did not say, which must never be read as "off" — an unreported signal and a disabled one need
			// opposite responses.
			DiskEncryptionEnabled *bool  `json:"disk_encryption_enabled"`
			FirewallEnabled       *bool  `json:"firewall_enabled"`
			PostureSource         string `json:"posture_source"`
			DeviceOS              string `json:"device_os"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}
		// The DEVICE's tenant, not this node's — see steerDeviceTenant. Handing an organization the material of
		// whichever organization happens to own the Edge is how a second customer received the first one's
		// enforcement.
		tenantID := steerDeviceTenant(r, config, identity, evaluator.PolicyBundle.TenantID)
		if strings.TrimSpace(tenantID) == "" {
			// See steerDeviceTenant: two authoritative questions, neither answered, and the node's own
			// organization is not a third answer. Refused rather than served somebody else's configuration.
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"this deployment cannot say which organization %q belongs to: its certificate chains to no "+
					"registered Tenant CA and no organization's enrolled inventory holds it. Enrol it, or "+
					"register its organization's Tenant CA on this node", identity))
			return
		}
		// Presence and posture from the REPORT, not from carrying traffic. See the field comment above: this is
		// the channel an enrolled device uses every 15 s, and the runtime store's own doc names the gap it is
		// closing ("populated-by: side_effect — the steer-mux CONNECT ... a device is present in this store
		// because it STEERED, not because it is alive").
		if deviceRuntime != nil {
			deviceRuntime.ingestFromReport(identity, tenantID, body.DeviceOS, body.DiskEncryptionEnabled,
				body.FirewallEnabled, body.PostureSource, sourceIPFromRequest(r), time.Now())
		}
		// CP-AUTHORITATIVE group (ledger), consistent with the resolution path: classification against the
		// admin-resolved set must use the same group the CP assigned, not a device-reported one.
		group := cpAuthoritativeGroup(config.EnrolledLedger, identity)
		effective := normalizeReportedIDs(body.EffectiveAppSigningIDs)
		// Classify at record time (so Query/ByApp/anomalous are simple field reads, durable-store friendly):
		// admin = ∈ the admin-resolved set the Edge authored for THIS device; floor = matches the known-floor
		// allowlist; unmanaged = neither (flagged). ResolveForDevice is authoritative for "currently admin-authored".
		var resolved []string
		if config.SteerExclusions != nil {
			resolved = config.SteerExclusions.ResolveForDevice(tenantID, identity, group)
		}
		admin, unmanaged := classifyEffectiveExclusions(effective, adminResolvedSet(resolved), config.ObservedKnownFloor)
		serverInitiated := body.ServerInitiatedRuleCount
		if serverInitiated < 0 {
			serverInitiated = 0
		}
		// Built once and used twice: recorded in this node's own view, and SHIPPED to the control plane where
		// the durable copy lives. The Edge used to write this straight into Postgres — one of the six reasons
		// an enforcement node held a database connection. See observed_exclusion_ship.go.
		reportEntry := observedExclusionEntry{
			TenantID:                tenantID,
			DeviceIdentity:          identity,
			DeviceGroup:             group,
			Platform:                strings.TrimSpace(body.Platform),
			EffectiveAppSigningIDs:  effective,
			ServerAppSigningIDCount: body.ServerAppSigningIDCount,
			IgnoredAppSigningIDs:    body.IgnoredAppSigningIDs,
			AdminAppSigningIDs:      admin,
			UnmanagedAppSigningIDs:  unmanaged,
			ReportedAt:              time.Now(),
			// Advisory device-state (sanitized: posture is enum-clamped, region is length-bounded).
			Posture:               normalizeReportedPosture(body.Posture),
			FailOpenConfigured:    body.FailOpenConfigured,
			RegionFailoverEnabled: body.RegionFailoverEnabled,
			ActiveRegion:          boundReportedString(body.ActiveRegion, 253),
			// Reporter-declared and therefore sanitized: hex only, fixed length, bounded count. A device cannot
			// be trusted to say WHICH CA is correct — only which it happens to hold — and an operator compares
			// that against the CA they are deploying.
			PinnedTransportCASHA256: normalizeReportedFingerprints(body.PinnedTransportCASHA256),
			AdoptedTrustSerial:      body.AdoptedTrustSerial,
			// Reporter-declared, so bounded and lower-cased; it is compared with the name this node announces
			// and never used as one.
			RenewalRecoverySNISent:  strings.ToLower(boundReportedString(body.RenewalRecoverySNISent, 253)),
			TransportServerNameSent: strings.ToLower(boundReportedString(body.TransportServerNameSent, 253)),
			// host:port, so a little longer than a name and lower-cased the same way the name is.
			RenewalRecoveryTarget:        strings.ToLower(boundReportedString(body.RenewalRecoveryTarget, 300)),
			PinnedInterceptionRootSHA256: normalizeReportedFingerprints(body.PinnedInterceptionRootSHA256),
			// Sanitized like every other reporter-declared fingerprint: hex only, fixed length. A device says
			// which root it is pinned to; it does not get to say whether that is acceptable.
			InterceptionRootPinSHA256: firstOrEmpty(normalizeReportedFingerprints([]string{body.InterceptionRootPin})),
			// Merged, never replaced: the device clears its journal once we accept it, so its next report
			// carries none and a straight overwrite would erase the evidence we just received.
			TrustRefusals: trustRefusals.Merge(tenantID, identity,
				normalizeReportedTrustRefusals(body.TrustRefusals)),
			// Merged on its own key, never folded into the transport refusals: "the Edge's certificate was
			// refused" and "the certificate interception served is refused" are different failures with
			// different fixes, and one list would make them indistinguishable — which is the confusion the
			// device-side journal was built to end.
			InterceptionRefusals: interceptionRefusals.Merge(tenantID, identity,
				normalizeReportedInterceptionRefusals(body.InterceptionRefusals)),
			ServerInitiatedRuleCount: serverInitiated,
			// Parse-validated and re-encoded, never stored verbatim. Empty = the agent did not say, which
			// the retire gate treats as "no additional constraint" — older agents keep working unchanged.
			// CARRIED FORWARD when this report omits it: the store is latest-wins on whole entries, so one
			// report without the field would otherwise erase the recorded fallback — and an erased fallback
			// is not a device with no bootstrap, it is a retire gate that silently stopped being held shut
			// (2026-08-02: the constraint vanished for BOTH platforms while their agents were sending it
			// every minute, and the old CA read as freely retirable). A re-provisioned bootstrap REPLACES
			// the value on the next report, so carrying forward never pins a stale credential; the
			// telemetry shelf life bounds how long an unrefreshed one keeps counting.
			FallbackClientCertPEM: carryForwardFallbackCert(config.ObservedExclusions, tenantID, identity,
				normalizeReportedFallbackCert(body.FallbackClientCertPEM)),
			// Latest-wins, not carried forward: this is the device's CURRENT accepted set, which it sends every
			// report when configured and omits when it has only its pin. Keeping a stale set would show a
			// device ready for a switch it may since have lost the key for. Sanitised to the shapes the
			// verifier accepts, so a malformed entry cannot inflate apparent readiness.
			AgentPolicyPublicKeys: normalizeReportedPolicyKeys(body.AgentPolicyPublicKeys),
		}
		config.ObservedExclusions.Record(reportEntry)
		shipObservedExclusion(writer, reportEntry)
		// ★★★ "THERE IS A NEWER ONE" — A HINT, NOT AN INSTRUCTION (2026-08-20, asked for from the Windows side
		// after two fleet operations in one day were rate-limited by a device's six-hour adoption tick).
		//
		// Agents fetch the trust bundle on their own schedule: about a minute on macOS, six hours on Windows.
		// So every rotation, every overlap and every withdrawal lands up to six hours late, and twice today a
		// person had to restart a service on a box to pull the fleet forward. That does not scale past the two
		// machines in this lab.
		//
		// This report already happens every minute. The serial goes back on it, so an agent that sees a number
		// above the one it holds can fetch once, straight away, instead of waiting for its tick.
		//
		// ★ IT CANNOT BE USED TO MOVE A DEVICE. The serial is meaningful only INSIDE the signed bundle, which
		// the device verifies and only accepts strictly above what it holds. A lie here makes a device fetch a
		// bundle it will judge on its own terms — it can waste one request, and can neither install anything
		// nor roll anything back. A header rather than a body so the response stays 204 for every agent that
		// has never heard of it.
		if offeredTrustBundle != nil {
			if envelope, ok := offeredTrustBundle(tenantID); ok {
				keys := append([]string{config.AgentPolicySigner.PublicKeyHex()}, config.AgentPolicyNextPublicKeys...)
				if payload, err := agentpolicy.VerifyTrustBundleWithKeys(envelope, keys, 0); err == nil && payload.TenantID == tenantID {
					w.Header().Set("X-DSSE-Trust-Serial", strconv.FormatInt(payload.Serial, 10))
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Client-side geo-steering: hand the device its tenant's RESIDENCY-FILTERED allowed-region edge
	// endpoints (home-anchored,). The agent measures latency/health among them and connects to the nearest
	// healthy one — but it can only ever pick from regions inside the tenant's boundary, because an out-of-boundary
	// region is never emitted here. Signed with the same key as /steer/agent-policy so the agent verifies it.
	// Signed trust bundle. Deliberately NOT behind a device identity check: a device that can still prove who it
	// is does not need this document, and one that cannot is exactly who does. Nothing here is secret — the
	// anchors are public certificates — and the bundle grants nothing, so serving it to an unauthenticated caller
	// costs nothing. Obtaining a certificate still requires the recovery path, which checks the expired
	// certificate, the enrolment ledger and revocation.
	if strings.TrimSpace(config.TrustBundleCAPEM) != "" && config.TrustBundleSerial > 0 && config.AgentPolicySigner != nil {
		// Signed per CHANGE, never per request: the document is identical for every device, so re-signing it
		// on each fetch would let unauthenticated traffic spend the signing key. With -transport-trust-store
		// the set is runtime-mutable (add / gated withdraw from the Console) and each change re-signs once and
		// swaps atomically; without it, the flag file is the fixed set and this signs exactly once at startup.
		var servedBundle atomic.Pointer[agentpolicy.Envelope]
		bundleTenant := evaluator.PolicyBundle.TenantID
		resignBundle := func(pems string, serial int64) (func(), error) {
			// Name the interception roots too. An agent cannot report which one it trusts unless it is told
			// which to look for, and without that report a switch of the interception root is blind — see
			// docs/interception_root_switch_design.ja.md.
			// The keyring travels with the anchors: same document, same signature, same adoption path. A
			// device that has taken this bundle will accept the next signing key when it starts signing.
			// ★ The node tenant's OWN answer, for the same reason as the policy document above: once the node's
			// organization has an interception issuer of its own, the node-wide root is not what signs its
			// devices' traffic. This is the default bundle; the per-tenant bundles have asked this way since
			// 2026-08-18 (trust_bundle_per_tenant.go).
			env, err := config.AgentPolicySigner.SignTrustBundleWithKeyring(bundleTenant, serial, pems,
				config.TrustBundleRecoveryEndpoint,
				interceptionRootFingerprintsForTenant(config, bundleTenant, bundleTenant),
				config.AgentPolicyNextPublicKeys, time.Now())
			if err != nil {
				return nil, err
			}
			return func() {
				servedBundle.Store(&env)
				if fps, ferr := (agentpolicy.TrustBundlePayload{TransportCAPEM: pems}).Fingerprints(); ferr == nil {
					log.Printf("trust_bundle serving serial=%d anchors=%d fingerprints=%v", serial, len(fps), fps)
				}
			}, nil
		}
		servePEMs, serveSerial := config.TrustBundleCAPEM, config.TrustBundleSerial
		// ★ PER ORGANIZATION (2026-08-16). The bundle names the anchors a device must trust and the
		// interception roots it must find in its own store; both are now per organization, so one document for
		// the whole node tells every customer but one to look for a certificate they will never have. The
		// per-tenant bundles share the transport set and serial — that is the deployment's Edge identity — and
		// differ in which interception root they name. Signed ONCE PER ORGANIZATION PER CHANGE, never per
		// request: this endpoint is deliberately unauthenticated, and signing per request would let anonymous
		// traffic spend the signing key.
		perTenant := newPerTenantTrustBundles(config, bundleTenant)
		// ★ The admin screen answers from the same builder, so what an operator reads about an organization is
		// what that organization's devices are handed. There is exactly one builder on a node; a second one
		// would be a second answer to the same question, which is the shape this file keeps correcting.
		perTenantTrustBundlesForAdmin = perTenant
		if p := strings.TrimSpace(config.TransportTrustStorePath); p != "" {
			resign := func(pems string, serial int64) (func(), error) {
				commit, err := resignBundle(pems, serial)
				if err != nil {
					return nil, err
				}
				return func() {
					commit()
					// Every organization's signature is stale once the transport set moves.
					perTenant.SetTransportMaterial(pems, serial)
				}, nil
			}
			var store *transportTrustStore
			var serr error
			if config.TransportTrustSharedStore != nil {
				// A node that AUTHORS keeps this where every node that might author counts from the same
				// place — see openSharedTransportTrustStore. A node that receives keeps a file.
				store, serr = openSharedTransportTrustStore(config.TransportTrustSharedStore,
					config.TransportTrustCarriedFromPath, config.TrustBundleCAPEM, config.TrustBundleSerial, resign)
			} else {
				store, serr = openTransportTrustStore(p, config.TrustBundleCAPEM, config.TrustBundleSerial, resign)
			}
			if serr != nil {
				log.Fatalf("transport trust store: %v", serr)
			}
			transportTrust = store
			// ★★★ BEFORE THIS NODE IS ALLOWED TO CHANGE WHAT THE FLEET ANNOUNCES (2026-08-20, measured by
			// running it). The guard used to sit further down, next to the transport listener — and an
			// unprepared node reached the announcement FIRST, rewrote the shared store without the
			// per-organization anchors, the recovery name or the per-organization names, advanced the serial,
			// and then passed the guard because by then there was nothing left to keep.
			//
			// Measured on the reference lab: one scaled-out Edge with no per-organization material took the
			// fleet's announcement from "two organizations' anchors + two names + the recovery name" down to a
			// single fingerprint, at serial 55. Every device that adopted it would have lost the anchor it
			// verifies its own Edge with. The window was a minute because somebody was watching.
			//
			// So the check happens where the damage happens: a node that cannot serve what the fleet has
			// already promised does not get to speak for the fleet.
			// ★ FIRST, CATCH UP. A node whose incoming material is the authority the fleet already announces
			// is behind, not broken — and refusing it before it can move would take out a node that is one
			// promotion away from being correct. Only a node that CANNOT reach the announced authority is
			// refused below.
			for _, org := range transportTenantCertificates.TenantsWithPendingAuthority() {
				perTenant.CatchUpWithTheFleet(org, store.Announced())
			}
			if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(store.Announced(),
				func(name string) bool {
					_, _, ok := transportTenantCertificates.For(name)
					return ok
				},
				func(name string) bool {
					return strings.EqualFold(offeredRenewalRecoverySNI(config.RenewalRecoverySNI), name)
				},
				transportTenantCertificates.AnchorFingerprintsFor,
				func(tenant string) string {
					fp, _ := transportTenantCertificates.AnchorFingerprintFor(tenant)
					return fp
				},
				// ★ What the control plane last SAID the deployment's organizations are. A promise for one it
				// did not mention is stale, not unkeepable — see the note in fleetPromisesThisNodeCannotKeep.
				organizationIsGoneAccordingToTheControlPlane); err != nil {
				log.Fatalf("REFUSING TO JOIN THIS FLEET: %v", err)
			}
			servePEMs, serveSerial = store.Current()
		}
		// ★★★ THE SERIAL FOLLOWS EVERYTHING THIS DOCUMENT SAYS, NOT ONLY THE TRANSPORT SET (2026-08-19,
		// reported from win-dev-1). The interception roots ride in this bundle and the serial moved only when
		// the anchors did — so an organization moved onto its own interception root while the serial stayed at
		// 12, and an agent takes a new bundle only when the serial advances. That box held the bundle it
		// adopted on 2026-08-03 and answered the readiness question from it for fifteen days, naming a root
		// nothing had signed under for days.
		//
		// Checked here, at start-up, against what the last served bundle announced — remembered in the store,
		// so an unchanged announcement is not a change and a restart does not inflate the serial.
		// ★★★ AND IT IS RECOMPUTED WHILE THE NODE RUNS, NOT ONLY AT START-UP (2026-08-20, measured).
		//
		// This block used to run once. That was invisible because the control-plane material happens to be
		// fetched a few seconds BEFORE it on boot — so the per-organization anchors made it into the
		// announcement by ordering, not by design. Everything that changed afterwards did not:
		//
		//   - material refreshed at two thirds of its life, or arriving for an organization onboarded while
		//     this node was up, was installed and announced to nobody until the next restart
		//   - the promotion that CLOSES an overlap is evaluated when a bundle is built, and bundles are cached
		//     by generation, so with settled evidence nothing ever re-asked. Measured on the lab: both devices
		//     reported holding the incoming authority at the current distribution, and the overlap stayed open
		//     because no code path was going to look again
		//
		// An unchanged announcement is compared as a set and does not advance the serial, so a settled
		// deployment stays silent and this costs one comparison a minute.
		recomputeAnnouncement := func() {
			if transportTrust == nil {
				return
			}
			// Ask, for each organization that is mid-rotation, whether its devices have arrived — this is the
			// step that turns evidence into a closed overlap, and it must happen BEFORE the anchors are read.
			for _, org := range transportTenantCertificates.TenantsWithPendingAuthority() {
				// First: has the FLEET already moved this organization? Then this node is behind, not
				// deciding — see CatchUpWithTheFleet. Without it a restart re-opens an overlap that closed on
				// evidence, because which authority a node serves is rebuilt from disk every boot.
				perTenant.CatchUpWithTheFleet(org, transportTrust.Announced())
				perTenant.PromoteIfAdopted(org)
			}

			// Everything the bundles say that is not the shared anchor set itself: the interception roots this
			// node's own organization is told to look for, and each organization's own transport anchor (roadmap
			// D, S2 — its bundle gains it, so its bundle changed).
			announced := interceptionRootFingerprintsForTenant(config, bundleTenant, bundleTenant)
			announced = append(announced, transportTenantCertificates.AnchorFingerprints()...)
			// ★ And the NAMES. Announcing an anchor without the name that selects the certificate it verifies
			// leaves a device holding half the answer — measured on mac-dev-1, which adopted the anchors and
			// never learned the name because nothing told it the bundle had changed again.
			announced = append(announced, transportTenantCertificates.ServerNameAnnouncements()...)
			// ★ Including the recovery name — and its ABSENCE. Withdrawing a name is the direction that matters
			// here: measured 2026-08-19, the node stopped offering the folded recovery path because the
			// certificate served for that name does not carry it, and every device that had already adopted the
			// bundle went on holding the name. A withdrawal that leaves the serial behind is not a withdrawal,
			// and the devices it strands are the ones whose certificate has expired.
			if sni := offeredRenewalRecoverySNI(config.RenewalRecoverySNI); sni != "" {
				announced = append(announced, "recovery-sni="+sni)
			} else if strings.TrimSpace(config.RenewalRecoverySNI) != "" {
				announced = append(announced, "recovery-sni=withdrawn")
			}
			// ★★★ EVERY FIELD THE PAYLOAD CARRIES, NOT JUST THE ONES THIS BLOCK WAS WRITTEN FOR (2026-08-19).
			// Devices adopt by serial and refuse anything at or below what they hold, so a payload field that
			// can change WITHOUT changing this string is a change no device will ever see. Measured: the
			// recovery endpoint and the agent-policy keyring were both outside it. Add here whatever is added
			// to TrustBundlePayload.
			// ★★★ AND THE WITHDRAWAL OF THE SHARED ANCHOR, WHICH CHANGES A BUNDLE WITHOUT CHANGING ANY TOKEN
			// ABOVE (2026-08-20, measured — the last step of roadmap D slipping through the rule written six
			// lines up).
			//
			// The shared anchor leaves an ORGANIZATION'S bundle when that organization's devices have all
			// adopted its own authority. That decision is made per organization while the bundle is built, and
			// nothing in this string moves: the anchor index is unchanged, the names are unchanged. So the
			// serial stayed at 87 while what a device is handed went from two anchors to one, and the devices
			// already holding 87 will never fetch again — they keep the shared anchor for ever, which is the
			// exact thing this step exists to take away from them.
			//
			// Measured: both devices reported serial 87 with two anchors while this node was serving serial 87
			// with one.
			for tenant := range transportTenantCertificates.anchorsByTenant() {
				// ★ PHASE ONE OF A RETIREMENT: the organization leaves the announcement while the node goes on
				// SERVING it. The promise is withdrawn with a serial, every device is told, and only then is
				// the certificate dropped — see the note on transportTenantCerts.retiring, written after doing
				// it the other way round took the deployment down.
				if transportTenantCertificates.IsRetiring(tenant) {
					continue
				}
				if _, _, withdrawn := perTenant.AnnouncedAnchorsFor(tenant); withdrawn {
					announced = append(announced, tenant+"="+sharedAnchorWithdrawnMarker)
				}
				// ★ The recovery name an organization is told is its own once it has a certificate carrying it,
				// and a device adopts by serial — so a change here has to move it like any other.
				if name, ok := transportTenantCertificates.ServerNameFor(tenant); ok {
					// ★ A SHAPE NEITHER PARSER CLAIMS (2026-08-20, and getting this wrong took region-b down
					// within a minute). The fleet-promise guard reads "tenant@name" as a name this node must
					// serve and "tenant=<64 hex>" as an anchor; a token written as tenant@recovery=... was read
					// as a promise to serve a server name called "recovery=recovery.dsse.invalid", which no
					// node can keep. This carries the same fact and collides with neither.
					announced = append(announced, "recovery-name-for-"+tenant+"="+
						recoveryNameForTenant(config.RenewalRecoverySNI, name))
				}
			}
			announced = append(announced, "recovery-endpoint="+strings.TrimSpace(config.TrustBundleRecoveryEndpoint))
			announced = append(announced, "policy-keys="+strings.Join(config.AgentPolicyNextPublicKeys, "+"))
			// ★ AND A NODE THAT CANNOT SEE THE WHOLE ANSWER DOES NOT GET TO SHRINK IT — see
			// announcement_a_node_may_not_shrink.go, written after two organizations' anchors spent the day
			// flapping in and out of the signed distribution because one node in a shared fleet holds files and
			// the other holds control-plane material.
			announced = announcementKeepingWhatThisNodeCannotSee(announced, transportTrust.Announced(),
				config.TenantTransportMaterialFromCP)
			if _, moved, aerr := transportTrust.AdvanceForAnnouncement(announced, "what these bundles announce"); aerr != nil {
				log.Printf("trust_bundle WARNING the announcement changed and the serial could not be advanced (%v) — "+
					"devices that adopt by serial will keep the previous answer", aerr)
			} else if moved {
				servePEMs, serveSerial = transportTrust.Current()
			}

		}
		recomputeAnnouncement()
		// ★ AND AGAIN WHILE IT RUNS. Once a minute: material refreshes, organizations are onboarded, and the
		// evidence that closes an overlap arrives on the devices' own schedule — none of which used to reach
		// the announcement until a restart. Unchanged is compared as a set and costs nothing.
		go func() {
			for range time.Tick(time.Minute) {
				recomputeAnnouncement()
			}
		}()
		commit, berr := resignBundle(servePEMs, serveSerial)
		if berr != nil {
			log.Fatalf("sign trust bundle: %v", berr)
		}
		commit()
		perTenant.SetTransportMaterial(servePEMs, serveSerial)
		offeredTrustBundle = perTenant.For
		trustBundleInvalidate = perTenant.Invalidate
		// The installer reads the SAME per-organization document a running device would, so an artifact
		// and a fleet can never be looking at two different bundles for one organization.
		installTrustBundleFor = func(tenant string) (any, bool) { return perTenant.For(tenant) }
		mux.HandleFunc("GET /bootstrap/trust-bundle", func(w http.ResponseWriter, r *http.Request) {
			// Whose bundle. A device that can still prove who it is gets its OWN organization's, resolved from
			// the certificate exactly as the steer routes do. One that cannot — the case this endpoint exists
			// for, a device whose certificate has expired — may name its organization explicitly; the contents
			// are public certificates and fingerprints, so serving them to an unauthenticated caller that
			// already knows the name costs nothing. No name and no certificate is the deployment's own answer,
			// which is what every caller received before this change.
			tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
			// ★★★ AND THE NAME IT DIALLED, WHEN IT NAMED NOTHING ELSE (2026-08-20, measured).
			//
			// No agent sends ?tenant= — not macOS, not Windows, and not the shared fetch helper both use. So
			// every device that reached this endpoint for the reason it exists (its certificate has expired, it
			// cannot prove who it is) was handed THE NODE'S organization's bundle. Measured on the lab: a
			// device of tenant_northwind receives tenant_reference_lab's single anchor, and that anchor cannot
			// verify the certificate this Edge presents for northwind.dsse.invalid — openssl says so. It
			// refuses, correctly, and never recovers.
			//
			// The last resort was therefore organization-blind: alive for the node's own organization and dead
			// for every other one. Nothing in a single-organization lab can show that.
			//
			// The server name is the selector everywhere else in this design — it is how an Edge chooses which
			// organization's certificate to present, before any client certificate arrives — and a device in
			// recovery still knows the name it was told. Reading it here costs nothing, discloses nothing a
			// caller did not already name, and makes the answer right for a device that says nothing else.
			if tenant == "" {
				// ★ THE NAME, EITHER WAY IT ARRIVES. A device knows the name it was told — it is in the
				// distribution it adopted and it is what it dials — and it may not know its organization's id
				// at all. So the name is accepted as a query as well as from the handshake: an agent fetching
				// this over an ordinary HTTPS client cannot set a server name for an address it dials, and
				// asking it to would have made the fix impossible on the platform that needs it most.
				if named := tenantForServedName(r, strings.TrimSpace(r.URL.Query().Get("server_name"))); named != "" {
					tenant = named
				}
			}
			if identity, verified := transportDeviceIdentityFromRequest(r); verified && strings.TrimSpace(identity) != "" {
				// ★ ONLY WHEN IT RESOLVED. steerDeviceTenant answers "" for a device this deployment cannot
				// attribute, and writing that over the value the served name already produced would replace a
				// good answer with none — turning a fix into a regression at the one call site whose shape is
				// different from the other five.
				if resolved := steerDeviceTenant(r, config, identity, bundleTenant); strings.TrimSpace(resolved) != "" {
					tenant = resolved
				}
			}
			// ★★ A NAME THIS NODE DOES NOT SERVE IS NOT AN INVITATION TO HAND OVER SOMEBODY ELSE'S (2026-08-21).
			//
			// An unrecognised selector used to fall through to this node's own organization, so a device that
			// asked for northwind.dsse.invalid on a node that did not serve it was handed the LAB's bundle —
			// a document naming an authority that cannot verify the certificate that device will be shown. It
			// refuses, correctly, and never recovers; that is the shape that stranded non-primary organizations
			// earlier. Answering "not here" lets the device try another Edge, which in a uniform fleet is the
			// right next move.
			//
			// (This is also what made the fallback readable as an existence oracle. It is worth saying plainly
			// that closing it does NOT make the deployment's customer list private: the transport port selects
			// each organization's certificate by SNI and presents it BEFORE any client certificate is asked
			// for — measured, CN=northwind.dsse.invalid for that name and the shared certificate for an
			// unknown one. Enumeration is a property of per-organization SNI, not of this route. Making it
			// impossible means unguessable organization names, which is a naming decision, not a bug fix.)
			if asked := strings.TrimSpace(r.URL.Query().Get("tenant")) + strings.TrimSpace(r.URL.Query().Get("server_name")); asked != "" {
				if _, serves := perTenant.For(tenant); !serves || strings.TrimSpace(tenant) == "" {
					writeError(w, http.StatusNotFound, fmt.Errorf("this node does not serve %q — ask another Edge "+
						"rather than take a bundle belonging to a different organization", asked))
					return
				}
			}
			if env, ok := perTenant.For(tenant); ok {
				// ★★ AN ANONYMOUS CALLER NAMING SOMEBODY ELSE'S ORGANIZATION IS RECORDED (2026-08-20).
				//
				// The reasoning above — the contents are public certificates and a caller must already know the
				// name — holds for a device in recovery and does NOT hold for a caller who GUESSES. Measured on
				// the lab: GET /bootstrap/trust-bundle?tenant=tenant_northwind answers with Northwind's bundle,
				// while an unknown name silently falls back to this node's own organization. That is a clean
				// yes/no oracle for "is this company a customer of this deployment", and for an MSSP the
				// customer list is confidential. The transport-facing TLS does not leak it: :8443 presents the
				// same shared certificate for every SNI, measured with three names.
				//
				// Whether to keep the anonymous selector at all is a decision between last-resort recovery for
				// non-primary organizations and customer-list confidentiality, and it belongs to an operator —
				// this path is the one whose ABSENCE stranded those organizations earlier the same day. What
				// does not need a decision is that it happens in silence. Enumeration now leaves a trail.
				if asked := strings.TrimSpace(r.URL.Query().Get("tenant")) + strings.TrimSpace(r.URL.Query().Get("server_name")); asked != "" {
					if identity, verified := transportDeviceIdentityFromRequest(r); !verified || strings.TrimSpace(identity) == "" {
						if !strings.EqualFold(strings.TrimSpace(tenant), strings.TrimSpace(bundleTenant)) {
							log.Printf("bootstrap trust bundle: an UNAUTHENTICATED caller from %s named %q and was served that organization's bundle "+
								"(this node's own organization is %q) — a device in recovery does this legitimately, and so does anyone enumerating customers",
								sourceIPFromRequest(r), tenant, bundleTenant)
						}
					}
				}
				writeJSON(w, http.StatusOK, env)
				return
			}
			writeJSON(w, http.StatusOK, servedBundle.Load())
		})
	}

	mux.HandleFunc("GET /steer/region-endpoints", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		// The LIVE map, not the boot one: a device asking which regions it may fail over to must be told what
		// the control plane says today, not what this node's command line said when it started.
		liveRegions := regionMap.Catalog()
		if liveRegions == nil {
			writeError(w, http.StatusNotFound, fmt.Errorf("geo-steering is not configured (single-region edge)"))
			return
		}
		// The DEVICE's tenant, not this node's — see steerDeviceTenant. Handing an organization the material of
		// whichever organization happens to own the Edge is how a second customer received the first one's
		// enforcement.
		tenantID := steerDeviceTenant(r, config, identity, evaluator.PolicyBundle.TenantID)
		if strings.TrimSpace(tenantID) == "" {
			// See steerDeviceTenant: two authoritative questions, neither answered, and the node's own
			// organization is not a third answer. Refused rather than served somebody else's configuration.
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"this deployment cannot say which organization %q belongs to: its certificate chains to no "+
					"registered Tenant CA and no organization's enrolled inventory holds it. Enrol it, or "+
					"register its organization's Tenant CA on this node", identity))
			return
		}
		var allowed []string
		var home string
		if tenantModelStore != nil {
			if tenant, terr := tenantModelStore.Get(r.Context(), tenantID); terr == nil {
				allowed = tenant.AllowedRegions
				home = tenant.HomeRegion
			}
		}
		payload := map[string]any{
			"schema_version":           "dsse.region-endpoints.v1",
			"tenant_id":                tenantID,
			"device_identity":          identity,
			"home_region":              home,
			"allowed_region_endpoints": liveRegions.allowedRegionEndpoints(allowed, home),
		}
		// ★★★ WHICH NAME TO PRESENT AT WHICHEVER REGION IT LANDS ON (2026-08-22, raised by win-dev-1).
		//
		// This answer gave an agent ADDRESSES and nothing else, so a device failing over had no idea what
		// server name to send. The Windows agent therefore has a rule — region failover beats the announced
		// name — written because a region that lacks the organization's certificate serves the shared one, and
		// a device verifying by the organization's name would lock itself out on arrival. A sensible rule for
		// an agent with no better information, and the consequence is that a device in failover cannot select
		// the folded enrolment or recovery path at all, because those are chosen BY that name.
		//
		// ★ THE NAME DOES NOT CHANGE ON FAILOVER, AND THIS FLEET GUARANTEES IT. A node that cannot serve what
		// the fleet announces refuses to start — refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors, a few
		// hundred lines up, exits the process rather than joining. So every Edge an agent can be steered to
		// serves this organization's name, and the agent does not need a rule: it needs to be told.
		//
		// Stated once, because it is a property of the ORGANIZATION and not of a region. Omitted entirely when
		// this organization has no name of its own, which is the honest answer for a device that should go on
		// dialling without one — never a guess, which is the rule the enrolment fold has paid for twice.
		if serverName, ok := transportTenantCertificates.ServerNameFor(tenantID); ok && strings.TrimSpace(serverName) != "" {
			payload["transport_server_name"] = serverName
			if enrol := organizationEnrolmentName(serverName); enrol != "" {
				if _, _, carried := transportTenantCertificates.For(enrol); carried {
					payload["enrolment_server_name"] = enrol
				}
			}
			if recovery := recoveryNameForTenant(config.RenewalRecoverySNI, serverName); recovery != "" {
				payload["renewal_recovery_server_name"] = recovery
			}
			payload["server_name_note"] = "Present this name at whichever region you are steered to. Every " +
				"Edge in this fleet serves it: a node that cannot keep what the fleet announces refuses to " +
				"start, so failing over does not change which name to send."
		}
		if config.AgentPolicySigner != nil {
			env, serr := config.AgentPolicySigner.Sign(payload, time.Now())
			if serr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("sign region endpoints: %w", serr))
				return
			}
			writeJSON(w, http.StatusOK, env)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})

	// CP-controlled steering posture (Phase 3): the signed sibling of the exclusion + region-endpoints
	// endpoints. The agent fetches this over the (T) mTLS transport and derives its fail-open / region-failover
	// posture from it instead of startup flags. Keyed to the cert-proven device identity; fail-CLOSED default.
	mux.HandleFunc("GET /steer/agent-policy/posture", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		p := config.SteerPosture.normalized()
		payload := map[string]any{
			"schema_version":        agentpolicy.SteeringPostureSchema,
			"tenant_id":             evaluator.PolicyBundle.TenantID,
			"device_identity":       identity,
			"fail_open_mode":        p.FailOpenMode,
			"fail_open_cooldown_ms": p.FailOpenCooldownMS,
			"region_failover":       p.RegionFailover,
			"generated_at":          time.Now().UTC().Format(time.RFC3339),
		}
		// ★★★ WHAT THIS DEPLOYMENT CAN ACTUALLY CARRY, SO AN AGENT DOES NOT STEER INTO WHAT DOES NOT EXIST
		// (2026-08-25, reported from a real endpoint and then decided).
		//
		// An agent captures ALL outbound TCP, IPv6 included — the right default. This deployment's Edges may
		// have no IPv6 leg at all, and then every one of those flows arrives, cannot be egressed, and is
		// closed with no bytes. Measured over seventeen minutes on one box: of 342 IPv6 flows, 185 carried
		// nothing. It survived only because applications fall back to IPv4 and because fail-open was on.
		//
		// Whether a deployment has IPv6 depends on where it runs, which is exactly why the ANSWER has to
		// travel rather than be assumed by either end. The Edge measures it by dialling; the agent captures
		// what the deployment says it can carry, and nothing else.
		//
		// ★ ABSENT MEANS "UNCHANGED", NEVER "NONE". An older Edge, or one that has not finished measuring,
		// sends no families — and an agent reading that as "capture nothing" would stop steering the fleet.
		if fam := egressFamiliesForReport(); fam != nil {
			if r, ok := fam.(*egressFamilyReport); ok {
				families := []string{}
				if r.IPv4 {
					families = append(families, "ipv4")
				}
				if r.IPv6 {
					families = append(families, "ipv6")
				}
				payload["capture_address_families"] = families
				payload["capture_address_families_note"] = "capture only these; this deployment cannot carry " +
					"a family that is not listed, and a flow steered into one it cannot carry is closed with " +
					"no bytes"
			}
		}
		if config.AgentPolicySigner != nil {
			env, serr := config.AgentPolicySigner.Sign(payload, time.Now())
			if serr != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("sign steering posture: %w", serr))
				return
			}
			writeJSON(w, http.StatusOK, env)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})

	// VLAN Boundary Enforcement: define VLAN/Subnet objects + inter-VLAN boundary policies, and
	// export concrete rules for an existing Firewall / L3 / Router (or a Network Enforcement Connector).
}

// tenantForServedName resolves the organization from the TLS server name the caller dialled, when this node
// serves a certificate for it. It trusts nothing: the name is a selector, exactly as it is in the handshake.
func tenantForServedName(r *http.Request, asked string) string {
	name := strings.ToLower(strings.TrimSpace(asked))
	if name == "" {
		if r == nil || r.TLS == nil {
			return ""
		}
		name = strings.ToLower(strings.TrimSpace(r.TLS.ServerName))
	}
	if name == "" {
		return ""
	}
	if _, tenant, ok := transportTenantCertificates.For(name); ok {
		return strings.TrimSpace(tenant)
	}
	return ""
}

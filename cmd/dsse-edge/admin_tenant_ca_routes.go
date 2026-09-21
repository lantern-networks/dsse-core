package main

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Tenant CA administration: the CA that a tenant's device certificates chain to, which is how the transport
// decides WHICH organization a connecting device belongs to.
//
// ★ WHY THESE ROUTES EXIST (2026-08-15). There was no API. The registry was a startup flag pointing at a JSON
// file of PEM paths, read once, so an organization created through the Console had no way to acquire the CA
// that identifies its devices — somebody had to edit a file and restart every Edge. Measured while standing
// up a second tenant on the lab: /admin/tenant-cas answered 404, and that tenant's devices were unadmittable
// by construction. It was the largest of the two remaining blockers on "create a tenant and it works".
//
// A registration has to land in TWO places to mean anything, and this is the only place that knows both:
//
//   - the TRUST set, so the handshake accepts a certificate issued by that CA at all;
//   - the ATTRIBUTION registry, so a verified chain resolves back to the owning tenant.
//
// Half of it is worse than neither: trust without attribution admits a device that belongs to nobody, and
// attribution without trust names a tenant whose devices cannot connect. So a partial result is reported as a
// failure rather than a 200 with a note.
// tenantCARegistryShared is the fleet's backend for the device-CA registry, when the deployment has one.
var tenantCARegistryShared blobstore.Persister

// persistTenantCARegistry makes a registration durable the way this deployment is configured: a shared store
// when there is one (so every Edge in the fleet admits that organization's devices), a file otherwise.
//
// ★★★ IT WAS A FILE ONLY, AND THE ANSWER SAID "this node, immediately" (2026-08-21). The control plane refuses
// to hold this registry at all and the config bundle carries no CA, so a customer registering its device CA
// reached exactly one Edge — and every other node in the fleet, including every one added later under load,
// rejected that organization's devices at the handshake. The reference lab hides it because its Edges
// bind-mount one file; a real deployment does not share a filesystem.
func persistTenantCARegistry(registry *tenantca.TenantCARegistry, registryPath string, removedSHA256 ...string) error {
	if tenantCARegistryShared != nil {
		// The removal is named, because the shared view still holds it and the merge would put it back. See
		// TenantCARegistry.SaveTo.
		return registry.SaveTo(tenantCARegistryShared, removedSHA256...)
	}
	return registry.Save(registryPath)
}

func registerTenantCARoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader,
	registry *tenantca.TenantCARegistry, registryPath string, tenantModelStore adminTenantModelRuntimeStore,
	// Whose devices are still admitted under a CA is a question about the enrolled fleet, so the withdrawal
	// gate needs the same config every other trust decision here is judged against.
	config serverConfig) {

	// ★ AN ORGANIZATION'S OWN DEVICE CA IS ITS OWN TO MANAGE (2026-08-16). These three routes were
	// admin.tenant.admin — operator-only — so the ONE PKI domain that is already shaped correctly (the customer
	// holds the key, the operator only verifies) could not be operated by the customer at all. Every rotation,
	// every added issuing CA, every withdrawal was a support ticket, and a CA rotation nobody can perform is a
	// CA nobody rotates.
	//
	// They are now the either-of pair this tree already uses for acts that are a TENANT act on your own
	// organization and an OPERATOR act on somebody else's: an ordinary admin holds admin.enrollment.*, which is
	// exactly the right scope — a device CA is device admission for your own fleet — and the handler decides
	// which case it is looking at by comparing the target tenant with the caller's.
	mux.HandleFunc("GET /admin/tenant-cas", adminEndpoint("admin.enrollment.read|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if registry == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf(
				"this node has no tenant CA registry configured (-transport-tenant-ca-registry), so it cannot identify devices by tenant"))
			return
		}
		// Scoped, and deliberately WITHOUT a withheld count. On the device screens a withheld count exists so a
		// tenant is never shown a smaller version of ITS OWN fleet. Another organization's CA is not a
		// diminished view of this caller's world — it is not in it — and a count of them is the membership
		// figure this list should not be publishing either.
		// ★ The answer follows the organization the request NAMES, so an operator who has ENTERED one sees that
		// organization's registrations rather than the deployment's — the same rule the PKI, fleet and policy
		// views use (adminAnswerScope). Entering an organization is a mode with a banner attached; a screen
		// that answers for somebody else inside it is how the wrong customer's material gets acted on.
		caller, operator := adminAnswerScope(r)
		counts := registry.Registrations()
		// ★ A COUNT IS NOT AN INVENTORY (2026-08-16). This answered `ca_count: 1` and nothing else — a tenant
		// admin reading its own PKI could not see which certificate identifies its devices, who issued it, or
		// WHEN IT EXPIRES. The lab's second organization holds a 30-day CA: when it lapses, every device of
		// that organization stops being admitted at the handshake, all at once, and the only warning anyone
		// would have had is the outage. The count is kept because screens read it; the facts travel beside it.
		//
		// Public certificate material only. The registry holds no key, by design — that is the whole shape of
		// this trust domain.
		facts := map[string][]tenantca.TenantCAFact{}
		soonest := map[string]int{}
		for _, fact := range registry.Facts(time.Now()) {
			facts[fact.TenantID] = append(facts[fact.TenantID], fact)
			if current, seen := soonest[fact.TenantID]; !seen || fact.DaysLeft < current {
				soonest[fact.TenantID] = fact.DaysLeft
			}
		}
		entries := make([]map[string]any, 0, len(counts))
		for tenantID, n := range counts {
			if !operator && !deviceGroupVisibleToTenant(tenantID, caller) {
				continue
			}
			entries = append(entries, map[string]any{
				"tenant_id": tenantID,
				"ca_count":  n,
				// Each CA described: common name, fingerprint, validity, and how many days are left. Soonest
				// expiry first, so the one about to lapse is the one read first.
				"cas": facts[tenantID],
				// The single number an operator acts on. Negative means it has already lapsed and that
				// organization's devices are not being admitted at all.
				"days_until_first_expiry": soonest[tenantID],
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_cas": entries,
			// Whether a registration made here would survive a restart. An operator has to be able to see that
			// before relying on it, not discover it at the next deploy.
			"durable": tenantCARegistryShared != nil || strings.TrimSpace(registryPath) != "",
			// Where on this node it is stored is the operator's business. A customer needs to know their
			// registration SURVIVES a restart, which is what durable says; the path is deployment plumbing.
			"registry_path": operatorOnlyValue(operator, strings.TrimSpace(registryPath)),
		})
	}))

	mux.HandleFunc("POST /admin/tenant-cas", adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF the device-CA registry (2026-08-23, measured).
		// It travels in the config bundle now, so a write accepted here diverges from the fleet — and it
		// is NOT self-correcting: measured on the lab, a CA registered directly on an Edge was still
		// there three minutes later and only vanished when an UNRELATED change on the control plane moved
		// the bundle's generation. A divergence corrected by coincidence is a divergence.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "device CA registry") {
			return
		}

		if registry == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf(
				"this node has no tenant CA registry configured (-transport-tenant-ca-registry)"))
			return
		}
		var req struct {
			TenantID string `json:"tenant_id"`
			CAPEM    string `json:"ca_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		// ★★ AN ORGANIZATION REGISTERING ITS OWN CA DOES NOT NAME ITSELF (2026-08-17, measured by signing in as
		// the first administrator of a self-run organization — a session that only became possible today). This
		// required tenant_id in the BODY, and the Console sends `operateTenant || ""`: an operator has that set,
		// a customer never does. So the customer's own "Register this organization's device CA" button posted
		// an empty tenant and got 400 "tenant_id and ca_pem are both required" — on the screen whose comment
		// records it as the fix for the ONE blocking item a new organization could not clear.
		//
		// Cleared for the operator, still blocking for the customer, and the failure names a field the person
		// pressing the button never filled in.
		//
		// A write's organization comes from the CALLER (the caller-organization rule): the operator may name another, and for anyone
		// else the answer is their own. The cross-tenant guard below is unchanged and is what keeps naming
		// somebody else's organization an operator act.
		if strings.TrimSpace(req.CAPEM) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("ca_pem is required"))
			return
		}
		tenantID, terr := adminTenantForWrite(r, strings.TrimSpace(req.TenantID))
		// The refusal for a body that names somebody else's organization lives in adminTenantForWrite now: this
		// route wrote its own, and then the same defect turned up on four other routes that had not.
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		if strings.TrimSpace(tenantID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"this request names no organization and none could be resolved from your session"))
			return
		}
		// ★★ SUSPENSION STOPS NEW ADMISSION, AND THIS IS ONE OF THE DOORS (2026-08-19). The decision recorded
		// on adminTenantAdministrativelySuspended is that suspension freezes the administrative plane and stops
		// NEW admission, while enforcement for devices already enrolled continues. Only POST /enroll enforced
		// it. Registering a device CA is admission by a different door: every device holding a certificate from
		// this CA is admitted at the transport handshake from the moment it lands, without touching /enroll at
		// all — so a suspended organization could go on onboarding machines.
		//
		// It matters most for the operator acting under a delegation, which is exactly the case suspension
		// exists for: a billing dispute where the provider should stop adding devices, not stop protecting the
		// ones already there.
		// ★ The same existence question as the token route: a device CA registered against an id nobody runs
		// admits machines into a namespace with no administrator, and survives to meet whoever occupies that
		// id next.
		if reason, gone := adminTenantIsGone(r.Context(), tenantModelStore, tenantID); gone &&
			adminTenantAbsenceIsAuthoritative(config.ConfigSourceURL) {
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%s, so no device authority can be registered for it", reason))
			return
		}
		if reason, refuse := adminTenantAdministrativelySuspended(r.Context(), tenantModelStore, tenantID); refuse {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%s, so no new device authority can be registered for it; enforcement for the devices it "+
					"already has is unaffected", reason))
			return
		}
		// Whose devices this CA would admit. Registering one for ANOTHER organization means every device that
		// CA issues is admitted as that organization's — it is a fleet-sized act on somebody else's tenant, so
		// it needs cross-tenant operator rights. Your own stays open, which is the whole point of the change.
		if err := adminTenantPKITargetAllowed(r, tenantID, "registering the device CA of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// Refuse a CA for an organization that does not exist, for the same reason the invite path does: a CA
		// registered to a tenant nobody created admits devices into an organization no screen can show. The
		// check answers "yes" when it cannot tell (a node that is not the tenant authority), so it never
		// blocks a registration it has no standing to judge.
		if !adminTenantStillExists(r.Context(), tenantModelStore, tenantID) {
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"organization %q does not exist; create it before giving it a CA", tenantID))
			return
		}

		// TRUST first. If the handshake will not accept the certificate, the attribution entry describes a
		// tenant whose devices cannot connect, and that is a worse thing to have written down than nothing.
		// Read at REQUEST time, not captured at registration. ★ It was captured, and the routes are registered
		// ~80 lines before the store is created, so a node that HAD a trust store answered "this node has no
		// runtime device-trust store" — found by trying to register a second tenant's CA on the lab. nil is a
		// valid value for that field, so nothing could have caught it but running it.
		trustStore := trustAnchorStoreOrNil(deviceClientCAs)
		if trustStore == nil {
			// ★★★ UNLESS THIS NODE AUTHORS RATHER THAN ENFORCES (2026-08-23, measured). The rule above is about
			// a node that will be asked to accept the certificate: registering a CA it cannot trust writes down
			// an organization whose devices cannot connect.
			//
			// A CONTROL PLANE is never asked. It does not terminate device transport; the Edges do, and they
			// take both halves — the registry and the trust anchors — from the config bundle it publishes
			// (config_bundle_device_cas.go). Requiring it to hold a device-trust pool of its own made the
			// authority for device CAs conditional on also being an enforcement node, which is the coupling
			// this whole move exists to remove. Measured: POST /admin/tenant-cas answered 501 on the control
			// plane, so the node that is supposed to author the registry was the one node that could not.
			if !edgeIsControlPlane {
				writeError(w, http.StatusNotImplemented, fmt.Errorf(
					"this node has no runtime device-trust store, so a CA registered now would not be trusted at the handshake"))
				return
			}
			logInfof("tenant_ca_registered_without_local_trust tenant=%q note=%q", tenantID,
				"this control plane does not verify device certificates itself; the Edges receive this CA in the "+
					"config bundle and are where it is trusted")
		} else if _, _, err := trustStore.Add(req.CAPEM); err != nil {
			// Already trusted is SUCCESS, not a failure. ★ Found by giving this test the real store instead of a
			// stand-in: the store refuses a duplicate, so re-registering a CA — the ordinary way to attribute one
			// that was already distributed, and the retry any operator makes — failed at the trust step and never
			// reached the attribution it was called for. The fake accepted duplicates and hid it.
			if !strings.Contains(err.Error(), "already distributed") {
				writeError(w, http.StatusBadRequest, fmt.Errorf("this CA was not accepted into the device trust set: %w", err))
				return
			}
		}
		added, err := registry.Register(tenantID, []byte(req.CAPEM))
		if err != nil {
			// The trust half went in. Say so: the operator now has a CA that is trusted and attributed to
			// nobody, which they must be able to see rather than infer from a 400.
			writeError(w, http.StatusConflict, fmt.Errorf(
				"the CA is now TRUSTED by this node but was NOT attributed to a tenant: %w", err))
			return
		}
		durable := true
		if err := persistTenantCARegistry(registry, registryPath); err != nil {
			durable = false
			// Trust and attribution are already live. Preserve that partial state so the same PEM can be
			// retried, but do not report a completed registration before its save is confirmed.
			logInfof("tenant_ca_registered_but_not_durable tenant=%s err=%v", tenantID, err)
		}
		now := time.Now()
		audit := adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenantID}, "tenant_ca_register", evaluator, now)
		fingerprints := []string{}
		for _, cert := range parseAllCerts([]byte(req.CAPEM)) {
			fingerprints = append(fingerprints, tenantca.CAAnchorKey(cert))
		}
		audit.Metadata["ca_sha256"] = fingerprints
		audit.Metadata["durable"] = durable
		if !durable {
			result := "error"
			audit.Result = &result
			audit.Metadata["applied"] = true
			audit.Metadata["persistence"] = "unconfirmed"
			audit.Metadata["reason_codes"] = []string{"tenant_ca_registration_save_failed"}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, now)
		if !durable {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"status": "partial", "applied": true, "tenant_id": tenantID,
				"ca_added": len(added), "trusted": true, "durable": false, "persistence": "unconfirmed",
				"error": "The CA registration is active on this server, but persistence is unconfirmed. Restore storage and retry with the same CA certificate before restarting. Fleet propagation is not confirmed.",
			})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"tenant_id":  tenantID,
			"ca_added":   len(added),
			"trusted":    true,
			"durable":    durable,
			"applies_to": "this node, immediately — no restart",
		})
	}))

	// ★ ONE CA, SO A ROTATION CAN BE FINISHED (2026-08-16). Withdrawing by tenant removes EVERY CA that
	// organization has — the right act for retiring its identity basis, the wrong one for ending a rotation.
	// Both CAs are registered at once while devices are re-issued under the new one; that overlap is the whole
	// method, and closing it used to mean removing both and re-registering the survivor, a window in which the
	// organization's devices were admitted by nothing.
	mux.HandleFunc("DELETE /admin/tenant-cas/{tenant_id}/{sha256}", adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF the device-CA registry (2026-08-23, measured).
		// It travels in the config bundle now, so a write accepted here diverges from the fleet — and it
		// is NOT self-correcting: measured on the lab, a CA registered directly on an Edge was still
		// there three minutes later and only vanished when an UNRELATED change on the control plane moved
		// the bundle's generation. A divergence corrected by coincidence is a divergence.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "device CA registry") {
			return
		}

		if registry == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("this node has no tenant CA registry configured"))
			return
		}
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		fingerprint := strings.TrimSpace(r.PathValue("sha256"))
		if tenantID == "" || fingerprint == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id and sha256 are both required"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, tenantID, "withdrawing a device CA of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// How many this organization would be left with, and whether anybody is still admitted under this one.
		// Counted BEFORE the removal, so the gate judges the state the caller is asking to change.
		remainingAfter, targetExists := 0, false
		for _, fact := range registry.Facts(time.Now()) {
			switch {
			case !strings.EqualFold(fact.TenantID, tenantID):
			case strings.EqualFold(fact.SHA256, fingerprint):
				targetExists = true
			default:
				remainingAfter++
			}
		}
		// Established before anything is removed, because the two halves below must not come apart: taking a
		// CA out of the trust set and then finding it was never attributed here would leave this node refusing
		// certificates on behalf of an organization it has no record of.
		if !targetExists {
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%q is not a CA registered to %q — nothing was withdrawn", fingerprint, tenantID))
			return
		}
		if verdict := deviceCAWithdrawalGate(config, tenantID, fingerprint, remainingAfter); !verdict.Allowed {
			writeError(w, http.StatusConflict, fmt.Errorf("withdrawal refused: %s", verdict.Text))
			return
		}
		// ★ THE WITHDRAWAL WROTE ONE HALF OF WHAT THE REGISTRATION WROTE (2026-08-16, measured live). The
		// handshake verifies against the runtime device-trust store, not against the registry's pool, and only
		// this store's own changes rebuild the pool a handshake reads. So a withdrawal that touched the
		// registry alone removed the ATTRIBUTION and left the ADMISSION — and the answer said, in the same
		// breath, both "devices issued under this CA can no longer be admitted" and "the certificate stays in
		// the device trust set". On the lab, a certificate issued by the just-withdrawn CA completed a (T)
		// handshake and was recorded against the device.
		//
		// ATTRIBUTION FIRST, then trust — and this ordering was itself measured, twice. The live pool is
		// rebuilt as "the registry's pool, cloned, plus this store's certificates", and only a change to the
		// store triggers that rebuild. Removing from the store first therefore rebuilt the pool from a
		// registry that still held the CA, and the withdrawal defeated itself: on the lab, a certificate
		// issued by the CA that had just been withdrawn — by a build containing this very fix, in the wrong
		// order — still completed a (T) handshake and was answered HTTP 200.
		trustStore := trustAnchorStoreOrNil(deviceClientCAs)
		if trustStore == nil {
			// ★★★ UNLESS THIS NODE AUTHORS RATHER THAN ENFORCES (2026-08-23). The rule is right and it is about
			// a node that will be asked to accept the certificate: taking the attribution away while the trust
			// set still holds the CA reports a rotation that did not happen.
			//
			// A CONTROL PLANE is never asked — it terminates no device handshakes. Both halves happen on the
			// Edges, which take the registry AND the trust anchors from the config bundle it publishes, and the
			// apply removes from both (config_bundle_device_cas.go). Requiring a device-trust pool here made
			// the authority for device CAs conditional on also being an enforcement node, which is the same
			// coupling registration had and the same answer.
			if !edgeIsControlPlane {
				writeError(w, http.StatusNotImplemented, fmt.Errorf(
					"this node has no runtime device-trust store, so this CA cannot be stopped from admitting "+
						"devices here; withdrawing the attribution alone would report a rotation that did not happen"))
				return
			}
			logInfof("tenant_ca_withdrawn_without_local_trust tenant=%q note=%q", tenantID,
				"this control plane does not verify device certificates itself; the Edges take this CA out of "+
					"both the registry and the trust set when they apply the next config bundle")
		}
		removed, remaining := registry.WithdrawAnchor(tenantID, fingerprint)
		if !removed {
			// Unreachable via the existence check above, and reported rather than ignored: it would mean the
			// registry changed underneath this request.
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%q is no longer attributed to %q — nothing was withdrawn", fingerprint, tenantID))
			return
		}
		if trustStore == nil {
			// A control plane, handled above: there is no local trust set to take it out of, and the Edges do
			// both halves when the bundle reaches them.
		} else if _, _, err := trustStore.Withdraw(fingerprint); err != nil {
			// Not in the trust set is SUCCESS: the CA was attributed here but distributed elsewhere, and the
			// end state asked for — this node does not admit it — already holds. Anything else is a refusal,
			// and the attribution stays so the operator can see what is still trusted.
			if !strings.Contains(err.Error(), "no distributed certificate has that fingerprint") {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"this CA could not be taken out of the device trust set, so it would keep admitting devices: %w", err))
				return
			}
			// Not in the trust set is not the end of it: the pool a handshake reads folds in the registry, so
			// the removal above is only served once something rebuilds it. Nothing else will.
			if err := trustStore.Reapply(); err != nil {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"this CA is no longer attributed to %q but the trust set a handshake reads could not be "+
						"rebuilt, so it may still admit devices: %w", tenantID, err))
				return
			}
		}
		durable := true
		if err := persistTenantCARegistry(registry, registryPath, fingerprint); err != nil {
			durable = false
			logInfof("tenant_ca_anchor_withdrawn_but_not_durable tenant=%s sha256=%s err=%v", tenantID, fingerprint, err)
		}
		now := time.Now()
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox,
			adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenantID}, "tenant_ca_anchor_withdraw", evaluator, now), now)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":     tenantID,
			"withdrawn":     fingerprint,
			"cas_remaining": remaining,
			"durable":       durable,
			"still_trusted": false,
			"applies_to":    "this node, immediately — no restart. Both halves: the handshake no longer accepts this CA, and it is no longer attributed to this organization.",
			"note":          "Devices whose certificates were issued under this CA can no longer be admitted. The rotation is finished.",
		})
	}))

	mux.HandleFunc("DELETE /admin/tenant-cas/{tenant_id}", adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND AN EDGE THAT PULLS ITS CONFIG IS NOT AN AUTHOR OF the device-CA registry (2026-08-23, measured).
		// It travels in the config bundle now, so a write accepted here diverges from the fleet — and it
		// is NOT self-correcting: measured on the lab, a CA registered directly on an Edge was still
		// there three minutes later and only vanished when an UNRELATED change on the control plane moved
		// the bundle's generation. A divergence corrected by coincidence is a divergence.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "device CA registry") {
			return
		}

		if registry == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("this node has no tenant CA registry configured"))
			return
		}
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required"))
			return
		}
		// Withdrawing your OWN is allowed and is a real thing to want (a rotation ends with the old CA gone).
		// Withdrawing somebody else's would stop admitting their entire fleet, which is why it is not a tenant
		// act — the loudest possible cross-tenant write on this surface.
		if err := adminTenantPKITargetAllowed(r, tenantID, "withdrawing the device CA of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		// Named BEFORE the withdrawal, because afterwards the registry no longer knows them — and the shared
		// view still does, so the merge would put them straight back. See TenantCARegistry.SaveTo.
		gone := []string{}
		for _, f := range registry.Facts(time.Now()) {
			if strings.EqualFold(strings.TrimSpace(f.TenantID), tenantID) {
				gone = append(gone, f.SHA256)
			}
		}
		removed := registry.Withdraw(tenantID)
		durable := true
		if err := persistTenantCARegistry(registry, registryPath, gone...); err != nil {
			durable = false
			logInfof("tenant_ca_withdrawn_but_not_durable tenant=%s err=%v", tenantID, err)
		}
		now := time.Now()
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox,
			adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenantID}, "tenant_ca_withdraw", evaluator, now), now)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":     tenantID,
			"ca_removed":    removed,
			"durable":       durable,
			"still_trusted": "the certificate stays in the device trust set — withdraw it there too if the intent is to stop admitting those devices entirely",
		})
	}))
}

// transportTrustAnchorStore is the runtime device-client-CA store, narrowed to what these routes need. It is
// the store that already makes trust live and durable; these routes reuse it rather than growing a second
// answer to "is this client certificate acceptable", which is how the effective pool diverged from the store
// once already.
type transportTrustAnchorStore interface {
	Add(certPEM string) (*x509.Certificate, int64, error)
	// Withdraw is the other half of Add, and it was missing. Registration writes BOTH halves — the trust set
	// the handshake reads, and the attribution that says whose devices those are — so a withdrawal that wrote
	// only the attribution half left the CA admitting devices it had just been declared to have stopped
	// admitting.
	Withdraw(sha string) (*x509.Certificate, int64, error)
	// Reapply rebuilds the pool a handshake reads from the current sets, without changing either. Needed
	// because that pool folds in the tenant-CA registry, and only a change to THIS store rebuilds it.
	Reapply() error
}

// trustAnchorStoreOrNil converts the concrete device-trust store to the narrowed interface, returning a real
// nil when there is no store. Assigning a nil *transportTrustStore straight into an interface field would
// produce a non-nil interface holding a nil pointer, and the routes' "is there a trust store?" check would
// pass on a node that has none — the CA would be attributed to a tenant and trusted by nobody.
func trustAnchorStoreOrNil(store *transportTrustStore) transportTrustAnchorStore {
	if store == nil {
		return nil
	}
	return store
}

// operatorOnlyValue blanks a deployment detail for a caller scoped to one organization. Used for the sort of
// value that answers "how is this node put together" rather than "what is true for my organization".
func operatorOnlyValue(operator bool, value string) string {
	if operator {
		return value
	}
	return ""
}

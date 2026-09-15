package main

// Policy-learning-mode toggles plus the interception-PKI admin routes — observe-mode
// learning switch, the live raw-forward (pinned-site) host set, per-tenant interception
// roots, and the interception INTERMEDIATE lifecycle (status/rotate/CSR/adopt/upload) —
// moved verbatim out of newServerWithConfig (Phase 2 route-registration split). Takes the
// whole serverConfig because interceptionRootSwitchGate judges the switch against the
// node's full served-material configuration.

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
)

// interceptionScopeForCaller keeps the shape of the signing-scope answer and removes, for a customer, the one
// part of it that is about somebody else: the note names the organization the node-wide intermediate belongs
// to. The counts stay — how many organizations sign under their own root is a fact about the deployment a
// customer is entitled to, and it is what makes the refusal of an unprovisioned tenant explicable.
func interceptionScopeForCaller(scope edgeplane.InterceptionSigningScope, operator bool) edgeplane.InterceptionSigningScope {
	if operator {
		return scope
	}
	// The note reads "<counts>; \"<tenant>\" keeps the node-wide intermediate ...". Keep the half that is
	// about the deployment; a quoted id after a semicolon is the half that names somebody.
	if i := strings.Index(scope.Note, "; \""); i >= 0 {
		scope.Note = scope.Note[:i]
	}
	return scope
}

// interceptionIsNotThisNodesAnswer replaces the sentence eleven routes used to say when this node does not
// serve interception, and it exists because that sentence was TRUE and MISLEADING in the same breath.
//
// ★★★ MEASURED 2026-08-22, and it is the third time this repository has found this shape.
//
//	GET /admin/interception-intermediate
//	  control plane  {"error": "interception is not enabled on this edge"}
//	  edge           {"mode":"own_offline_root","root_common_name":"Lab Tenant Interception Root 2029", ...}
//
// A CONTROL PLANE IS NOT AN EDGE. It holds each organization's interception AUTHORITY and hands out
// short-lived material; it serves no traffic and inspects nothing, so "not enabled on this edge" reads to
// anybody asking as "this organization has no interception" — which is the opposite of true. The same
// correction was made to GET /admin/tenant-install-bundle and then to GET /admin/tenant-transport-authority:
// "that is not mine to say" and "there is none" are different answers, and a route that gives the second when
// it means the first is a route that lies.
//
// Returns true when it has answered and the caller must stop.
func interceptionIsNotThisNodesAnswer(w http.ResponseWriter, config serverConfig, act string) bool {
	if config.NetworkExtensionLabTLS != nil {
		return false
	}
	// Holding organizations' authorities is what a control plane does; serving their traffic is what an Edge
	// does. Saying which of the two this node is turns an unanswerable error into a next step.
	if config.TenantInterceptionAuthority != nil {
		writeError(w, http.StatusConflict, fmt.Errorf(
			"this node holds organizations' interception AUTHORITIES but serves no traffic, so it cannot say "+
				"%s — that is an EDGE's answer, and answering it from here would report every organization as "+
				"having no interception. Ask an Edge; the authority itself is at "+
				"/admin/tenant-interception-authority", act))
		return true
	}
	writeError(w, http.StatusServiceUnavailable, fmt.Errorf(
		"interception is not enabled on this node, so it cannot say %s", act))
	return true
}

func registerInterceptionPKIRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader) {
	mux.HandleFunc("GET /admin/intercept/bypass-hosts", adminEndpoint("admin.swg.read", func(w http.ResponseWriter, r *http.Request) {
		if config.NetworkExtensionLabTLS == nil {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		writeJSON(w, http.StatusOK, config.NetworkExtensionLabTLS.InspectionPatternsForTenant(adminTenantIDFromRequest(r)).Bypass)
	}))
	// Interception-root PKI: the default (anchor) root + any per-tenant roots known this run, so an operator can
	// distribute each tenant's interception root to that tenant's devices. POST provisions a tenant's root (and
	// persists it when -interception-per-tenant-root-dir is set) so it can be distributed BEFORE enabling
	// per-tenant scope. Returns the root certificate PEM (public — safe to surface).
	mux.HandleFunc("GET /admin/interception-roots", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		// ★ THE LIST WAS EVERY TENANT'S (2026-08-16). The POST beside it was closed a day earlier — a customer
		// could mint another customer's interception root — but the read next to it still answered with the
		// whole per-tenant table to any admin holding admin.policy.write's read counterpart. A root certificate
		// is public material, so what leaked is not key material: it is the MEMBERSHIP LIST. Every other
		// organization on this deployment, by tenant id, to any customer who asked.
		//
		// An OPERATOR keeps the fleet view on purpose, and this is the one place that differs from the device
		// screens: distributing each tenant's root to that tenant's devices is an operator act, and it cannot
		// be done from a list that shows one tenant at a time. A device, by contrast, is one customer's and an
		// operator reaches it by selecting that tenant (X-Operate-Tenant).
		caller := adminTenantIDFromRequest(r)
		roots := config.NetworkExtensionLabTLS.ListTenantInterceptionRoots()
		if !adminCallerIsOperator(r) {
			own := roots[:0:0]
			for _, info := range roots {
				if deviceGroupVisibleToTenant(info.Tenant, caller) {
					own = append(own, info)
				}
			}
			roots = own
		}
		// The organizations that actually SIGN under their own root, scoped the same way. This is the answer
		// to "which anchor do my devices need", and it is a different list from the roots above: a root can
		// exist here and sign nothing, which is the state this deployment was in.
		issuers := config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates()
		if !adminCallerIsOperator(r) {
			own := issuers[:0:0]
			for _, row := range issuers {
				if deviceGroupVisibleToTenant(row.Tenant, caller) {
					own = append(own, row)
				}
			}
			issuers = own
		}
		// ★ WHO HAS MOVED, BEFORE ANYONE TRIES TO FINISH THE MOVE (2026-08-16). The withdrawal gate reads the
		// devices' reported pins, but nothing SHOWED them — so the only way to learn the state of a replacement
		// was to attempt the withdrawal and read the refusal. A gate whose inputs are invisible turns every
		// rotation into trial and error, and teaches operators to treat the refusal as an obstacle rather than
		// as an answer.
		//
		// Computed by the SAME function that decides the act, so the screen and the act cannot disagree about
		// who is ready.
		adoption := map[string]any{}
		for _, row := range issuers {
			for _, retiring := range row.Retiring {
				verdict := interceptionRootWithdrawalGate(config, r, row.Tenant, retiring.SHA256)
				adoption[row.Tenant+"/"+retiring.SHA256] = map[string]any{
					"withdrawable": verdict.Allowed,
					// Named, not counted: "some devices are not ready" sends an operator hunting.
					"still_pinned": verdict.StillPinned,
					"not_reported": verdict.Silent,
					"reason":       verdict.Text,
				}
			}
		}
		// ★ WHICH OF THESE ARE INDISTINGUISHABLE IN A TRUST STORE. A machine shows an operator the NAME, and two
		// authorities can share one — this deployment has had that twice, including an outage. Reported from
		// what the node actually holds, because the collision can also come from a customer-supplied root this
		// Edge did not name and cannot rename.
		named := map[string]string{}
		for _, info := range config.NetworkExtensionLabTLS.ListTenantInterceptionRoots() {
			if certs := parseAllCerts([]byte(info.CertPEM)); len(certs) > 0 {
				named[certFingerprint(certs[0])] = certs[0].Subject.CommonName
			}
		}
		for _, row := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
			if certs := parseAllCerts([]byte(row.RootPEM)); len(certs) > 0 {
				named[certFingerprint(certs[0])] = certs[0].Subject.CommonName
			}
			for _, retiring := range row.Retiring {
				if certs := parseAllCerts([]byte(retiring.PEM)); len(certs) > 0 {
					named[certFingerprint(certs[0])] = certs[0].Subject.CommonName
				}
			}
		}
		for _, cert := range parseAllCerts(config.NetworkExtensionLabTLS.RootCertificatePEM()) {
			named[certFingerprint(cert)] = cert.Subject.CommonName
		}
		writeJSON(w, http.StatusOK, map[string]any{
			// Keyed by the shared common name, listing the fingerprints that carry it. Empty is the healthy
			// state; a non-empty entry names certificates an operator cannot tell apart on a machine.
			"indistinguishable_by_name": interceptionRootsIndistinguishableByName(named),
			// The anchor this Edge signs under today. Shown to every caller because it is what their own
			// devices are currently trusting — withholding it would hide from a tenant the root its own fleet
			// is pinned to. Whose root it is, is the subject of per-tenant scope below.
			"default_root_pem":   string(config.NetworkExtensionLabTLS.RootCertificatePEM()),
			"per_tenant":         roots,
			"per_tenant_issuers": issuers,
			// Keyed "<tenant>/<retiring root sha256>". Empty when no replacement is in progress.
			"retiring_root_adoption": adoption,
			// Whether these roots actually SIGN anything. A tenant root that exists but is never used to mint a
			// leaf is the gap this deployment is in the middle of closing (E-13b): provisioning one and reading
			// it back tells you nothing about which CA a device will really see.
			// ★★ THE SCOPE NOTE NAMED ANOTHER CUSTOMER (2026-08-18, read as Acme's own administrator). The lists
			// above were scoped a month earlier because a root list is a MEMBERSHIP list; the sentence beside
			// them was not, and it says: `"tenant_reference_lab" keeps the node-wide intermediate its devices
			// already trust`. The scoping reached the structured fields and stopped at the paragraph.
			"signing_scope": interceptionScopeForCaller(config.NetworkExtensionLabTLS.InterceptionRootScope(),
				adminCallerIsOperator(r)),
		})
	}))
	// ★★★ ANNOUNCE A ROOT BEFORE ANYTHING SIGNS UNDER IT (2026-08-21). An agent reports which of the ANNOUNCED
	// interception roots it found in its own store, so until this route existed there was no way to ask "do
	// this organization's devices have the new root yet?" before switching to it. The first evidence was the
	// traffic that needed it, and switching blind took every site on win-dev-1 down for eighteen minutes.
	//
	// The transport lane has had announce-alongside-then-promote since roadmap D. This is the same act for
	// interception, and the same discipline: announce, MEASURE, switch, withdraw.
	//
	// ★ ANNOUNCING IS NOT TRUSTING. The bundle carries fingerprints; the certificate is distributed out of band
	// on purpose. This says "look for this and tell me whether you have it", nothing more — which is why it is
	// safe to call before the material exists anywhere else.
	mux.HandleFunc("POST /admin/interception-roots/{tenant}/announce", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		target := strings.TrimSpace(r.PathValue("tenant"))
		// "self" resolves to the caller's own organization, like every other {tenant} route here — a tenant
		// administrator must be able to address their own organization without knowing its id.
		resolved, terr := adminResolveTenantPathTarget(r, target)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		target = resolved
		if err := adminTenantPKITargetAllowed(r, target, "announcing an interception root for"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var body struct {
			RootPEM string `json:"root_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode the root to announce: %w", err))
			return
		}
		root, err := config.NetworkExtensionLabTLS.AnnounceTenantInterceptionRoot(target, []byte(body.RootPEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_root_announced.v1",
			"tenant_id":      target,
			"common_name":    root.Subject.CommonName,
			"sha256":         certFingerprint(root),
			"signing":        false,
			"applies_to": "this organization's devices, on their next policy fetch. They look for it in their " +
				"own trust store and report whether they hold it — nothing signs under it until an issuing " +
				"authority beneath it is loaded, so this changes no traffic.",
			"next": "wait until every device of this organization reports this fingerprint, then load the " +
				"issuing authority. Switching before they do breaks every site at once on any device that " +
				"missed it.",
		})
	}))

	mux.HandleFunc("POST /admin/interception-roots/{tenant}", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		// ★ THE PATH TENANT IS NOT THE CALLER'S TENANT, AND NOTHING CHECKED (2026-08-15). This route mints the
		// interception root a tenant's devices are told to trust, and it took the tenant from the URL. It needs
		// admin.policy.write, which every ordinary tenant `admin` holds — so a customer could mint the
		// interception root of ANOTHER customer. Reproduced on the lab: tenant_reference_lab's admin, an
		// ordinary role with no operator rights, provisioned a root for tenant_northwind and got the
		// certificate back.
		//
		// Your own tenant stays open. Another tenant's is an OPERATOR act and requires admin.tenant.admin —
		// the same permission that gates the rest of cross-tenant administration.
		//
		// The check itself now lives in adminTenantPKITargetAllowed, shared with the device-CA registry: as
		// each PKI domain becomes tenant-manageable the same decision is needed in more places, and a second
		// copy of a boundary is where the two answers begin to differ. Extracting it also settled a case this
		// copy got wrong — a deployment with no tenant model at all (empty caller) could not provision any
		// per-tenant root, because "" never equals a tenant name and the single admin there holds no
		// admin.tenant.admin. That caller is the deployment's operator, and the shared predicate says so.
		target := strings.TrimSpace(r.PathValue("tenant"))
		resolved, err := adminResolveTenantPathTarget(r, target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target = resolved
		if err := adminTenantPKITargetAllowed(r, target, "provisioning the interception root of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		info, err := config.NetworkExtensionLabTLS.ProvisionTenantInterceptionRoot(target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	}))
	// ★ RETIRING A PROVISIONED ROOT (2026-08-16). POST above creates one so it can be DISTRIBUTED before
	// per-tenant signing is enabled. Nothing removed them, so a deployment that later went a different way —
	// this one did, to offline per-tenant issuers — keeps certificates that sign nothing, and on the reference
	// lab two of them carried the same common name, which is exactly what an operator cannot resolve from a
	// trust store. Leaving them is not neutral: they may have been handed to a customer.
	//
	// The refusals live in the engine and are the point: a root that IS or WOULD BECOME the signer for that
	// organization is not retired here, because removing it changes what that organization's devices must
	// trust without telling them.
	mux.HandleFunc("DELETE /admin/interception-roots/{tenant}", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		target := strings.TrimSpace(r.PathValue("tenant"))
		resolved, err := adminResolveTenantPathTarget(r, target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target = resolved
		if err := adminTenantPKITargetAllowed(r, target, "retiring the provisioned interception root of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		retired, err := config.NetworkExtensionLabTLS.RetireTenantInterceptionRoot(target)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		if !retired {
			writeError(w, http.StatusNotFound, fmt.Errorf("%q has no provisioned interception root on this node", target))
			return
		}
		// Its devices may be told a different set from now on.
		invalidateTrustBundles()
		recordPKIMaterialChange(writer, r, evaluator, target,
			"interception_tenant_root_retired", "interception_ca", target,
			"A provisioned per-tenant interception root was removed from this node. It was not signing anything; "+
				"any device that was given it now holds a certificate nothing chains to.",
			map[string]any{"tenant": target})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_tenant_root_retired.v1",
			"tenant":         target,
			"retired":        true,
			"note": "It signed nothing, so no traffic changes. A device that was given this certificate keeps " +
				"trusting an authority no leaf chains to — harmless, and worth removing from that machine when " +
				"it is next touched.",
		})
	}))
	// ★ THE EMERGENCY PATH, AND IT IS NOT WITHDRAWAL (2026-08-16). Withdrawal ends a planned replacement and
	// refuses to touch the root currently signing, because telling an organization's devices to stop looking
	// for the certificate their traffic uses is an outage. A leaked key inverts that: the outage is the
	// correct outcome, and signing on with a key somebody else may hold is not.
	//
	// Afterwards that organization is FAIL-CLOSED — no issuer, so its traffic is not intercepted until a
	// replacement is loaded, and deliberately not signed under the deployment's own authority instead. The
	// revoked fingerprints are refused for good, including against a restore of the bundle still on disk.
	mux.HandleFunc("POST /admin/interception-intermediate/{tenant}/revoke", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		target := strings.TrimSpace(r.PathValue("tenant"))
		resolved, err := adminResolveTenantPathTarget(r, target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target = resolved
		if err := adminTenantPKITargetAllowed(r, target, "revoking the interception authority of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode revocation: %w", err))
			return
		}
		revoked, err := config.NetworkExtensionLabTLS.RevokeTenantInterceptionAuthority(target, body.Reason)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// Its devices must stop being told to look for these roots.
		invalidateTrustBundles()
		recordPKIMaterialChange(writer, r, evaluator, target,
			"interception_authority_revoked", "interception_ca", strings.Join(revoked, ","),
			"This organization's interception authority was revoked. Its traffic is NOT being intercepted until a "+
				"replacement issuer is loaded, and these certificates can no longer be loaded on this node.",
			map[string]any{"tenant": target, "revoked_sha256": revoked, "reason": body.Reason})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_authority_revoked.v1",
			"tenant":         target,
			"revoked_sha256": revoked,
			"reason":         strings.TrimSpace(body.Reason),
			"intercepted":    false,
			"note": "That organization is fail-closed: not intercepted, rather than intercepted under an authority " +
				"somebody else may hold. Load a replacement issuer to end that — the revoked certificates stay " +
				"refused, the organization does not.",
		})
	}))
	// Interception INTERMEDIATE lifecycle: status + rotation (the leaked-intermediate response — devices keep
	// trusting the same root, only the exposed signing intermediate changes). Runtime mode regenerates the
	// intermediate from the Edge-held root; offline mode hot-loads a fresh intermediate the OFFLINE root re-issued.
	mux.HandleFunc("GET /admin/interception-intermediate", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		// ★★ AN ANSWER IS ABOUT THE ORGANIZATION THE REQUEST NAMES (2026-08-18). This handler never mentioned a
		// tenant: an operator inside Northwind — which has its own root — was told mode=offline,
		// intermediate_cn="...(tenant_reference_lab)", root_cn="Lantern DSSE MSSP Root CA v2". Every field
		// described a different organization's issuer and the provider's root, and nothing said so. The
		// Console then rendered "this tenant has no interception authority of its own" directly above a card
		// showing that tenant's own root.
		// One rule, in one place — adminAnswerScope, the same one the policy and certificate screens use.
		if tenant, wholeDeployment := adminAnswerScope(r); !wholeDeployment && strings.TrimSpace(tenant) != "" {
			writeJSON(w, http.StatusOK, config.NetworkExtensionLabTLS.InterceptionIntermediateStatusForTenant(tenant))
			return
		}
		status := config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
		// ★ WHICH AUTHORITY ACTUALLY SIGNED, not only which ones are configured. The two answers had been the
		// same screen for so long that "every organization signs under its own root" was being read off a list
		// of loaded issuers — which says nothing about the traffic whose organization never resolved and was
		// therefore signed under the node-wide intermediate, i.e. under one named customer's CA.
		status["signing_counts_since_start"] = edgeplane.InterceptionSigningCounts()
		// ★★ AND WHETHER THE INTERMEDIATE THIS ANSWER LEADS WITH SIGNS ANYTHING AT ALL (2026-08-19). The
		// per-organization answer was corrected on 2026-08-18; this deployment-wide one still opened with
		// intermediate_cn and root_cn and said nothing about whether they are in use. Measured on the
		// reference lab: root_cn read "Lantern DSSE MSSP Root CA v2" while signing_counts_since_start in the
		// SAME body read {own_offline_root: 11} — every leaf signed by an organization's own authority and
		// none by the one the answer names.
		//
		// An operator reading the headline concludes the deployment intercepts under the provider's root.
		// That reading is part of how the two regions came to sign the same organization differently without
		// anyone treating it as urgent. So the answer names the organizations this node-wide intermediate
		// would still sign for; an empty list means it signs for nobody and can be retired, which is the one
		// fact an operator needs here and could not previously get from this screen.
		status["node_wide_intermediate_signs_for"] = tenantsWithoutTheirOwnInterceptionIssuer(config)
		writeJSON(w, http.StatusOK, status)
	}))
	mux.HandleFunc("POST /admin/interception-intermediate/rotate", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		config.NetworkExtensionLabTLS.RotateInterceptionIntermediate()
		status := config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
		// The signer behind every certificate a steered endpoint accepts just changed. Somebody will ask who
		// did that, and until now there was no answer anywhere — not even a log line.
		recordPKIMaterialChange(writer, r, evaluator, adminTenantIDFromRequest(r),
			"interception_intermediate_rotated", "interception_ca", fmt.Sprint(status["root_cn"]),
			"A new issuing intermediate was generated under the same root. Endpoints keep trusting the root, so nothing was re-provisioned.",
			map[string]any{"mode": status["mode"], "root_common_name": status["root_cn"]})
		writeJSON(w, http.StatusOK, status)
	}))
	// Moving interception under a central root WITHOUT exporting the signing key: the Edge asks for a
	// certificate for the key it already holds, and whoever holds the root signs that request offline.
	mux.HandleFunc("POST /admin/interception-intermediate/csr", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CommonName   string `json:"common_name"`
			Organization string `json:"organization"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
			return
		}
		csrPEM, err := edgeplane.InterceptionIntermediateCSR(config.NetworkExtensionLabTLS,
			strings.TrimSpace(body.CommonName), strings.TrimSpace(body.Organization))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfof("interception_intermediate_csr_issued common_name=%q", strings.TrimSpace(body.CommonName))
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_intermediate_csr.v1",
			"csr_pem":        string(csrPEM),
			"note":           "Have the root that endpoints will trust sign this, then POST the certificate to /admin/interception-intermediate/adopt. The signing key stays where it is; only its certificate changes.",
		})
	}))
	// Adopt the signed result: same key, new parent. This CHANGES the anchor endpoints verify against, so it
	// runs behind the reporting gate — an interception root a device does not hold breaks every site on it.
	mux.HandleFunc("POST /admin/interception-intermediate/adopt", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		var body struct {
			RootCertPEM         string `json:"root_cert_pem"`
			IntermediateCertPEM string `json:"intermediate_cert_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode certificates: %w", err))
			return
		}
		if ok, verdict := interceptionRootSwitchGate(config, body.RootCertPEM); !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("interception root switch refused: %s", verdict.Text))
			return
		}
		if err := edgeplane.AdoptReparentedIntermediate(config.NetworkExtensionLabTLS,
			[]byte(body.RootCertPEM), []byte(body.IntermediateCertPEM), config.InterceptionReparentStateDir); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		status := config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
		recordPKIMaterialChange(writer, r, evaluator, adminTenantIDFromRequest(r),
			"interception_root_reparented", "interception_ca", fmt.Sprint(status["root_cn"]),
			"The interception signing key was re-parented under a new root. The key did not move; only its certificate and the anchor endpoints verify against changed.",
			map[string]any{"mode": status["mode"], "root_common_name": status["root_cn"], "key_custody": status["key_custody"]})
		writeJSON(w, http.StatusOK, status)
	}))
	// ★ ONE ORGANIZATION'S OWN INTERCEPTION ISSUER (2026-08-16). This is what makes per-tenant interception
	// real rather than provisioned: the bundle loaded here is an intermediate issued by THAT organization's own
	// offline root, and from then on its devices are shown certificates minted under their own employer's CA.
	//
	// Loading the first one puts the node into per-tenant signing, and that mode is FAIL-CLOSED: an
	// organization without an intermediate of its own is refused rather than signed under somebody else's.
	// That is the sharp edge and it belongs in the response, not in a runbook — so the answer says how many
	// organizations are covered and that the rest are not being intercepted.
	//
	// Either-of, object-scoped, like the rest of the tenant PKI surface: your own organization is a tenant act
	// (its PKI team issued this intermediate from its own root), somebody else's needs operator rights.
	mux.HandleFunc("POST /admin/interception-intermediate/{tenant}", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		target := strings.TrimSpace(r.PathValue("tenant"))
		resolved, err := adminResolveTenantPathTarget(r, target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target = resolved
		// This pattern shares its prefix with the intermediate lifecycle routes. A literal segment beats a
		// wildcard in the mux, so /rotate, /csr and /adopt still reach their own handlers — but an
		// organization named one of those would be silently unreachable here, which is the kind of collision
		// that is found years later by the one customer whose id happens to collide.
		switch strings.ToLower(target) {
		case "rotate", "csr", "adopt":
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"%q is a reserved path segment on this route and cannot be used as an organization id here", target))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "loading the interception issuing CA of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var body struct {
			RootCertPEM         string `json:"root_cert_pem"`
			IntermediateCertPEM string `json:"intermediate_cert_pem"`
			IntermediateKeyPEM  string `json:"intermediate_key_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode intermediate bundle: %w", err))
			return
		}
		// NOTE: deliberately NOT gated by interceptionRootSwitchGate. That gate protects the devices that
		// already trust THIS NODE's anchor from having it replaced underneath them; this route adds a
		// SEPARATE anchor for one organization and changes nothing for anybody else. Reusing the gate here
		// would refuse the first tenant onboarding on the grounds that nobody has adopted a root they have
		// not been given yet — a guard firing on the state it exists to help reach.
		root, err := config.NetworkExtensionLabTLS.LoadOfflineTenantIntermediate(target,
			[]byte(body.RootCertPEM), []byte(body.IntermediateCertPEM), []byte(body.IntermediateKeyPEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// This organization's anchor just changed, so its signed trust bundle — the document that tells its
		// devices which interception root to look for — is stale. Without this the devices would go on
		// reporting against the previous answer until something else happened to move the transport set,
		// which in a deployment that is not rotating is never.
		invalidateTrustBundles()
		covered := config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates()
		durable := false
		for _, row := range covered {
			if strings.EqualFold(row.Tenant, target) {
				durable = row.Durable
			}
		}
		recordPKIMaterialChange(writer, r, evaluator, target,
			"interception_tenant_issuer_loaded", "interception_ca", root.Subject.CommonName,
			"This organization's intercepted traffic is now signed under its OWN root. Its devices must trust that root, and no other organization's traffic can be signed with this key.",
			map[string]any{"tenant": target, "root_common_name": root.Subject.CommonName})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_tenant_issuer.v1",
			"tenant":         target,
			"root_pem":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})),
			// What this organization's devices must trust. Handing back the anchor is the point: an anchor
			// nobody can export is an anchor nobody deploys.
			"root_common_name": root.Subject.CommonName,
			// False means live now and gone at the next restart, which would return this organization to
			// REFUSED. The per-tenant roots shipped in exactly that state once and it was found by restarting.
			"durable": durable,
			// Per-tenant signing is now in force. Everything not in this list is NOT being intercepted.
			"organizations_covered": len(covered),
			"note":                  "Organizations without an intermediate of their own are refused rather than signed under another organization's CA.",
		})
	}))
	// ★ ENDING AN OVERLAP IS ITS OWN ACT (2026-08-16). Replacing an organization's interception authority keeps
	// the previous root ANNOUNCED, so devices pinned to it keep working while they are moved across. That
	// overlap has to be closed deliberately — an authority nobody withdraws is a second CA the organization's
	// devices go on accepting forever, which is the opposite of what replacing it was for.
	//
	// The refusal that matters lives in the engine: the root currently SIGNING cannot be withdrawn. Telling an
	// organization's devices to stop looking for the certificate their own traffic uses is an outage wearing
	// the word "withdraw".
	mux.HandleFunc("DELETE /admin/interception-intermediate/{tenant}/retiring/{sha256}", adminEndpoint("admin.policy.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		target := strings.TrimSpace(r.PathValue("tenant"))
		resolved, err := adminResolveTenantPathTarget(r, target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		target = resolved
		if err := adminTenantPKITargetAllowed(r, target, "withdrawing a retiring interception root of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		fingerprint := strings.TrimSpace(r.PathValue("sha256"))
		// ★ DECIDED ON WHAT DEVICES REPORTED, NOT ON JUDGEMENT (2026-08-16). Withdrawing while devices are
		// still pinned to this root re-creates by hand the flag day the overlap was built to remove. See
		// interceptionRootWithdrawalGate: silence blocks, an organization with no devices is allowed, and a
		// device that cannot report is accounted for by name.
		if verdict := interceptionRootWithdrawalGate(config, r, target, fingerprint); !verdict.Allowed {
			writeError(w, http.StatusConflict, fmt.Errorf("withdrawal refused: %s", verdict.Text))
			return
		}
		removed, err := config.NetworkExtensionLabTLS.WithdrawRetiringTenantRoot(target, fingerprint)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%q is not announced as a retiring root for %q — nothing was withdrawn", fingerprint, target))
			return
		}
		// Its devices are told a smaller set from now on, so the signature they read must be rebuilt.
		invalidateTrustBundles()
		recordPKIMaterialChange(writer, r, evaluator, target,
			"interception_tenant_root_withdrawn", "interception_ca", fingerprint,
			"This organization's devices are no longer told to look for that root. Any device still pinned to it "+
				"will now see a mismatch against what this Edge signs under.",
			map[string]any{"tenant": target, "root_sha256": fingerprint})
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_interception_tenant_retiring.v1",
			"tenant":         target,
			"withdrawn":      fingerprint,
			"note": "Devices still pinned to this root now mismatch. Re-installing them with this organization's " +
				"current configuration is what moves them; the install bundle carries it.",
		})
	}))
	mux.HandleFunc("POST /admin/interception-intermediate", adminEndpoint("admin.platform.write", func(w http.ResponseWriter, r *http.Request) {
		if interceptionIsNotThisNodesAnswer(w, config, "what this organization's traffic is inspected under") {
			return
		}
		var body struct {
			RootCertPEM         string `json:"root_cert_pem"`
			IntermediateCertPEM string `json:"intermediate_cert_pem"`
			IntermediateKeyPEM  string `json:"intermediate_key_pem"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode intermediate bundle: %w", err))
			return
		}
		// Changing the ROOT here changes what every steered endpoint must already trust. Unlike a transport
		// certificate, a device that does not hold it loses every HTTPS site at once — so the same gate the
		// anchor withdrawal uses applies, decided on what devices REPORTED rather than on what was
		// distributed. See docs/interception_root_switch_design.ja.md: the signal was built first precisely
		// so this operation would not be blind.
		if ok, verdict := interceptionRootSwitchGate(config, body.RootCertPEM); !ok {
			writeError(w, http.StatusConflict, fmt.Errorf("interception root switch refused: %s", verdict.Text))
			return
		}
		if err := config.NetworkExtensionLabTLS.ReloadOfflineIntermediate([]byte(body.RootCertPEM), []byte(body.IntermediateCertPEM), []byte(body.IntermediateKeyPEM)); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		status := config.NetworkExtensionLabTLS.InterceptionIntermediateStatus()
		recordPKIMaterialChange(writer, r, evaluator, adminTenantIDFromRequest(r),
			"interception_root_switched", "interception_ca", fmt.Sprint(status["root_cn"]),
			"The root every steered endpoint verifies intercepted traffic against was replaced. Only devices that had already reported holding it were counted.",
			map[string]any{"mode": status["mode"], "root_common_name": status["root_cn"]})
		writeJSON(w, http.StatusOK, status)
	}))
}

// tenantsWithoutTheirOwnInterceptionIssuer names the organizations this node knows about that have no
// interception issuer of their own — the ones the node-wide intermediate would sign for.
//
// Derived from the organizations that have a registered device CA (the ones this node can admit at all) minus
// those with a loaded per-tenant issuer. An organization this node has never heard of is not listed: reporting
// it as covered by the node-wide authority would be inventing a fact about somebody else's deployment.
func tenantsWithoutTheirOwnInterceptionIssuer(config serverConfig) []string {
	if config.NetworkExtensionLabTLS == nil {
		return nil
	}
	own := map[string]bool{}
	for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
		own[strings.ToLower(strings.TrimSpace(issuer.Tenant))] = true
	}
	known := map[string]bool{}
	if reg := config.TenantCARegistry; reg != nil {
		for tenant := range reg.Registrations() {
			known[strings.ToLower(strings.TrimSpace(tenant))] = true
		}
	}
	if t := strings.ToLower(strings.TrimSpace(config.TenantIDForTrust)); t != "" {
		known[t] = true
	}
	out := []string{}
	for tenant := range known {
		if !own[tenant] {
			out = append(out, tenant)
		}
	}
	sort.Strings(out)
	return out
}

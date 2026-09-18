package main

// newAdminEndpointMiddleware builds the admin-plane gate every admin route is registered
// through in newServerWithConfig: authentication (Console session, named API token, or the
// legacy owner bearer), CSRF for session-authenticated mutations, RBAC permission + API-token
// scope checks, the multi-tenant X-Operate-Tenant override audit, and the uniform API-write
// audit. Moved verbatim from newServerWithConfig (Phase 2 stage extraction,
// ); every dependency is set once
// during construction and read-only afterwards.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

func newAdminEndpointMiddleware(evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, adminAuth adminAuthRuntimeStore, adminToken string, devMode bool, tenantModelStore adminTenantModelRuntimeStore,
	hasAdministrators func(context.Context, string) (bool, bool), credentials *localAdminCredentialStore, refusalAudit ...*adminStandbyAudit) func(permission string, handler http.HandlerFunc) http.HandlerFunc {
	refusals := newAdminStandbyAudit(writer, evaluator)
	if len(refusalAudit) > 0 && refusalAudit[0] != nil {
		refusals = refusalAudit[0]
	}
	return func(permission string, handler http.HandlerFunc) http.HandlerFunc {
		recordRefusal := refusals.forPermission(permission)
		return func(w http.ResponseWriter, r *http.Request) {
			// ★★★ BEFORE ANYTHING ELSE: a change written to a node that does not lead is accepted and then
			// discarded. See admin_writes_belong_to_the_leader.go — measured with its control, a device blocked
			// on a standby was still admitted two minutes later while the same block on the leader bit in
			// fifteen seconds. Checked here because this is the one place every administrative route passes
			// through, and a rule enforced anywhere else is a rule with holes in it.
			if adminWriteRefusedOnAStandby(w, permission) {
				recordRefusal()
				return
			}
			identity, ok, err := adminRequestIdentity(r, evaluator.PolicyBundle.TenantID, adminToken, adminAuth, devMode, time.Now())
			if ok && err == nil {
				identity, ok, err = refreshManagedAdminIdentity(r.Context(), adminAuth, credentials, identity)
			}
			if err != nil {
				log.Printf("admin auth store error: %v", err)
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAuthFailureAuditLog("admin_auth_failed", evaluator, sourceIPFromRequest(r), r.UserAgent(), "authentication_store_error"), time.Now())
				writeError(w, http.StatusInternalServerError, fmt.Errorf("admin authentication store is unavailable"))
				return
			}
			if !ok && adminRequestCarriedCredentials(r) && AuthorityWasUnreachable() {
				// ★★★ "I COULD NOT ASK" IS NOT "YOU ARE NOT WHO YOU SAY YOU ARE" (2026-08-25). This node
				// resolves credentials by asking the deployment's authority. While leadership is moving
				// between regions there is a window where it cannot be reached, and answering 401 there sends
				// an operator to look at their token — which is fine — at the exact moment the deployment is
				// failing over. Reported from a real endpoint as "the token dies and comes back".
				log.Printf("admin auth: the authority could not be reached, so this credential was NOT judged")
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf(
					"this node could not reach the deployment's authority, so the credential was not judged "+
						"— leadership may be moving between regions; retry shortly"))
				return
			}
			if !ok {
				// Only audit a REJECTED authentication attempt (credentials presented but invalid). An anonymous
				// pre-login probe (no cookie, no token — the Console checking session state before sign-in) is a
				// normal 401, not a security event; auditing it recorded a spurious "Admin auth failed" on every
				// login (b).
				if adminRequestCarriedCredentials(r) {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAuthFailureAuditLog("admin_auth_failed", evaluator, sourceIPFromRequest(r), r.UserAgent(), "authentication_failed"), time.Now())
				}
				writeError(w, http.StatusUnauthorized, fmt.Errorf("admin authentication is required"))
				return
			}
			if adminMutatingMethod(r.Method) && identity.AuthMethod == "admin_session" && !adminCSRFTokenMatches(r, identity) {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAuthFailureAuditLog("admin_csrf_required", evaluator, sourceIPFromRequest(r), r.UserAgent(), "csrf_token_required"), time.Now())
				writeError(w, http.StatusForbidden, fmt.Errorf("admin csrf token is invalid or absent"))
				return
			}
			// ★ EITHER-OF PERMISSIONS (2026-08-15). A few routes are a TENANT act on your own organization and an
			// OPERATOR act on somebody else's — provisioning an interception root is the measured one. Gating
			// such a route on the tenant permission alone let a customer perform it against another customer;
			// gating it on the operator permission alone takes it away from the tenant whose root it is. The
			// operator does not hold customer-side write permissions by design (that is the open the envelope design envelope
			// question), so "either" is what the route actually needs, and the handler then decides which case
			// it is looking at.
			// ★ A HEADER YOU MAY NOT USE MUST NOT SILENTLY REDIRECT YOUR WRITE (2026-08-16, measured live).
			// X-Operate-Tenant is ignored for callers without admin.tenant.admin, which is right for a READ —
			// you see your own organization and never another's — and wrong for a WRITE, because the act lands
			// somewhere the caller did not name. An API token holding only the tenant admin role sent
			// X-Operate-Tenant: tenant_northwind with POST /admin/admins/invite and got 201, with the
			// administrator seated in its OWN organization. Nothing in the answer contradicted the request.
			//
			// This is the header twin of the caller-organization rule: the same choice carried in the BODY was made a 400 for exactly
			// this reason, and the header form was left behind. Refused here rather than per route, because a
			// rule every write must remember is one that will be forgotten.
			//
			// ★★★ AND THE SAME IS TRUE OF A READ (2026-08-22, measured on the reference fleet). The rule above
			// was written for writes only, on the stated grounds that a read is harmless — "you see your own
			// organization and never another's". That is true about DISCLOSURE and false about the answer: the
			// caller asked about one organization and is handed a different one's numbers under the first one's
			// name, with nothing saying so.
			//
			// Measured: reference-edge-region-b runs without -operator-tenant-id and says so at start-up, so
			// nobody may act across organizations there. GET /admin/enrolled-devices with
			// X-Operate-Tenant: tenant_reference_lab answered HTTP 200 and an EMPTY list — the operator's own
			// organization, which has no devices — while the same request on the other Edge of the same fleet
			// returned three. A refusal drawn as a zero, and this time on the read side.
			//
			// The Console had already met this on ONE screen and worked around it there, by having that
			// route's answer carry answered_for and printing "this answer is about X, not Y". A per-screen
			// workaround for a server-wide rule only covers the routes that happen to report it.
			if requested := strings.TrimSpace(r.Header.Get("X-Operate-Tenant")); requested != "" &&
				!strings.EqualFold(requested, strings.TrimSpace(identity.TenantID)) &&
				!adminIdentityMayActAcrossOrganizations(identity) {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.tenant.admin", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
				would := "carried out in"
				if !adminMutatingMethod(r.Method) {
					would = "answered for"
				}
				home := strings.TrimSpace(identity.TenantID)
				if home == "" {
					home = "no organization"
				}
				writeError(w, http.StatusForbidden, fmt.Errorf(
					"this request names organization %q and you may only act in %q — it would otherwise have been "+
						"%s your own organization, which is not what you asked for", requested, home, would))
				return
			}
			// ★★ WHO, RESOLVED ONCE, BEFORE ANYTHING WRITES A RECORD (2026-08-17, read in a probe
			// organization's own audit trail). The label was being looked up twice, in two places, BOTH of them
			// below — so every row emitted earlier carried the id alone, and the identity handed to the handler
			// carried the id alone too. Measured: four rows about one operator session, of which two named the
			// person and two did not, including the row for the one act that escapes the delegation gate.
			//
			// A customer cannot resolve an operator's id: the directory their console reads holds their OWN
			// administrators. An id-only row names nobody to the only reader it is for.
			//
			// Mutations only — audit rows are written for writes, and a read must not pay for a lookup nothing
			// will use. Failure is silent by design: a record with an id is worse than one with a name, and far
			// better than no record because the directory was briefly unavailable.
			actorEmail, actorDisplayName := "", ""
			if adminMutatingMethod(r.Method) && strings.TrimSpace(identity.PrincipalID) != "" &&
				(identity.AuthMethod == "admin_session" || identity.AuthMethod == "admin_api_token") {
				if p, found, perr := adminAuth.FindPrincipal(r.Context(), identity.PrincipalID, identity.TenantID); perr == nil && found {
					actorEmail = strings.TrimSpace(p.Email)
					if p.DisplayName != nil {
						actorDisplayName = strings.TrimSpace(*p.DisplayName)
					}
					// The label is what a screen prints when it has one line: a name if there is one, the email
					// otherwise. The two stay SEPARATE fields on the record — an audit row whose `email` holds a
					// display name is a row nobody can filter by address.
					if strings.TrimSpace(identity.PrincipalLabel) == "" {
						identity.PrincipalLabel = actorDisplayName
						if identity.PrincipalLabel == "" {
							identity.PrincipalLabel = actorEmail
						}
					}
				}
			}

			// The operator envelope (the envelope design, decided 2026-08-16), read ONCE and used for two independent
			// questions below. An empty target means this is not an operator acting inside another
			// organization, and everything that reads it after this is a no-op.
			envelope := operatorDelegationForRequest(r.Context(), r, identity, tenantModelStore, time.Now())

			// ★ A TENANT-SIDE ACT INSIDE SOMEBODY ELSE'S ORGANIZATION NEEDS THAT ORGANIZATION'S DELEGATION,
			// however the permission check was satisfied. Keying this off "the role check failed" was the
			// first version and it made the delegation decorative for exactly the routes that most needed
			// it: several tenant acts are gated "tenant permission OR operator permission" — a workaround
			// added while the envelope design was still open — so an operator passed on admin.tenant.admin outright and
			// the delegation was never consulted. Measured in the harness: an organization that had
			// delegated NOTHING was written to with a 201.
			//
			// The rule is therefore about the ACT. If any alternative in the gate is a permission an
			// ordinary administrator of that organization holds, this is that organization's business, and
			// the operator needs to have been asked. Operator-side acts (the tenant registry itself, the
			// deployment's PKI, capacity) name no tenant-side permission and are untouched.
			// The single exception to the delegation gate, decided ONCE: the delegation is both the thing that
			// permits a customer-side act and the thing that SUPPLIES the permission for it, so an exception
			// that answered only the first would be refused two checks later. See
			// operatorMaySeatFirstAdministrator for why seating the FIRST administrator of an organization
			// with none is not ordinary work inside somebody's organization.
			seatingFirstAdministrator := envelope.Resolved && operatorDelegationGrants(permission) &&
				!envelope.Delegated && operatorMaySeatFirstAdministrator(r.Context(), r, permission, envelope, hasAdministrators)
			if envelope.Resolved && operatorDelegationGrants(permission) && !envelope.Delegated {
				if seatingFirstAdministrator {
					record := adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent())
					record.EventType = "operator_seated_first_administrator"
					allowed := "success"
					record.Result = &allowed
					record.TenantID = envelope.Target
					record.Metadata["note"] = "the organization had no administrator, so the operator seated its " +
						"first one without a standing delegation; this is the only act that does not need one"
					// ★ AND IT MUST READ AS THE OPERATOR ON THE CUSTOMER'S SCREEN (2026-08-17, read in the probe
					// organization's own audit trail). Built from the denial builder, this row carried the
					// principal id alone — and the directory a customer's console resolves ids against is its OWN
					// administrators, so the one act that escapes the delegation gate rendered as a bare
					// adm_fa6e5d24…. That is the defect adminOperateWithinTenantAuditLog already fixed once; the
					// keys it established are what the console reads, so this row carries the same ones rather
					// than a second name for the same thing.
					stampOperatorActor(record.Metadata, identity)
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, record, time.Now())
				} else {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
					writeError(w, http.StatusForbidden, operatorDelegationRefusal(envelope, permission))
					return
				}
			}
			if !adminPermissionAllowedAny(identity.Roles, permission) {
				// The delegation is also what SUPPLIES the permission: an operator holds none of the
				// customer-side writes in their own right (the customer-write rule), so inside a delegated organization the
				// ceiling is what an administrator of that organization holds — and nothing beyond it, because
				// a customer's signature must not widen what the operator can do to the installation.
				if (!envelope.Delegated || !operatorDelegationGrants(permission)) && !seatingFirstAdministrator {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
					writeError(w, http.StatusForbidden, fmt.Errorf("admin permission %s is required", permission))
					return
				}
			}
			// ★ AND THE ELEVATION IS CHECKED SEPARATELY, NOT AS A FALLBACK. Several destructive routes are
			// gated "tenant permission OR operator permission", so an operator satisfies the check above
			// outright and never reaches the delegated branch. Hanging the elevation off that branch would
			// have left exactly the acts it exists for — revoking an interception authority, withdrawing a
			// device CA — ungated for the one caller it was written to bound.
			if envelope.Resolved && envelope.NeedsElevation && !envelope.Elevated {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
				// ★★ THE REFUSAL USED TO END WITH A curl COMMAND (2026-08-21, read on the Console while
				// finishing a certificate rotation). The screen told an operator to
				// "POST /admin/operator-elevations (X-Operate-Tenant: …)" — an API call, printed on a page,
				// as the way to proceed. That is the same defect the rotation control itself was built to
				// fix one layer up: a control an operator cannot reach is not a control.
				//
				// So the answer now carries the fact in a field a screen can act on. The prose says what is
				// needed and why; the machinery for asking is the screen's job, not the reader's.
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": operatorElevationRefusal(envelope).Error(),
					"elevation_required": map[string]any{
						"tenant_id": envelope.Target,
						"why":       envelope.Why,
					},
				})
				return
			}
			if !adminScopeAllowed(identity, permission) {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
				writeError(w, http.StatusForbidden, fmt.Errorf("admin api token scope %s is required", permission))
				return
			}
			// ★★★ AND A DEPLOYMENT-WIDE ACT IS THE OPERATOR'S, WHICHEVER ROLE HOLDS THE PERMISSION
			// (2026-08-22, measured — see deployment_wide_acts_belong_to_the_operator.go).
			if err := adminDeploymentWideActAllowed(identity, permission); err != nil {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, permission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
				writeError(w, http.StatusForbidden, err)
				return
			}
			// Multi-Tenant Admin Console/: when an operator (admin.tenant.admin) acts within a SELECTED
			// tenant via X-Operate-Tenant, audit the override. We audit MUTATIONS only (POST/PUT/PATCH/DELETE);
			// reads are high-volume and belong to a separate access-log layer, not the admin audit trail. The
			// permission/CSRF gate above is unchanged — the override only re-scopes the tenant, it never widens
			// the operator's roles. Self-targeting overrides (resolved tenant == own tenant) are no-ops.
			if operateTenant, overridden := adminOperateTenant(r, identity); overridden &&
				adminMutatingMethod(r.Method) &&
				strings.TrimSpace(operateTenant) != strings.TrimSpace(identity.TenantID) {
				// ★ NAMED, LIKE THE ROW BESIDE IT (2026-08-17, read in the customer's own audit trail). This is
				// THE row an organization reads to answer "somebody outside my organization was working in
				// it" — and it carried the operator's principal id alone, while the config-change row emitted
				// microseconds later carried their email. The directory a customer's console resolves ids
				// against is its OWN administrators, so the operator's id stayed a bare adm_1e9a9d5698…: one
				// act, two identities, on one screen. The lookup that fixed it has since moved ABOVE the gates,
				// because rows written before this point had the same problem and could not reach it here.
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminOperateWithinTenantAuditLog(identity, operateTenant, r.Method, r.URL.Path, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			}
			// Uniform API-write audit (b): every admin MUTATION leaves a trail — Console session, named API
			// token, or the legacy owner bearer — regardless of whether the handler emits its own domain audit.
			// Reads (GET) are not audited here (high-volume; a separate access layer). Wrap the writer to record
			// the outcome status, and resolve the caller's email/name so the trail says WHO, not an opaque id.
			// Auth endpoints (login/logout/activate) are NOT config changes — they have their own admin_login /
			// admin_logout audit — so skip the config-change row for them (no redundant/mislabeled row).
			if adminMutatingMethod(r.Method) && !adminAuthEndpointPath(r.URL.Path) {
				rec := &adminAuditStatusRecorder{ResponseWriter: w}
				// ★ RESOLVED FROM THE IDENTITY WE ARE HOLDING, NOT READ BACK OUT OF THE REQUEST (2026-08-16).
				// adminTenantIDFromRequest reads the identity from the request CONTEXT, and the identity is not
				// attached until the handler is called a few lines below — so this was empty on every request,
				// the principal lookup underneath it asked for a principal in tenant "", and the uniform
				// API-write audit has never carried the actor's email or display name FOR ANYONE. The existing
				// test passes the email into the builder directly, so it proved the builder and not the lookup.
				//
				// Two different tenants, and conflating them is what hid it: the act is ABOUT the operated
				// tenant, and the principal LIVES IN its own — an operator administering a customer is exactly
				// the case where those differ.
				auditTenant, _ := adminOperateTenant(r, identity)
				// ★ AND FOR API TOKENS TOO (2026-08-16). Only sessions resolved the name, so once the lab's
				// automation moved off the shared break-glass token — the whole point of C-7 — its acts went
				// from naming a synthetic principal to naming an opaque id, and a reader still could not tell
				// who. A token belongs to a principal exactly as a session does; the id is resolvable either
				// way, and "who" is the question the migration exists to answer.
				//
				// Resolved once, above, for every row this request writes rather than separately for this one.
				email, displayName := actorEmail, actorDisplayName
				// ★ RECORDED AS ITSELF (the machine-credential separation). A break-glass act used to land in the ordinary config-change
				// trail, indistinguishable from a named administrator's work except by the synthetic principal
				// id nobody reads. A day of PKI work on the reference lab is in the record as
				// "admin_legacy_token" and answers "who" with nothing. Emitted BEFORE the handler runs, so an
				// act that panics or hangs still leaves the mark.
				if identity.AuthMethod == "legacy_admin_token" {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox,
						adminBreakGlassUseAuditLog(identity, r.Method, r.URL.Path, evaluator, auditTenant,
							sourceIPFromRequest(r), r.UserAgent()), time.Now())
				}
				handler(rec, requestWithAdminIdentity(r, identity))
				// ★ AND THIS ROW TOO, WHEN THE ACTOR IS FROM ANOTHER ORGANIZATION (2026-08-17, read on the
				// customer's own audit screen after the other three were fixed). It named the operator — it has
				// always carried the email — and said nothing about them being an outsider, so it rendered
				// exactly like a row about the organization's own administrator, next to three rows that now
				// say "the operator, on your behalf". Knowing the name must not hide whose act it was.
				//
				// Conditional, because this row is emitted for EVERY mutation by anyone: a customer's own
				// administrator changing their own settings is not an operator act, and badging it would be the
				// same lie pointing the other way.
				configChange := adminConfigChangeAuditLog(identity, email, displayName, r.Method, r.URL.Path, rec.statusOrDefault(), evaluator, auditTenant, sourceIPFromRequest(r), r.UserAgent())
				if strings.TrimSpace(auditTenant) != "" &&
					!strings.EqualFold(strings.TrimSpace(auditTenant), strings.TrimSpace(identity.TenantID)) {
					stampOperatorActor(configChange.Metadata, identity)
				}
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, configChange, time.Now())
				return
			}
			handler(w, requestWithAdminIdentity(r, identity))
		}
	}

}

// adminPermissionAllowedAny accepts a single permission, or several separated by "|" meaning ANY of them.
//
// The separator keeps every existing call site — and the route manifest, and the OpenAPI drift detector —
// reading exactly as before for the routes that need one permission, while the handful that are a tenant act
// on your own organization and an operator act on another can say so in one place instead of doing their own
// authorization behind a permissive gate. A route that looks ungated and checks internally is how an
// authorization hole hides in plain sight.
func adminPermissionAllowedAny(roles []string, permission string) bool {
	for _, candidate := range strings.Split(permission, "|") {
		if candidate = strings.TrimSpace(candidate); candidate != "" && adminPermissionAllowed(roles, candidate) {
			return true
		}
	}
	return false
}

// Existing sessions must observe account suspension, removal and current roles.
// First-party provenance comes from the authenticated principal, never a request field.
// External IdPs and a relying Edge with no local credential authority remain unchanged.
func refreshManagedAdminIdentity(ctx context.Context, auth adminAuthRuntimeStore, credentials *localAdminCredentialStore, identity adminIdentity) (adminIdentity, bool, error) {
	if auth == nil || credentials == nil || (identity.AuthMethod != "admin_session" && identity.AuthMethod != "admin_api_token") {
		return identity, true, nil
	}
	ctx, cancel := context.WithTimeout(ctx, credentialPersistenceTimeout)
	defer cancel()
	principal, found, err := auth.FindPrincipal(ctx, identity.PrincipalID, identity.TenantID)
	if err != nil {
		return adminIdentity{}, false, err
	}
	if !found {
		return adminIdentity{}, false, nil
	}
	if principal.IDPID != "first_party" {
		return identity, true, nil
	}
	credential, exists := credentials.authorityFor(identity.TenantID, identity.PrincipalID)
	if !exists || credential.Status != credentialStatusActive {
		return adminIdentity{}, false, nil
	}
	if identity.AuthMethod == "admin_session" {
		identity.Roles = credential.Roles
	}
	return identity, true, nil
}

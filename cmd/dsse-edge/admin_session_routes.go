package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// First-party admin authentication surface — activation (password/TOTP), login,
// session introspection, logout, the API-only /admin 410, and tokenized export
// downloads. // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerAdminSessionRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, adminAuth adminAuthRuntimeStore, adminDownloadTokens *adminDownloadTokenStore, exportObjectStore adminExportObjectStore, tenantModelStore adminTenantModelRuntimeStore, devMode bool) {
	if config.LocalCredentials != nil {
		firstPartyChallenges := newLoginChallengeStore()

		// Authentication routes bypass the configuration-change middleware. Record each
		// activation attempt independently, including malformed bodies and repeated enrollment.
		activationAudit := func(r *http.Request, w *adminAuditStatusRecorder, event, tenant, target string) {
			if w.statusOrDefault() >= 400 {
				event += "_failed"
			}
			audit := adminLoginAuditLog(event, nil, nil, evaluator, r, "")
			audit.Action = stringPtr("admin_activation")
			audit.TargetType = stringPtr("admin_account")
			if tenant != "" {
				audit.TenantID = tenant
			}
			if target != "" {
				audit.TargetID = stringPtr(target)
			}
			audit.Metadata = map[string]any{"method": r.Method, "path": r.URL.Path,
				"status_code": w.statusOrDefault(), "auth_method": "activation_token"}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, time.Now())
		}

		mux.HandleFunc("GET /admin/activate", func(w http.ResponseWriter, r *http.Request) {
			email, err := config.LocalCredentials.ActivationEmail(r.URL.Query().Get("token"), time.Now())
			if err != nil {
				writeCredentialError(w, http.StatusNotFound, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"email": email})
		})
		// control-plane-only: an Edge does not register the first-party account surface at all (measured: 404)
		mux.HandleFunc("POST /admin/activate/password", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Token       string `json:"token"`
				NewPassword string `json:"new_password"`
			}
			var tenant, target string
			rec := &adminAuditStatusRecorder{ResponseWriter: w}
			w = rec
			defer func() { activationAudit(r, rec, "admin_activation_password_set", tenant, target) }()

			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
				return
			}
			tenant, target = config.LocalCredentials.activationAuditTarget(req.Token, time.Now())
			if err := config.LocalCredentials.SetActivationPassword(req.Token, req.NewPassword, time.Now()); err != nil {
				writeCredentialError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": "password_set"})
		})
		// control-plane-only: an Edge does not register the first-party account surface at all (measured: 404)
		mux.HandleFunc("POST /admin/activate/totp/begin", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Token string `json:"token"`
			}
			var tenant, target string
			rec := &adminAuditStatusRecorder{ResponseWriter: w}
			w = rec
			defer func() { activationAudit(r, rec, "admin_activation_totp_started", tenant, target) }()

			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
				return
			}
			tenant, target = config.LocalCredentials.activationAuditTarget(req.Token, time.Now())
			secret, uri, err := config.LocalCredentials.BeginTOTPEnrollment(req.Token, time.Now())
			if err != nil {
				writeCredentialError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth_uri": uri})
		})
		// control-plane-only: an Edge does not register the first-party account surface at all (measured: 404)
		mux.HandleFunc("POST /admin/activate/totp/complete", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Token string `json:"token"`
				Code  string `json:"code"`
			}
			var tenant, target string
			rec := &adminAuditStatusRecorder{ResponseWriter: w}
			w = rec
			defer func() { activationAudit(r, rec, "admin_account_activated", tenant, target) }()

			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
				return
			}
			tenant, target = config.LocalCredentials.activationAuditTarget(req.Token, time.Now())
			recovery, err := config.LocalCredentials.CompleteActivation(req.Token, req.Code, time.Now())
			if err != nil {
				writeCredentialError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"status": credentialStatusActive, "recovery_codes": recovery})
		})

		// control-plane-only: an Edge does not register sign-in at all (measured: 404) — accounts are the control plane's
		mux.HandleFunc("POST /admin/login/password", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
				return
			}
			cred, err := config.LocalCredentials.VerifyPassword(req.Email, req.Password, time.Now())
			if err != nil {
				if errors.Is(err, errCredentialPersistence) {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", nil, nil, evaluator, r, "credential_storage_unavailable"), time.Now())
					writeCredentialError(w, http.StatusUnauthorized, err)
					return
				}
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", nil, nil, evaluator, r, "password"), time.Now())
				writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"))
				return
			}
			challenge, err := firstPartyChallenges.Issue(cred.Email, time.Now())
			if err != nil {
				writeCredentialError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"challenge_token": challenge, "totp_required": true})
		})
		// control-plane-only: an Edge does not register sign-in at all (measured: 404) — accounts are the control plane's
		mux.HandleFunc("POST /admin/login/totp", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ChallengeToken string `json:"challenge_token"`
				Code           string `json:"code"`
			}
			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
				return
			}
			email, ok := firstPartyChallenges.Consume(req.ChallengeToken, time.Now())
			if !ok {
				writeError(w, http.StatusUnauthorized, fmt.Errorf("login challenge is invalid or expired"))
				return
			}
			cred, err := config.LocalCredentials.VerifyTOTP(email, req.Code, time.Now())
			if err != nil {
				if errors.Is(err, errCredentialPersistence) {
					_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", nil, nil, evaluator, r, "credential_storage_unavailable"), time.Now())
					writeCredentialError(w, http.StatusUnauthorized, err)
					return
				}
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", nil, nil, evaluator, r, "totp"), time.Now())
				writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"))
				return
			}
			// The label this organization already knows this person by, when it knows them — see
			// principalFromCredentialResolved.
			principal := principalFromCredentialResolved(cred, time.Now(), func(tenantID, subject string) (string, bool) {
				if lookup, ok := config.AdminAuth.(interface {
					PrincipalIDForSubject(string, string) (string, bool)
				}); ok {
					return lookup.PrincipalIDForSubject(tenantID, subject)
				}
				return "", false
			})
			if reason, refuse := adminTenantIsGone(r.Context(), tenantModelStore, principal.TenantID); refuse {
				log.Printf("admin login refused for %s: %s", principal.Email, reason)
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", &principal, nil, evaluator, r, "tenant_deleted"), time.Now())
				writeError(w, http.StatusForbidden, fmt.Errorf("this organization is no longer active — contact your operator"))
				return
			}
			if reason, refuse := adminTenantAdministrativelySuspended(r.Context(), tenantModelStore, principal.TenantID); refuse {
				log.Printf("admin login refused for %s: %s", principal.Email, reason)
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_failed", &principal, nil, evaluator, r, "tenant_suspended"), time.Now())
				writeError(w, http.StatusForbidden, fmt.Errorf(
					"this organization is suspended — its devices are still protected, but administrators cannot sign in. Contact your operator"))
				return
			}
			session, err := mintFirstPartyAdminSession(r.Context(), adminAuth, principal, sourceIPFromRequest(r), r.UserAgent(), time.Now())
			if err != nil {
				// ★ THE DATABASE'S WORDS ARE NOT AN ANSWER TO A PERSON SIGNING IN (2026-08-20). A customer
				// administrator met
				//     pq: duplicate key value violates unique constraint "admin_principals_subject_unique_idx"
				// on their own screen, which says nothing they can act on and everything about our schema. The
				// cause is fixed above; this is so the next cause does not arrive the same way.
				log.Printf("admin login could not be completed for %s (%s): %v", principal.Email, principal.TenantID, err)
				writeError(w, http.StatusInternalServerError, fmt.Errorf(
					"your sign-in could not be completed. Nothing about your account was changed — ask your "+
						"operator to look at the sign-in log for %s", principal.Email))
				return
			}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_login_succeeded", &principal, &session, evaluator, r, ""), time.Now())
			http.SetCookie(w, adminSessionCookie(session))
			writeJSON(w, http.StatusCreated, signInAnswer(principal, session, config.AdminConsoleOrigin, r))
		})
	}

	mux.HandleFunc("GET /admin/session", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		roles := adminRolesFromRequest(r)
		payload := map[string]any{
			"tenant_id":    adminTenantIDFromRequest(r),
			"principal_id": adminPrincipalIDFromRequest(r),
			"roles":        roles,
			"permissions":  adminPermissionsForRoles(roles),
			"scopes":       adminScopesFromRequest(r),
			"auth_method":  adminAuthMethodFromRequest(r),
		}
		if identity, ok := adminIdentityFromRequest(r); ok && identity.APITokenID != "" {
			payload["api_token_id"] = identity.APITokenID
		}
		// WHO this principal is, resolved here because this is where the accounts live. An enforcing Edge
		// validating a session has no other route to the name — the front door sends the account listing to the
		// authority too — so a record of who approved a device could otherwise only ever hold an id.
		if label := adminPrincipalLabel(config.LocalCredentials, adminTenantIDFromRequest(r), adminPrincipalIDFromRequest(r)); label != "" {
			payload["principal_label"] = label
		}
		if csrfToken := adminCSRFTokenFromRequest(r); csrfToken != "" {
			payload["csrf_token"] = csrfToken
		}
		// The tenant's own clock, so every surface reads times and computes day boundaries in it. Sent as the
		// IANA NAME and never as an offset: an offset is wrong twice a year wherever daylight saving applies,
		// and "yesterday" must mean the operator's yesterday all year round.
		//
		// The Console converts; the API keeps returning UTC timestamps. Converting server-side would put
		// tenant-local values into responses that also feed exports and comparisons, and audit trails stop
		// being comparable the moment their timestamps live in different zones.
		payload["timezone"] = adminTenantTimezone(r.Context(), tenantModelStore, adminTenantIDFromRequest(r))
		// ★ WHETHER THIS PRINCIPAL IS THE OPERATOR'S OWN. Distinct from holding admin.tenant.admin: a
		// customer's administrator can be given cross-tenant powers on a single-tenant deployment, and an
		// operator is defined by WHICH ORGANIZATION they belong to. The Console needs the distinction to land
		// them on their own screens instead of a customer dashboard full of things they cannot touch — and it
		// cannot derive it, because the operator tenant is deliberately hidden from the customer list.
		if identity, ok := adminIdentityFromRequest(r); ok {
			if tenant, err := tenantModelStore.Get(r.Context(), strings.TrimSpace(identity.TenantID)); err == nil {
				payload["is_operator_tenant"] = tenant.IsOperator
			}
		}
		writeJSON(w, http.StatusOK, payload)
	}))
	mux.HandleFunc("POST /admin/logout", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("admin_session"); err == nil {
			if _, _, err := adminAuth.RevokeSessionForTenant(r.Context(), strings.TrimSpace(cookie.Value), adminTenantIDFromRequest(r), time.Now()); err != nil {
				log.Printf("revoke admin session: %v", err)
			}
		}
		// Attribute the logout to the authenticated caller (resolve the principal for the email), not "System":
		// the wrapper already authenticated this request, so the identity is in context.
		var principal *adminPrincipal
		if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.PrincipalID) != "" {
			if p, found, perr := adminAuth.FindPrincipal(r.Context(), identity.PrincipalID, adminTenantIDFromRequest(r)); perr == nil && found {
				principal = &p
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminLoginAuditLog("admin_logout", principal, nil, evaluator, r, ""), time.Now())
		http.SetCookie(w, expiredAdminSessionCookie())
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
	}))
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		// the Edge is API-only. The Admin Console is a SEPARATE-host application (repo-root
		// console/, served by console-server) that calls this admin API over TLS; the Edge never serves it.
		writeError(w, http.StatusGone, fmt.Errorf("the Admin Console is a separate application; call the admin API (/admin/*) directly over TLS"))
	})
	mux.HandleFunc("GET /admin/export-downloads/{download_token}", func(w http.ResponseWriter, r *http.Request) {
		// ConsumeContext captures the write lease only after a read preflight.
		// Invalid unauthenticated links must not join the CP writer queue.
		token, ok, err := adminDownloadTokens.ConsumeContext(r.Context(), r.PathValue("download_token"), time.Now())
		if err != nil {
			if token.TenantID != "" {
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminDownloadAuditLog("admin_export_download_failed", token, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			}
			log.Printf("export download refused: token spend was not confirmed")
			if errors.Is(err, errDownloadNotLeader) {
				writeError(w, http.StatusConflict, errDownloadNotLeader)
				return
			}
			writeError(w, http.StatusServiceUnavailable, errDownloadStoreUnavailable)
			return
		}
		if !ok {
			// ★★ AND IN A FLEET THIS IS USUALLY NOT AN EXPIRY (2026-08-20, measured on four Edges). The token
			// store is a map in one process and the generated file is on that node's own disk, so a link minted
			// by region-a is 404 on every other Edge: behind a load balancer an export downloads only when the
			// browser lands back on the node that produced it. Live: the same token answered 404 on :9445 and
			// 200 with 2573 bytes on :9443, seconds apart.
			//
			// The sentence used to say "absent or expired", which sends an administrator to export again — and
			// again, at the same odds. The fix for the defect itself is a shared object store plus a durable
			// token store and is a decision about where exports live; until then this at least names what
			// happened, because a misleading error costs more than a missing feature.
			// The fleet-wide reason is gone: outstanding links and their bytes are shared, so a link minted on
			// one Edge downloads from any of them, and a spend on one is a spend on all. What remains are the
			// two honest reasons.
			writeError(w, http.StatusNotFound, fmt.Errorf("this download link has already been used, or it has "+
				"expired — a link is good for one download within fifteen minutes. Generate a new one"))
			return
		}
		// The bytes that travelled with the token, so any Edge in the fleet can serve the link. Falling back to
		// this node's own disk covers a token minted before the payload could be read.
		data := token.Payload
		if len(data) == 0 {
			var err error
			data, err = exportObjectStore.ReadGeneratedFile(token.LocalFilename)
			if err != nil {
				// The spend is already committed, so this is something that took effect:
				// record it. The read error names a server path; keep it in the log and
				// give the anonymous bearer a fixed answer.
				log.Printf("export download failed after the link was spent: generated file unreadable on this node: %v", err)
				_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminDownloadAuditLog("admin_export_download_failed", token, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
				writeError(w, http.StatusNotFound, fmt.Errorf("this download link has been used, but the export file is not available on this server. Generate a new export"))
				return
			}
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminDownloadAuditLog("admin_export_downloaded", token, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
		w.Header().Set("content-type", "application/gzip")
		w.Header().Set("content-disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(token.LocalFilename)))
		w.Header().Set("cache-control", "no-store")
		w.Header().Set("pragma", "no-cache")
		w.Header().Set("referrer-policy", "no-referrer")
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("x-payload-checksum", token.PayloadChecksum)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

// adminTenantIsGone answers whether this principal's organization no longer exists, and why. It is the check
// that turns "the tenant was deleted" into something an account actually feels.
//
// ★ THE MEASURED DEFECT (2026-08-15). Deleting an organization removed its registry row and nothing else.
// Authentication never consulted the tenant registry at all, so its administrators went on logging in
// afterwards, carrying a tenant_id no plane had heard of. Reproduced on the lab: tenant_delprobe2 was deleted
// from the control plane and both Edges, and its administrator authenticated seconds later. Worse, the account
// could not be cleaned up — "cannot delete the last administrator able to manage admins in this tenant" is an
// invariant that outlives the tenant, so deleting the organization LOCKED the orphan in place.
//
// It refuses only when it can actually tell. A store that cannot enumerate, or that enumerates to nothing, is
// a node which is not the tenant authority — the same reading the config bundle gives an empty tenant section.
// Treating "I don't know" as "deleted" would lock every administrator out of a control plane whose registry
// failed to load, which is a far worse failure than the one being fixed.
// adminTenantAbsenceIsAuthoritative reports whether THIS node's registry copy may be used as evidence that an
// organization does not exist.
//
// ★★★ A PULLED COPY CANNOT TESTIFY TO AN ABSENCE (2026-08-19, measured). The control plane keeps the tenant
// registry in shared Postgres; the enforcement Edge is started with a LOCAL FILE
// (-tenant-model-store=/dataplane-ne/tenant_model.json) that nothing distributes to. Suspending an
// organization on the control plane leaves the Edge reading "active", and an organization CREATED there is
// simply not in the Edge's file at all.
//
// So a refusal built on "not in the registry" is correct on the authority and an outage everywhere else: the
// first thing a new organization does is approve a device, and that would be refused by a node that has never
// heard of it. adminTenantIsGone already refuses to testify when the store cannot ENUMERATE; this is the same
// asymmetry one step out — a node that pulls its configuration is not the register.
func adminTenantAbsenceIsAuthoritative(configSourceURL string) bool {
	return strings.TrimSpace(configSourceURL) == ""
}

func adminTenantIsGone(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) (string, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || store == nil {
		return "", false
	}
	adminStore, ok := store.(adminTenantModelAdminStore)
	if !ok {
		return "", false // a narrow store cannot enumerate, so it cannot testify to an absence
	}
	tenants, err := adminStore.List(ctx)
	if err != nil || len(tenants) == 0 {
		return "", false
	}
	for _, tenant := range tenants {
		if strings.EqualFold(strings.TrimSpace(tenant.TenantID), tenantID) {
			return "", false
		}
	}
	return fmt.Sprintf("tenant %q is not in the registry (%d tenant(s) known here)", tenantID, len(tenants)), true
}

// adminTenantStillExists is the inverse of adminTenantIsGone, for the guards that only make sense while the
// organization is around. It answers TRUE whenever it cannot tell, so an unreadable registry never switches a
// protection off — the asymmetry is deliberate and is the opposite default from the login check, because here
// "I don't know" must keep the guard ON.
func adminTenantStillExists(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) bool {
	_, gone := adminTenantIsGone(ctx, store, tenantID)
	return !gone
}

// adminTenantAdministrativelySuspended reports whether this organization's LIFECYCLE STATE refuses
// administrative access, and why.
//
// ★ THE MEASURED DEFECT (2026-08-18). The tenant model validates status as active|suspended|archived, the
// Console offers all three in a dropdown, and the API reference calls it "the tenant lifecycle" — and NOTHING
// read it. Measured on the lab: an organization was set to suspended, its administrator signed in immediately
// afterwards, and the response that served them said "status":"suspended" while doing it. A control an
// operator can set, that changes nothing, is worse than no control: it is a promise the product does not keep.
//
// Deliberately NOT folded into adminTenantIsGone. "Deleted" and "suspended" are different facts, and
// adminTenantStillExists — which guards destructive acts — must keep meaning EXISTS rather than IS USABLE, or
// suspending an organization would quietly re-open the erasure path against it.
//
// Decided 2026-08-18: suspension freezes the ADMINISTRATIVE plane and stops NEW admission. Enforcement for
// devices already enrolled continues, and the data is kept — a billing dispute must not become a security
// incident by taking protection off a customer's laptops.
func adminTenantAdministrativelySuspended(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string) (string, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || store == nil {
		return "", false
	}
	tenant, err := store.Get(ctx, tenantID)
	if err != nil {
		// Unreadable registry does not suspend anybody: the asymmetry matches adminTenantIsGone, where "I don't
		// know" must never invent a refusal an operator did not ask for.
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(tenant.Status)) {
	case "suspended":
		return fmt.Sprintf("organization %q is suspended", tenantID), true
	case "archived":
		return fmt.Sprintf("organization %q is archived", tenantID), true
	}
	return "", false
}

// signInAnswer shapes what a completed sign-in returns.
// ★★★ A BROWSER GETS A REDIRECT AND A COOKIE; A PROGRAM GETS THE SESSION (2026-08-31, found by
// building a deployment from nothing, which is the only thing that would have found it).
//
// This branch withholds the session from the body whenever the deployment names a Console, and it
// is RIGHT to do that for a browser: the cookie is HttpOnly, so page script cannot read the
// session, and an XSS on the Console cannot lift it. But the installer signs in here too — it is
// how `dsse-install -bootstrap-admin` mints the first named administrator — and it reads the
// session out of the body. The moment the control plane was told where its Console is, step 3 of
// this product's own install procedure began failing with:
//
//	dsse-install: the sign-in carried no session
//
// A deployment that names a Console could not be installed. Nothing else changed, and the
// deployment that had been standing for hours went on working, so only a build FROM NOTHING shows
// it.
//
// The discriminator is the request, not a flag: a browser always sends Sec-Fetch-Mode, and sends
// Origin on a cross-origin POST. A command-line client sends neither. So a browser keeps exactly
// what it had — redirect plus HttpOnly cookie, session never in readable script — and a program
// gets what it came for.
func signInAnswer(principal any, session any, consoleOrigin string, r *http.Request) map[string]any {
	answer := map[string]any{"principal": principal}
	if origin := strings.TrimSpace(consoleOrigin); origin != "" {
		answer["redirect"] = origin + "/#signed-in"
	}
	if r.Header.Get("Sec-Fetch-Mode") == "" && r.Header.Get("Origin") == "" {
		answer["session"] = session
	}
	return answer
}

// Storage failures are server failures, not invalid input or a rejected credential.
// Never expose the backing store's error text to the caller.
func writeCredentialError(w http.ResponseWriter, fallback int, err error) {
	if errors.Is(err, errCredentialPersistence) {
		writeError(w, http.StatusServiceUnavailable, errCredentialPersistence)
		return
	}
	writeError(w, fallback, err)
}

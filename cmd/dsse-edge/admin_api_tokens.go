package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"strings"
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

type adminAPIToken struct {
	ID                        string         `json:"id"`
	TenantID                  string         `json:"tenant_id"`
	Name                      string         `json:"name"`
	TokenHash                 string         `json:"token_hash"`
	Roles                     []string       `json:"roles"`
	Scopes                    []string       `json:"scopes"`
	CreatedByAdminPrincipalID string         `json:"created_by_admin_principal_id"`
	CreatedAt                 string         `json:"created_at"`
	ExpiresAt                 string         `json:"expires_at"`
	LastUsedAt                *string        `json:"last_used_at"`
	Status                    string         `json:"status"`
	Metadata                  map[string]any `json:"metadata"`
}

type adminAPITokenResponse struct {
	ID                        string         `json:"id"`
	TenantID                  string         `json:"tenant_id"`
	Name                      string         `json:"name"`
	Roles                     []string       `json:"roles"`
	Scopes                    []string       `json:"scopes"`
	CreatedByAdminPrincipalID string         `json:"created_by_admin_principal_id"`
	CreatedAt                 string         `json:"created_at"`
	ExpiresAt                 string         `json:"expires_at"`
	LastUsedAt                *string        `json:"last_used_at"`
	Status                    string         `json:"status"`
	Metadata                  map[string]any `json:"metadata"`
}

type adminAPITokenCreateRequest struct {
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

type adminAPITokenRotateRequest struct {
	ExpiresAt string `json:"expires_at"`
}

type adminAPITokenCreateResponse struct {
	Token    adminAPITokenResponse `json:"token"`
	RawToken string                `json:"raw_token"`
}

func buildAdminAPIToken(req adminAPITokenCreateRequest, tenantID, createdBy string, now time.Time) (adminAPIToken, string, *adminPrincipal, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return adminAPIToken{}, "", nil, fmt.Errorf("api token name is required")
	}
	expiresAt := strings.TrimSpace(req.ExpiresAt)
	if expiresAt == "" {
		expiresAt = now.UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	}
	parsedExpiresAt, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return adminAPIToken{}, "", nil, fmt.Errorf("parse api token expires_at: %w", err)
	}
	if !parsedExpiresAt.After(now.UTC()) {
		return adminAPIToken{}, "", nil, fmt.Errorf("api token expires_at must be in the future")
	}
	// Refuse what we do not recognise instead of dropping it. Silently issuing a token weaker than the one
	// asked for is how an automation runs for months and then fails at the one moment it matters.
	if unknown := adminUnknownTokenRoles(req.Roles); len(unknown) > 0 {
		return adminAPIToken{}, "", nil, fmt.Errorf(
			"this deployment has no such role: %s (roles: owner, super_admin, admin, analyst, approver, auditor)",
			strings.Join(unknown, ", "))
	}
	roles := normalizedAdminRoles(req.Roles, []string{defaultAdminAPITokenRole})
	if len(roles) == 0 {
		return adminAPIToken{}, "", nil, fmt.Errorf("api token roles are invalid")
	}
	scopes := normalizedStringList(req.Scopes)
	if len(scopes) == 0 {
		scopes = defaultAdminAPITokenScopes(roles)
	}
	if err := validateAdminAPITokenScopes(scopes, roles); err != nil {
		return adminAPIToken{}, "", nil, err
	}
	rawToken, err := newAdminRawToken()
	if err != nil {
		return adminAPIToken{}, "", nil, err
	}
	tokenID, err := newAdminAPITokenID()
	if err != nil {
		return adminAPIToken{}, "", nil, err
	}
	token := adminAPIToken{
		ID:                        tokenID,
		TenantID:                  tenantID,
		Name:                      name,
		TokenHash:                 adminTokenHash(rawToken),
		Roles:                     roles,
		Scopes:                    scopes,
		CreatedByAdminPrincipalID: createdBy,
		CreatedAt:                 now.UTC().Format(time.RFC3339),
		ExpiresAt:                 parsedExpiresAt.UTC().Format(time.RFC3339),
		Status:                    "active",
		Metadata:                  map[string]any{"token_display_prefix": rawTokenPrefix(rawToken)},
	}
	var labPrincipal *adminPrincipal
	if createdBy == "admin_lab_bypass" {
		labPrincipal = &adminPrincipal{
			ID:        "admin_lab_bypass",
			TenantID:  tenantID,
			Subject:   "lab_bypass_admin",
			Email:     "lab-bypass-admin@example.local",
			Roles:     []string{"owner"},
			IDPID:     "local_edge_lab_bypass",
			Status:    "active",
			CreatedAt: now.UTC().Format(time.RFC3339),
			Metadata:  map[string]any{"source": "phase1_lab_bypass"},
		}
	}
	return token, rawToken, labPrincipal, nil
}

func rotateAdminAPIToken(existing adminAPIToken, rotatedBy string, req adminAPITokenRotateRequest, now time.Time) (adminAPIToken, adminAPIToken, string, error) {
	if strings.TrimSpace(existing.ID) == "" || strings.TrimSpace(existing.TenantID) == "" {
		return adminAPIToken{}, adminAPIToken{}, "", fmt.Errorf("admin api token is missing id or tenant_id")
	}
	if existing.Status == "revoked" {
		return adminAPIToken{}, adminAPIToken{}, "", fmt.Errorf("admin api token %s is revoked", existing.ID)
	}
	expiresAt := strings.TrimSpace(req.ExpiresAt)
	if expiresAt == "" {
		expiresAt = now.UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	}
	parsedExpiresAt, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return adminAPIToken{}, adminAPIToken{}, "", fmt.Errorf("parse api token expires_at: %w", err)
	}
	if !parsedExpiresAt.After(now.UTC()) {
		return adminAPIToken{}, adminAPIToken{}, "", fmt.Errorf("api token expires_at must be in the future")
	}
	if err := validateAdminAPITokenScopes(existing.Scopes, existing.Roles); err != nil {
		return adminAPIToken{}, adminAPIToken{}, "", err
	}
	rawToken, err := newAdminRawToken()
	if err != nil {
		return adminAPIToken{}, adminAPIToken{}, "", err
	}
	rotatedID, err := newAdminAPITokenID()
	if err != nil {
		return adminAPIToken{}, adminAPIToken{}, "", err
	}
	rotatedAt := now.UTC().Format(time.RFC3339)
	revoked := existing
	revoked.Status = "revoked"
	if revoked.Metadata == nil {
		revoked.Metadata = map[string]any{}
	}
	revoked.Metadata["revoked_at"] = rotatedAt
	revoked.Metadata["rotated_at"] = rotatedAt
	revoked.Metadata["rotated_by_admin_principal_id"] = rotatedBy
	revoked.Metadata["rotated_to_admin_api_token_id"] = rotatedID
	rotated := adminAPIToken{
		ID:                        rotatedID,
		TenantID:                  existing.TenantID,
		Name:                      existing.Name,
		TokenHash:                 adminTokenHash(rawToken),
		Roles:                     append([]string(nil), existing.Roles...),
		Scopes:                    append([]string(nil), existing.Scopes...),
		CreatedByAdminPrincipalID: rotatedBy,
		CreatedAt:                 rotatedAt,
		ExpiresAt:                 parsedExpiresAt.UTC().Format(time.RFC3339),
		Status:                    "active",
		Metadata: map[string]any{
			"token_display_prefix":            rawTokenPrefix(rawToken),
			"rotated_from_admin_api_token_id": existing.ID,
			"rotated_by_admin_principal_id":   rotatedBy,
		},
	}
	return revoked, rotated, rawToken, nil
}

func defaultAdminAPITokenScopes(roles []string) []string {
	return adminPermissionsForRoles(roles)
}

func validateAdminAPITokenScopes(scopes, roles []string) error {
	allowed := map[string]bool{}
	for _, permission := range adminPermissionsForRoles(roles) {
		allowed[permission] = true
	}
	for _, scope := range scopes {
		if scope == "" {
			continue
		}
		if scope == "*" {
			if allowed["*"] {
				continue
			}
			return fmt.Errorf("api token scope %s is not allowed by roles", scope)
		}
		if allowed["*"] || allowed[scope] {
			continue
		}
		return fmt.Errorf("api token scope %s is not allowed by roles", scope)
	}
	return nil
}

func newAdminAPITokenID() (string, error) {
	return randomEdgeID("admin_token_", time.Now().UTC()), nil
}

func publicAdminAPIToken(token adminAPIToken) adminAPITokenResponse {
	return adminAPITokenResponse{
		ID:                        token.ID,
		TenantID:                  token.TenantID,
		Name:                      token.Name,
		Roles:                     append([]string(nil), token.Roles...),
		Scopes:                    append([]string(nil), token.Scopes...),
		CreatedByAdminPrincipalID: token.CreatedByAdminPrincipalID,
		CreatedAt:                 token.CreatedAt,
		ExpiresAt:                 token.ExpiresAt,
		LastUsedAt:                token.LastUsedAt,
		Status:                    token.Status,
		Metadata:                  copyAnyMap(token.Metadata),
	}
}

func publicAdminAPITokens(tokens []adminAPIToken) []adminAPITokenResponse {
	result := make([]adminAPITokenResponse, 0, len(tokens))
	for _, token := range tokens {
		result = append(result, publicAdminAPIToken(token))
	}
	return result
}

const defaultAdminAPITokenRole = "auditor"

var adminAPITokenAssignableRoles = []string{"admin", "tenant_admin", "analyst", "approver", "auditor", "super_admin"}

func adminAPITokenCreateAuthAllowed(identity adminIdentity) bool {
	return identity.AuthMethod != "admin_api_token"
}

func adminAPITokenRevokeAuthAllowed(identity adminIdentity, tokenID string) bool {
	return adminAPITokenSelfLifecycleAuthAllowed(identity, tokenID)
}

func adminAPITokenRotateAuthAllowed(identity adminIdentity, tokenID string) bool {
	return adminAPITokenSelfLifecycleAuthAllowed(identity, tokenID)
}

func adminAPITokenSelfLifecycleAuthAllowed(identity adminIdentity, tokenID string) bool {
	if identity.AuthMethod != "admin_api_token" {
		return true
	}
	return identity.APITokenID != "" && identity.APITokenID == tokenID
}

// API-token + RBAC-catalog admin routes. // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerAPITokenRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, adminAuth adminAuthRuntimeStore) {
	mux.HandleFunc("GET /admin/api-tokens", adminEndpoint("admin.api_tokens.read", func(w http.ResponseWriter, r *http.Request) {
		tokens, err := adminAuth.ListAPITokensForTenant(r.Context(), adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": publicAdminAPITokens(tokens)})
	}))
	mux.HandleFunc("GET /admin/rbac/catalog", adminEndpoint("admin.api_tokens.read", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, adminRBACCatalog())
	}))
	mux.HandleFunc("POST /admin/api-tokens", adminEndpoint("admin.api_tokens.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AN API TOKEN IS A CREDENTIAL, AND THE CONTROL PLANE IS WHERE IT IS ISSUED (2026-08-24,
		// measured). Asked of both nodes with one administrator session, the Edge answered 0 tokens and the
		// control plane answered 9. Two nodes, two answers, and the Console reads whichever one it is pointed
		// at — so a token minted here would live in this Edge's own store, be invisible to the authority, and
		// vanish when the node did.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "an admin API token") {
			return
		}
		var req adminAPITokenCreateRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode admin api token create request: %w", err))
			return
		}
		identity, _ := adminIdentityFromRequest(r)
		// ★ A CUSTOMER'S OWN ADMINISTRATOR COULD MINT AN OWNER TOKEN (2026-08-16, measured live). This route
		// is gated on admin.api_tokens.write — a permission every tenant `admin` holds, correctly, because
		// minting a token for your own organization is ordinary work. What was missing is any check on WHICH
		// roles the token carries. northwind's own administrator (roles ["admin"], no cross-tenant permission)
		// minted a token with role "owner"; it resolved with permissions ["*"], listed every organization in
		// the deployment, read the deployment's interception PKI, and created an organization.
		//
		// The invite and role-change routes both guard the tenant-admin threshold. The rule here is the
		// stronger one they should probably share: a token may never carry a role its minting principal does
		// not itself hold. A tenant admin minting an analyst token is ordinary; minting anything above
		// themselves is the escalation, and the threshold check would have missed a role that gains platform
		// powers without gaining admin.tenant.admin.
		if escalated := adminRolesBeyondPrincipal(req.Roles, identity.Roles); len(escalated) > 0 {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.api_tokens.create.privilege_escalation", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf(
				"a token cannot be given a role you do not hold yourself: %s", strings.Join(escalated, ", ")))
			return
		}
		if !adminAPITokenCreateAuthAllowed(identity) {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.api_tokens.create.non_token", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("admin api token creation is not allowed from admin api token authentication"))
			return
		}
		token, rawToken, err := adminAuth.CreateAPITokenForTenant(r.Context(), req, adminTenantIDFromRequest(r), adminPrincipalIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAPITokenAuditLog("admin_api_token_created", token, evaluator, sourceIPFromRequest(r)), time.Now())
		writeJSON(w, http.StatusCreated, adminAPITokenCreateResponse{Token: publicAdminAPIToken(token), RawToken: rawToken})
	}))
	mux.HandleFunc("POST /admin/api-tokens/{token_id}/revoke", adminEndpoint("admin.api_tokens.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AN API TOKEN IS A CREDENTIAL, AND THE CONTROL PLANE IS WHERE IT IS ISSUED (2026-08-24,
		// measured). Asked of both nodes with one administrator session, the Edge answered 0 tokens and the
		// control plane answered 9. Two nodes, two answers, and the Console reads whichever one it is pointed
		// at — so a token minted here would live in this Edge's own store, be invisible to the authority, and
		// vanish when the node did.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "an admin API token") {
			return
		}
		tokenID := r.PathValue("token_id")
		identity, _ := adminIdentityFromRequest(r)
		if !adminAPITokenRevokeAuthAllowed(identity, tokenID) {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.api_tokens.revoke.self", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("admin api token revocation is allowed only for the authenticating token"))
			return
		}
		token, ok, err := adminAuth.RevokeAPITokenForTenant(r.Context(), tokenID, adminTenantIDFromRequest(r), time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("admin api token %s is absent", tokenID))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAPITokenAuditLog("admin_api_token_revoked", token, evaluator, sourceIPFromRequest(r)), time.Now())
		writeJSON(w, http.StatusOK, publicAdminAPIToken(token))
	}))
	mux.HandleFunc("POST /admin/api-tokens/{token_id}/rotate", adminEndpoint("admin.api_tokens.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AN API TOKEN IS A CREDENTIAL, AND THE CONTROL PLANE IS WHERE IT IS ISSUED (2026-08-24,
		// measured). Asked of both nodes with one administrator session, the Edge answered 0 tokens and the
		// control plane answered 9. Two nodes, two answers, and the Console reads whichever one it is pointed
		// at — so a token minted here would live in this Edge's own store, be invisible to the authority, and
		// vanish when the node did.
		if configWriteRejectedWhenSourced(w, config.ConfigSourceURL, "an admin API token") {
			return
		}
		var req adminAPITokenRotateRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode admin api token rotate request: %w", err))
			return
		}
		tokenID := r.PathValue("token_id")
		identity, _ := adminIdentityFromRequest(r)
		if !adminAPITokenRotateAuthAllowed(identity, tokenID) {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.api_tokens.rotate.self", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("admin api token rotation is allowed only for the authenticating token"))
			return
		}
		token, rawToken, ok, err := adminAuth.RotateAPITokenForTenant(r.Context(), tokenID, adminTenantIDFromRequest(r), adminPrincipalIDFromRequest(r), req, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("admin api token %s is absent", tokenID))
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAPITokenAuditLog("admin_api_token_rotated", token, evaluator, sourceIPFromRequest(r)), time.Now())
		writeJSON(w, http.StatusCreated, adminAPITokenCreateResponse{Token: publicAdminAPIToken(token), RawToken: rawToken})
	}))
	// Admin SSO / IdP-federated admin login was ABOLISHED (product decision): admin access is first-party only
	// (email + password + TOTP), so admin access never depends on an external IdP — no IdP-outage lockout and no
	// second admin-auth surface to secure. The former /admin/login/discover (home-realm discovery) and
	// /admin/oidc/callback (tenant-SSO + managed-OIDC admin login) handlers were removed. End-user (workforce)
	// IdP federation — /auth/oidc/callback, the SWG authenticate step-up, the console Sign-in Providers — is a
	// separate feature and is unaffected.
	// First-party admin accounts (SaaS-issued): owner invites by email -> single-use activation link -> the
	// user sets a password + enrolls TOTP 2FA -> steady-state login = email + password + TOTP. Coexists with
	// IdP federation; the break-glass admin token still works.
	// Invite is registered unconditionally (RBAC-gated) so the permission gate is always enforced; it returns
	// 503 when first-party accounts are not enabled. The activation/login endpoints below are registered only
	// when the feature is on.
}

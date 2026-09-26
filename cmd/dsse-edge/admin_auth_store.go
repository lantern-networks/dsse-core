package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"sort"
	"strings"
	"sync"
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type adminAuthRuntimeStore interface {
	PersistPrincipal(context.Context, adminPrincipal) error
	PersistSession(context.Context, adminSession) error
	PersistAPIToken(context.Context, adminAPIToken) error
	FindPrincipal(context.Context, string, string) (adminPrincipal, bool, error)
	HasAuthRecords(context.Context, string) (bool, error)
	ListAPITokensForTenant(context.Context, string) ([]adminAPIToken, error)
	CreateAPITokenForTenant(context.Context, adminAPITokenCreateRequest, string, string, time.Time) (adminAPIToken, string, error)
	RevokeAPITokenForTenant(context.Context, string, string, time.Time) (adminAPIToken, bool, error)
	RotateAPITokenForTenant(context.Context, string, string, string, adminAPITokenRotateRequest, time.Time) (adminAPIToken, string, bool, error)
	RevokeSessionForTenant(context.Context, string, string, time.Time) (adminSession, bool, error)
	LookupSessionAdminIdentity(context.Context, string, string, time.Time) (adminIdentity, bool, error)
	LookupAPITokenAdminIdentity(context.Context, string, string, time.Time) (adminIdentity, bool, error)
}

type adminAuthStatsReader interface {
	AdminAuthStats(context.Context, string) (adminAuthStoreStats, error)
}

type adminAuthStoreHealth struct {
	TenantID   string              `json:"tenant_id"`
	Status     string              `json:"status"`
	Mode       string              `json:"mode"`
	Reasons    []string            `json:"reasons"`
	CheckedAt  string              `json:"checked_at"`
	HasRecords bool                `json:"has_records"`
	Stats      adminAuthStoreStats `json:"stats"`
	LastError  string              `json:"last_error,omitempty"`
}

type adminAuthStoreStats struct {
	Principals int `json:"principals"`
	Sessions   int `json:"sessions"`
	APITokens  int `json:"api_tokens"`
	Total      int `json:"total"`
}

func adminAuthStoreHealthFor(ctx context.Context, store adminAuthRuntimeStore, tenantID string, now time.Time) adminAuthStoreHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := adminAuthStoreHealth{
		TenantID:  tenantID,
		Status:    "ok",
		Mode:      adminAuthStoreMode(store),
		Reasons:   []string{},
		CheckedAt: now.UTC().Format(time.RFC3339),
		Stats:     adminAuthStoreStats{},
	}
	if store == nil {
		health.Status = "unconfigured"
		health.Reasons = []string{"auth_store_unconfigured"}
		return health
	}
	stats, err := adminAuthStatsFor(ctx, store, tenantID)
	if err != nil {
		health.Status = "degraded"
		health.Reasons = []string{"auth_store_error"}
		health.LastError = "admin authentication store is unavailable"
		return health
	}
	health.Stats = stats
	health.HasRecords = stats.Total > 0
	return health
}

func adminAuthStatsFor(ctx context.Context, store adminAuthRuntimeStore, tenantID string) (adminAuthStoreStats, error) {
	if reader, ok := store.(adminAuthStatsReader); ok {
		return reader.AdminAuthStats(ctx, tenantID)
	}
	hasRecords, err := store.HasAuthRecords(ctx, tenantID)
	if err != nil {
		return adminAuthStoreStats{}, err
	}
	if hasRecords {
		return adminAuthStoreStats{Total: 1}, nil
	}
	return adminAuthStoreStats{}, nil
}

func adminAuthStoreMode(store adminAuthRuntimeStore) string {
	switch store.(type) {
	case nil:
		return "none"
	case *adminAuthStore:
		return "memory"
	case postgresAdminAuthStore:
		return "postgres"
	default:
		return "custom"
	}
}

type adminAuthStore struct {
	mu         sync.RWMutex
	principals map[string]adminPrincipal
	sessions   map[string]adminSession
	apiTokens  map[string]adminAPIToken
}

type adminPrincipal struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Subject     string         `json:"subject"`
	Email       string         `json:"email"`
	DisplayName *string        `json:"display_name"`
	Roles       []string       `json:"roles"`
	IDPID       string         `json:"idp_id"`
	Status      string         `json:"status"`
	CreatedAt   string         `json:"created_at"`
	LastLoginAt *string        `json:"last_login_at"`
	Metadata    map[string]any `json:"metadata"`
}

type adminSession struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	AdminPrincipalID string         `json:"admin_principal_id"`
	Subject          string         `json:"subject"`
	Roles            []string       `json:"roles"`
	AuthTime         string         `json:"auth_time"`
	MFAState         string         `json:"mfa_state"`
	SourceIP         *string        `json:"source_ip"`
	UserAgent        *string        `json:"user_agent"`
	CreatedAt        string         `json:"created_at"`
	ExpiresAt        string         `json:"expires_at"`
	LastActiveAt     string         `json:"last_active_at"`
	Status           string         `json:"status"`
	Metadata         map[string]any `json:"metadata"`
}

type adminRBACCatalogResponse struct {
	APITokenDefaultRole string                      `json:"api_token_default_role"`
	APITokenRoles       []adminRBACCatalogRoleEntry `json:"api_token_roles"`
}

type adminRBACCatalogRoleEntry struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type adminIdentity struct {
	PrincipalID string
	// PrincipalLabel is who that id belongs to, as the authority reports it. Empty when it cannot be resolved,
	// which is honest — the id is still there.
	PrincipalLabel string
	TenantID       string
	Roles          []string
	Scopes         []string
	AuthMethod     string
	APITokenID     string
	CSRFToken      string
}

type adminIdentityContextKey struct{}

func newAdminAuthStore() *adminAuthStore {
	return &adminAuthStore{
		principals: map[string]adminPrincipal{},
		sessions:   map[string]adminSession{},
		apiTokens:  map[string]adminAPIToken{},
	}
}

func (s *adminAuthStore) UpsertPrincipal(principal adminPrincipal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[principal.ID] = principal
}

// PrincipalIDForSubject answers "does this organization already know this person, and by what id".
//
// ★ THE PERSON IS (ORGANIZATION, IdP, SUBJECT) — the database says so with a unique index on those three, and
// the id is a label chosen once. Sign-in asks this so that a credential whose label drifted (a re-invite used
// to mint a new one) adopts the label already recorded instead of trying to become a second person, which the
// index refuses and the customer sees as a raw database error.
func (s *adminAuthStore) PrincipalIDForSubject(tenantID, subject string) (string, bool) {
	if s == nil {
		return "", false
	}
	want := strings.ToLower(strings.TrimSpace(subject))
	tenant := strings.TrimSpace(tenantID)
	if want == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.principals {
		if !strings.EqualFold(strings.TrimSpace(p.TenantID), tenant) {
			continue
		}
		if strings.ToLower(strings.TrimSpace(p.Subject)) == want {
			return p.ID, true
		}
	}
	return "", false
}

func (s *adminAuthStore) Principal(id, tenantID string) (adminPrincipal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.principals[id]
	if !ok || principal.TenantID != tenantID {
		return adminPrincipal{}, false
	}
	return principal, true
}

func (s *adminAuthStore) UpsertSession(session adminSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

func (s *adminAuthStore) UpsertAPIToken(token adminAPIToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiTokens[token.ID] = token
}

func (s *adminAuthStore) HasRecords(tenantID string) bool {
	stats := s.Stats(tenantID)
	return stats.Total > 0
}

func (s *adminAuthStore) Stats(tenantID string) adminAuthStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := adminAuthStoreStats{}
	for _, principal := range s.principals {
		if principal.TenantID == tenantID {
			stats.Principals++
		}
	}
	for _, session := range s.sessions {
		if session.TenantID == tenantID {
			stats.Sessions++
		}
	}
	for _, token := range s.apiTokens {
		if token.TenantID == tenantID {
			stats.APITokens++
		}
	}
	stats.Total = stats.Principals + stats.Sessions + stats.APITokens
	return stats
}

func (s *adminAuthStore) ListAPITokens(tenantID string) []adminAPIToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens := []adminAPIToken{}
	for _, token := range s.apiTokens {
		if token.TenantID == tenantID {
			tokens = append(tokens, token)
		}
	}
	sort.SliceStable(tokens, func(i, j int) bool {
		return tokens[i].ID < tokens[j].ID
	})
	return tokens
}

func (s *adminAuthStore) CreateAPIToken(req adminAPITokenCreateRequest, tenantID, createdBy string, now time.Time) (adminAPIToken, string, error) {
	token, rawToken, labPrincipal, err := buildAdminAPIToken(req, tenantID, createdBy, now)
	if err != nil {
		return adminAPIToken{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if labPrincipal != nil {
		s.principals[labPrincipal.ID] = *labPrincipal
	}
	s.apiTokens[token.ID] = token
	return token, rawToken, nil
}

func (s *adminAuthStore) RotateAPIToken(id, tenantID, rotatedBy string, req adminAPITokenRotateRequest, now time.Time) (adminAPIToken, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.apiTokens[id]
	if !ok || existing.TenantID != tenantID {
		return adminAPIToken{}, "", false, nil
	}
	revoked, rotated, rawToken, err := rotateAdminAPIToken(existing, rotatedBy, req, now)
	if err != nil {
		return adminAPIToken{}, "", true, err
	}
	s.apiTokens[revoked.ID] = revoked
	s.apiTokens[rotated.ID] = rotated
	return rotated, rawToken, true, nil
}

func (s *adminAuthStore) RevokeAPIToken(id, tenantID string, now time.Time) (adminAPIToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.apiTokens[id]
	if !ok || token.TenantID != tenantID {
		return adminAPIToken{}, false
	}
	token.Status = "revoked"
	revokedAt := now.UTC().Format(time.RFC3339)
	if token.Metadata == nil {
		token.Metadata = map[string]any{}
	}
	token.Metadata["revoked_at"] = revokedAt
	s.apiTokens[id] = token
	return token, true
}

func (s *adminAuthStore) RevokeSession(id, tenantID string, now time.Time) (adminSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || session.TenantID != tenantID {
		return adminSession{}, false
	}
	session.Status = "revoked"
	session.LastActiveAt = now.UTC().Format(time.RFC3339)
	s.sessions[id] = session
	return session, true
}

func (s *adminAuthStore) IdentityForSession(sessionID, tenantID string, now time.Time) (adminIdentity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	// An empty tenantID resolves the session's OWN tenant; see the Postgres twin for why the filter had to go.
	if !ok || (tenantID != "" && session.TenantID != tenantID) || session.Status != "active" {
		return adminIdentity{}, false
	}
	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || !now.UTC().Before(expiresAt) {
		return adminIdentity{}, false
	}
	principal, ok := s.principals[session.AdminPrincipalID]
	if !ok || principal.Status != "active" {
		return adminIdentity{}, false
	}
	session.LastActiveAt = now.UTC().Format(time.RFC3339)
	s.sessions[sessionID] = session
	return adminIdentity{
		PrincipalID: session.AdminPrincipalID,
		TenantID:    session.TenantID,
		Roles:       append([]string(nil), session.Roles...),
		AuthMethod:  "admin_session",
		CSRFToken:   stringMetadata(session.Metadata, adminCSRFTokenKey),
	}, true
}

func (s *adminAuthStore) IdentityForAPIToken(rawToken, tenantID string, now time.Time) (adminIdentity, bool) {
	tokenHash := adminTokenHash(rawToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	// An empty tenantID means "resolve the TOKEN's own tenant" — see
	// buildPostgresAdminAPITokenIdentityStatement for why the mandatory filter was a defect rather than a
	// control. Kept identical here so the in-memory and Postgres stores cannot answer authentication
	// differently, which is how a lab passes what production refuses.
	tenantID = strings.TrimSpace(tenantID)
	for id, token := range s.apiTokens {
		if (tenantID != "" && token.TenantID != tenantID) || token.Status != "active" || token.TokenHash == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(token.TokenHash), []byte(tokenHash)) != 1 {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, token.ExpiresAt)
		if err != nil || !now.UTC().Before(expiresAt) {
			if err == nil {
				token.Status = "expired"
				s.apiTokens[id] = token
			}
			continue
		}
		principal, ok := s.principals[token.CreatedByAdminPrincipalID]
		if !ok || principal.Status != "active" {
			continue
		}
		lastUsedAt := now.UTC().Format(time.RFC3339)
		token.LastUsedAt = &lastUsedAt
		s.apiTokens[id] = token
		return adminIdentity{
			PrincipalID: token.CreatedByAdminPrincipalID,
			TenantID:    token.TenantID,
			Roles:       append([]string(nil), token.Roles...),
			Scopes:      append([]string(nil), token.Scopes...),
			AuthMethod:  "admin_api_token",
			APITokenID:  token.ID,
		}, true
	}
	return adminIdentity{}, false
}

func (s *adminAuthStore) PersistPrincipal(_ context.Context, principal adminPrincipal) error {
	s.UpsertPrincipal(principal)
	return nil
}

func (s *adminAuthStore) PersistSession(_ context.Context, session adminSession) error {
	s.UpsertSession(session)
	return nil
}

func (s *adminAuthStore) PersistAPIToken(_ context.Context, token adminAPIToken) error {
	s.UpsertAPIToken(token)
	return nil
}

func (s *adminAuthStore) FindPrincipal(_ context.Context, id, tenantID string) (adminPrincipal, bool, error) {
	principal, ok := s.Principal(id, tenantID)
	return principal, ok, nil
}

func (s *adminAuthStore) HasAuthRecords(_ context.Context, tenantID string) (bool, error) {
	return s.HasRecords(tenantID), nil
}

func (s *adminAuthStore) AdminAuthStats(_ context.Context, tenantID string) (adminAuthStoreStats, error) {
	return s.Stats(tenantID), nil
}

func (s *adminAuthStore) ListAPITokensForTenant(_ context.Context, tenantID string) ([]adminAPIToken, error) {
	return s.ListAPITokens(tenantID), nil
}

func (s *adminAuthStore) CreateAPITokenForTenant(_ context.Context, req adminAPITokenCreateRequest, tenantID, createdBy string, now time.Time) (adminAPIToken, string, error) {
	return s.CreateAPIToken(req, tenantID, createdBy, now)
}

func (s *adminAuthStore) RevokeAPITokenForTenant(_ context.Context, id, tenantID string, now time.Time) (adminAPIToken, bool, error) {
	token, ok := s.RevokeAPIToken(id, tenantID, now)
	return token, ok, nil
}

func (s *adminAuthStore) RotateAPITokenForTenant(_ context.Context, id, tenantID, rotatedBy string, req adminAPITokenRotateRequest, now time.Time) (adminAPIToken, string, bool, error) {
	return s.RotateAPIToken(id, tenantID, rotatedBy, req, now)
}

func (s *adminAuthStore) RevokeSessionForTenant(_ context.Context, id, tenantID string, now time.Time) (adminSession, bool, error) {
	session, ok := s.RevokeSession(id, tenantID, now)
	return session, ok, nil
}

// RevokeAllForTenant revokes every live session and API token a tenant holds, and reports the counts.
//
// ★ WHY (2026-08-15). Refusing a LOGIN once a tenant is deleted leaves whoever was already signed in working
// for the rest of the session's eight hours, and an API token working until someone remembers it. A tenant
// that has been deleted has to stop being usable now, not eventually. Sessions and tokens are marked revoked
// rather than dropped, so the record of what existed survives the deletion.
func (s *adminAuthStore) RevokeAllForTenant(_ context.Context, tenantID string, now time.Time) (sessions int, tokens int, err error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := now.UTC().Format(time.RFC3339)
	for id, session := range s.sessions {
		if !strings.EqualFold(strings.TrimSpace(session.TenantID), tenantID) || session.Status == "revoked" {
			continue
		}
		session.Status = "revoked"
		session.LastActiveAt = stamp
		s.sessions[id] = session
		sessions++
	}
	for id, token := range s.apiTokens {
		if !strings.EqualFold(strings.TrimSpace(token.TenantID), tenantID) || token.Status == "revoked" {
			continue
		}
		token.Status = "revoked"
		if token.Metadata == nil {
			token.Metadata = map[string]any{}
		}
		token.Metadata["revoked_at"] = stamp
		s.apiTokens[id] = token
		tokens++
	}
	return sessions, tokens, nil
}

func (s *adminAuthStore) LookupSessionAdminIdentity(_ context.Context, sessionID, tenantID string, now time.Time) (adminIdentity, bool, error) {
	identity, ok := s.IdentityForSession(sessionID, tenantID, now)
	return identity, ok, nil
}

func (s *adminAuthStore) LookupAPITokenAdminIdentity(_ context.Context, rawToken, tenantID string, now time.Time) (adminIdentity, bool, error) {
	identity, ok := s.IdentityForAPIToken(rawToken, tenantID, now)
	return identity, ok, nil
}

func adminSessionCookie(session adminSession) *http.Cookie {
	return &http.Cookie{
		Name:     "admin_session",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // TLS-only Edge — cookies never traverse plaintext
		SameSite: http.SameSiteLaxMode,
		MaxAge:   8 * 60 * 60,
	}
}

func expiredAdminSessionCookie() *http.Cookie {
	return expiredCookie("admin_session")
}

func adminPrincipalIDFromRequest(r *http.Request) string {
	if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.PrincipalID) != "" {
		return identity.PrincipalID
	}
	return "admin_lab_001"
}

func adminAuthFailureAuditLog(eventType string, evaluator decision.Evaluator, sourceIP, userAgent, reason string) model.AuditLog {
	action := "admin_auth"
	result := "failure"
	return model.AuditLog{
		ID:            randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:      evaluator.PolicyBundle.TenantID,
		EventType:     eventType,
		TargetType:    stringPtr("admin_endpoint"),
		Action:        &action,
		Result:        &result,
		Reason:        &reason,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"user_agent":   userAgent,
			"reason_codes": []string{reason},
		},
	}
}

func adminRBACDeniedAuditLog(identity adminIdentity, permission string, evaluator decision.Evaluator, sourceIP, userAgent string) model.AuditLog {
	action := "admin_rbac"
	result := "failure"
	reason := "admin_rbac_denied"
	tenantID := strings.TrimSpace(identity.TenantID)
	if tenantID == "" {
		tenantID = evaluator.PolicyBundle.TenantID
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_admin_rbac_denied_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   stringPtr(identity.PrincipalID),
		EventType:     "admin_rbac_denied",
		TargetType:    stringPtr("admin_permission"),
		TargetID:      stringPtr(permission),
		Action:        &action,
		Result:        &result,
		Reason:        &reason,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"auth_method":        identity.AuthMethod,
			"identity_tenant_id": identity.TenantID,
			// ★★★ NOT THE NODE'S OWN ORGANIZATION (2026-08-20). This carried
			// evaluator.PolicyBundle.TenantID — the organization the NODE belongs to — inside a record the
			// refused customer reads on their own screen. Measured with a real customer session sweeping 121
			// routes: /admin/state handed tenant_northwind's administrator the string "tenant_reference_lab".
			//
			// The standing policy is that audit records are NOT EDITED, and it stands: nothing already written
			// is touched, and no read redacts anything. What changes is that this field is not written, which
			// is a different act. It had no reader anywhere in the tree — the record already says which node
			// answered, through EdgeRegionID and EdgeClusterID, and that is what an investigation uses.
			"roles":        identity.Roles,
			"scopes":       identity.Scopes,
			"user_agent":   userAgent,
			"reason_codes": []string{"admin_rbac_denied"},
		},
	}
}

func adminAuthMethodFromRequest(r *http.Request) string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		return identity.AuthMethod
	}
	return ""
}

func adminCSRFTokenFromRequest(r *http.Request) string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		return identity.CSRFToken
	}
	return ""
}

func adminCSRFTokenMatches(r *http.Request, identity adminIdentity) bool {
	expected := strings.TrimSpace(identity.CSRFToken)
	candidate := strings.TrimSpace(r.Header.Get("x-csrf-token"))
	if expected == "" || candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func requestWithAdminIdentity(r *http.Request, identity adminIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, identity))
}

func adminIdentityFromRequest(r *http.Request) (adminIdentity, bool) {
	identity, ok := r.Context().Value(adminIdentityContextKey{}).(adminIdentity)
	return identity, ok
}

// adminRequestCarriedCredentials reports whether the request PRESENTED any admin credential — a session cookie or
// a bearer/api token. It distinguishes a rejected authentication attempt (credentials present but invalid — worth
// an admin_auth_failed audit) from an ANONYMOUS pre-login probe (the Console checking "am I logged in?" before
// sign-in, which returns 401 by design). Auditing the anonymous probe recorded a spurious "Admin auth failed" on
// every login; only genuine failed attempts should be audited. See b.
// adminAuthEndpointPath reports whether the path is an authentication endpoint (login/logout/activate/csrf),
// which is audited as its own admin_login / admin_logout event and is NOT a config mutation — so the uniform
// admin_config_change wrapper audit skips it.
func adminAuthEndpointPath(path string) bool {
	p := strings.TrimSpace(path)
	return p == "/admin/logout" ||
		strings.HasPrefix(p, "/admin/login") ||
		strings.HasPrefix(p, "/admin/activate") ||
		p == "/admin/csrf"
}

var adminPermissionsByRole = map[string]map[string]bool{
	"owner": {
		"*": true,
	},
	"admin": {
		"admin.connectors.read":               true,
		"admin.connectors.write":              true,
		"admin.state.read":                    true,
		"admin.swg.read":                      true,
		"admin.swg.write":                     true,
		"admin.idp.read":                      true,
		"admin.idp.write":                     true,
		"admin.grants.read":                   true,
		"admin.grants.write":                  true,
		"admin.config.read":                   true,
		"admin.config.write":                  true,
		"admin.eastwest.read":                 true,
		"admin.eastwest.write":                true,
		"admin.usage.read":                    true,
		"admin.identity.read":                 true,
		"admin.identity.write":                true,
		"admin.nhi.read":                      true,
		"admin.nhi.write":                     true,
		"admin.logs.read":                     true,
		"admin.logs.export.preview":           true,
		"admin.retention.read":                true,
		"admin.retention.write":               true,
		"admin.export.create":                 true,
		"admin.export.read":                   true,
		"admin.export.cancel":                 true,
		"admin.export.cancel.all":             true,
		"admin.audit.delivery.read":           true,
		"admin.audit.delivery.replay":         true,
		"admin.domain_events.delivery.read":   true,
		"admin.domain_events.delivery.replay": true,
		"admin.break_glass.read":              true,
		"admin.break_glass.write":             true,
		"admin.approval.read":                 true,
		"admin.approval.write":                true,
		"admin.api_tokens.read":               true,
		"admin.api_tokens.write":              true,
		"admin.accounts.read":                 true,
		"admin.accounts.write":                true,
		"admin.policy.read":                   true,
		"admin.policy.write":                  true,
		"admin.applications.read":             true,
		"admin.applications.write":            true,
		"admin.policy_candidates.read":        true,
		"admin.policy_candidates.write":       true,
		"admin.policy_candidates.review":      true,
		"admin.agent_tools.read":              true,
		"admin.agent_tools.write":             true,
		"admin.tool_call_events.read":         true,
		"admin.tool_call_events.write":        true,
		"admin.delegated_grants.read":         true,
		"admin.delegated_grants.write":        true,
		"admin.delegated_grants.revoke":       true,
		"admin.endpoints.read":                true,
		"admin.endpoints.write":               true,
		"admin.tenant.read":                   true,
		"admin.tenant.write":                  true,
		"admin.ai.read":                       true,
		"admin.vlan.read":                     true,
		"admin.vlan.write":                    true,
		"admin.risk.read":                     true,
		"admin.risk.write":                    true,
		"admin.serverinitiated.read":          true,
		"admin.serverinitiated.write":         true,
		"admin.dns.read":                      true,
		// ★★ admin.dns.WRITE IS NOT HERE, AND WAS (2026-08-17, measured as a customer administrator: PUT
		// /admin/dns-policy reached its handler and answered 400 only because the body was malformed). The
		// scope gates exactly one route, and that route sets the resolver policy for the whole NODE — deny
		// list, sinkholes, stub answers — with no tenant in it anywhere. A customer could sinkhole a domain
		// for every organization on the Edge, or deny one. admin.dns.READ stays: seeing the DNS policy that
		// applies to you is not the same as writing it.
		"admin.dlp.read":         true,
		"admin.dlp.write":        true,
		"admin.agents.read":      true,
		"admin.agents.write":     true,
		"admin.enrollment.read":  true,
		"admin.enrollment.write": true,
		"admin.steering.read":    true,
		"admin.steering.write":   true,
		"admin.certs.read":       true,
		// ★★ admin.certs.WRITE IS NOT HERE, AND WAS (2026-08-17, measured as a customer administrator).
		// Every route that requires it is DEPLOYMENT material, not this organization's: PUT /admin/certs/{name}
		// and its rollback replace the certificate this node serves to every device of every organization, and
		// POST/DELETE /admin/pki/operations stage a transport trust rotation. Measured with tenant_northwind's
		// own administrator — no cross-tenant permission anywhere — PUT /admin/certs/edge reached the handler
		// and was refused only by the body validator. Rolling back to an older version needs no body at all.
		//
		// This is the same hole admin.platform.write was created to close, and this scope was left behind in
		// that sweep. The reasoning there applies unchanged: a separate scope rather than widening a tenant
		// one, because a customer keeps admin.certs.READ — they must be able to see the PKI that intercepts
		// them — and their own material (device CA, per-tenant interception root) is reached through
		// admin.enrollment.write and admin.policy.write, which they still hold.
		//
		// The operator did not hold it either: super_admin has no admin.certs.write, so the party whose
		// material this is could not replace it while every customer could.
	},
	"analyst": {
		"admin.state.read":             true,
		"admin.swg.read":               true,
		"admin.eastwest.read":          true,
		"admin.logs.read":              true,
		"admin.logs.export.preview":    true,
		"admin.export.create":          true,
		"admin.export.read":            true,
		"admin.export.cancel":          true,
		"admin.approval.read":          true,
		"admin.policy.read":            true,
		"admin.applications.read":      true,
		"admin.policy_candidates.read": true,
		"admin.agent_tools.read":       true,
		"admin.tool_call_events.read":  true,
		"admin.connectors.read":        true,
		"admin.delegated_grants.read":  true,
		"admin.endpoints.read":         true,
		"admin.tenant.read":            true,
		"admin.ai.read":                true,
		"admin.vlan.read":              true,
		"admin.steering.read":          true,
		"admin.certs.read":             true,
		"admin.serverinitiated.read":   true,
		"admin.dns.read":               true,
		"admin.dlp.read":               true,
		"admin.agents.read":            true,
		"admin.enrollment.read":        true,
	},
	"approver": {
		"admin.state.read":        true,
		"admin.break_glass.read":  true,
		"admin.break_glass.write": true,
		"admin.approval.read":     true,
		"admin.approval.write":    true,
	},
	"auditor": {
		"admin.state.read":                  true,
		"admin.usage.read":                  true,
		"admin.identity.read":               true,
		"admin.nhi.read":                    true,
		"admin.logs.read":                   true,
		"admin.logs.export.preview":         true,
		"admin.export.create":               true,
		"admin.export.read":                 true,
		"admin.audit.delivery.read":         true,
		"admin.domain_events.delivery.read": true,
		"admin.break_glass.read":            true,
		"admin.approval.read":               true,
		"admin.api_tokens.read":             true,
		"admin.accounts.read":               true,
		"admin.policy.read":                 true,
		"admin.applications.read":           true,
		"admin.policy_candidates.read":      true,
		"admin.agent_tools.read":            true,
		"admin.tool_call_events.read":       true,
		"admin.connectors.read":             true,
		"admin.delegated_grants.read":       true,
		"admin.endpoints.read":              true,
		"admin.tenant.read":                 true,
		"admin.ai.read":                     true,
		"admin.vlan.read":                   true,
		"admin.serverinitiated.read":        true,
		"admin.dns.read":                    true,
		"admin.dlp.read":                    true,
		"admin.agents.read":                 true,
		"admin.enrollment.read":             true,
	},
	// ★★★ super_admin IS NOT "THE OPERATOR", AND READING IT THAT WAY HAS COST THIS TREE TWICE.
	//
	// This comment used to open with "super_admin is the cross-tenant operator". It is a ROLE, and every
	// customer's own top administrator holds it — it is the account a customer signs in with. Whether a caller
	// may act outside their own organization is decided by which ORGANIZATION they belong to, in
	// operator_is_an_organization_not_a_role.go (2026-08-21), never by what is granted here.
	//
	// The cost of the old reading, both times, was a permission MOVED here for safety:
	//
	//   2026-08-15  admin.platform.write / admin.quota.write / admin.certs.write / admin.dns.write were taken
	//               off the per-tenant `admin` role and granted below, on the stated grounds that super_admin
	//               was the operator. That moved them out of reach of a customer's `admin` and INTO reach of
	//               the customer's `super_admin`. Measured on 2026-08-22: a customer administrator reached all
	//               seventeen of those routes, replaced the deployment's DNS policy with a 200, and got inside
	//               the signing path for the software every device installs.
	//   the same    /admin/tenants and its delete and purge routes were gated on admin.tenant.admin alone, so
	//               one customer could END another. Also measured on 2026-08-22, on a throwaway organization.
	//
	// Both are now closed where the ACT is, not where the grant is: deployment_wide_acts_belong_to_the_operator.go
	// and an_organizations_life_is_not_a_customers_to_end.go. What is granted below is therefore the CEILING of
	// what this role can be asked for — it is not, and has never been, a statement about who holds it.
	//
	// What the role still means: the top administrator of an organization. It administers that organization,
	// including its profile in /admin/tenants, and it is scoped to tenant administration rather than the owner
	// "*" wildcard so that its token cannot reach unrelated data planes.
	"super_admin": {
		"admin.tenant.admin": true,
		// ★ THE DEPLOYMENT ITSELF IS THE OPERATOR'S, NOT A TENANT'S (2026-08-15). Fleet trust anchors, the
		// foundation interception PKI and agent release publishing are acts on the whole installation, and they
		// were gated on permissions every ordinary tenant `admin` holds. Reproduced on the lab with a real
		// customer account: it reached the trust-anchor and device-client-CA routes, reached agent publishing,
		// and ROTATED THE INTERCEPTION INTERMEDIATE — the CA signing every intercepted TLS leaf on that Edge,
		// for every tenant on it — with a 200.
		//
		// A separate scope rather than reusing the tenant-side ones, the same reasoning as admin.quota.write
		// below: those scopes also cover things that are legitimately a tenant admin's (steer exclusions live
		// under admin.steering.write, tenant policy under admin.policy.write), and widening them would take a
		// customer's own configuration away to close an operator hole.
		"admin.platform.write": true,
		// The certificates this node SERVES, and staged transport trust rotations — deployment material, moved
		// here from the per-tenant `admin` role. See the note there.
		"admin.certs.write": true,
		// The node's DNS resolver policy — deny, sinkhole, stub — likewise moved. One route, no tenant in it.
		"admin.dns.write":    true,
		"admin.tenant.read":  true,
		"admin.tenant.write": true,
		"admin.state.read":   true,
		// ★ CAPACITY IS THE OPERATOR'S, NOT THE TENANT'S (2026-08-14). Setting a tenant's device quota, and
		// applying the licence the quotas are drawn from, are MSSP-level acts: the party a limit constrains must
		// not be the party who writes it. Both routes used to require admin.enrollment.write, which the
		// per-tenant `admin` role holds and this cross-tenant operator did NOT — so the only party who could set
		// a quota was the tenant it applied to, and the operator whose job it is could not do it at all.
		//
		// A separate scope rather than adding admin.enrollment.write here: that scope also covers enrolment
		// tokens, enabling and disabling devices, and device groups, which are legitimately a tenant admin's
		// work. Splitting the capacity routes out is what lets the tenant keep the second set and lose the first.
		"admin.quota.write": true,
	},
}

func adminRBACCatalog() adminRBACCatalogResponse {
	roles := make([]adminRBACCatalogRoleEntry, 0, len(adminAPITokenAssignableRoles))
	for _, role := range adminAPITokenAssignableRoles {
		roles = append(roles, adminRBACCatalogRoleEntry{
			Role:        role,
			Permissions: adminPermissionsForRoles([]string{role}),
		})
	}
	return adminRBACCatalogResponse{
		APITokenDefaultRole: defaultAdminAPITokenRole,
		APITokenRoles:       roles,
	}
}

func adminPermissionAllowed(roles []string, permission string) bool {
	for _, role := range roles {
		allowed := adminPermissionsByRole[role]
		if allowed["*"] || allowed[permission] {
			return true
		}
	}
	return false
}

func adminPermissionsForRoles(roles []string) []string {
	permissions := []string{}
	seen := map[string]bool{}
	for _, role := range roles {
		for permission := range adminPermissionsByRole[role] {
			if seen[permission] {
				continue
			}
			seen[permission] = true
			permissions = append(permissions, permission)
		}
	}
	sort.Strings(permissions)
	return permissions
}

// Admin account lifecycle routes (invite/list/suspend/reactivate/delete/roles).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerAdminAccountRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, adminAuth adminAuthRuntimeStore, operatorTenantID string) {
	mux.HandleFunc("POST /admin/admins/invite", adminEndpoint("admin.accounts.write", func(w http.ResponseWriter, r *http.Request) {
		if config.LocalCredentials == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("first-party admin accounts are not enabled"))
			return
		}
		var req struct {
			Email string   `json:"email"`
			Roles []string `json:"roles"`
			// TenantID is NOT how the target organization is chosen — the operating tenant is, and it comes from
			// the caller's authenticated context. The field exists only so that sending it is an ERROR.
			//
			// ★ MEASURED (2026-08-15). It used to be absent from this struct, so the JSON decoder dropped it in
			// silence: an invite carrying {"tenant_id":"tenant_delprobe2"} answered 201 and seated the
			// administrator in the CALLER's tenant instead. Nothing in the response said which organization the
			// account had joined. A field that changes nothing is worse than a field that does not exist, and
			// reading the tenant from the body is the same defect the licensing route was fixed for.
			TenantID string `json:"tenant_id"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		if body := strings.TrimSpace(req.TenantID); body != "" && !strings.EqualFold(body, strings.TrimSpace(adminTenantIDFromRequest(r))) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("this invitation would go to organization %q, not %q — the organization comes from the one you are operating in, so switch to it and invite again",
				adminTenantIDFromRequest(r), body))
			return
		}
		roles := req.Roles
		if len(roles) == 0 {
			roles = []string{"admin"}
		}
		inviteTenantID := adminTenantIDFromRequest(r)
		// ★ A SUSPENDED ORGANIZATION TAKES NO NEW ADMISSIONS (2026-08-18). Suspension freezes the administrative
		// plane and stops new admission; enforcement for devices already enrolled continues. Seating another
		// administrator into a frozen organization would hand out a credential that cannot sign in.
		if reason, refuse := adminTenantAdministrativelySuspended(r.Context(), config.TenantModelStore, inviteTenantID); refuse {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%s — a suspended organization takes no new administrators. Reactivate it first", reason))
			return
		}
		// Privilege-escalation guard (parity with the roles handler): only a caller holding admin.tenant.admin (a
		// cross-tenant operator) may invite an account into a role that itself grants admin.tenant.admin
		// (owner / super_admin). Without this a tenant-confined admin could mint a cross-tenant operator inside
		// their own tenant via an invite.
		inviteIdentity, _ := adminIdentityFromRequest(r)
		if adminRolesGrantTenantAdmin(roles) && !adminPermissionAllowed(inviteIdentity.Roles, "admin.tenant.admin") {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(inviteIdentity, "admin.tenant.admin", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("inviting an account into a cross-tenant operator role requires admin.tenant.admin"))
			return
		}
		// Operator-tenant convention (Q5): the operator tenant uses the scoped super_admin role, not owner "*".
		if adminOperatorTenantRejectsOwner(operatorTenantID, inviteTenantID, roles) {
			writeError(w, http.StatusConflict, fmt.Errorf("the operator tenant uses the scoped super_admin role; owner cannot be invited into the operator tenant"))
			return
		}
		// ★ THE TARGET ORGANIZATION MUST EXIST (2026-08-15). An invite named the tenant in a header and nothing
		// checked it, so an address could be seated as the administrator of an organization the control plane
		// has never heard of — measured on the lab against a tenant that exists on one Edge and nowhere else.
		//
		// Note that Get() cannot answer this: for an unknown id it SYNTHESISES a default tenant (display name
		// = the id, status active) rather than reporting absence. Existence is only answerable against the
		// list, which is why this asks the admin store for it.
		if adminStore, ok := config.TenantModelStore.(adminTenantModelAdminStore); ok {
			tenants, terr := adminStore.List(r.Context())
			if terr == nil {
				known := false
				for _, t := range tenants {
					if strings.EqualFold(strings.TrimSpace(t.TenantID), strings.TrimSpace(inviteTenantID)) {
						known = true
						break
					}
				}
				if !known {
					writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist; create it before inviting an administrator into it", inviteTenantID))
					return
				}
			}
		}
		principalID := randomEdgeID("adm_", time.Now())
		token, err := config.LocalCredentials.Invite(req.Email, inviteTenantID, principalID, roles, time.Now())
		if errors.Is(err, errCredentialBelongsToAnotherTenant) {
			// 409, not 400: the request is well formed and the caller can act on the answer.
			//
			// ★ WHAT THE ANSWER SAYS DEPENDS ON WHO IS ASKING. Inviting a colleague into your own organization
			// is a TENANT administrator's everyday job, not an operator's — so this message is read mostly by
			// someone who cannot see other organizations at all. Telling them the address "is already an
			// administrator in another organization" hands them a fact about a tenant they are isolated from,
			// and turns this endpoint into a way to ask whether a given person administers anything here. An
			// operator holding admin.tenant.admin can already list every tenant, so for them it is not news.
			//
			// The audit line records the real reason either way: an operator has to be able to find out what
			// actually happened, and that is a different question from what the screen says.
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox,
				adminLoginAuditLog("admin_account_invite_refused_cross_tenant", nil, nil, evaluator, r, req.Email), time.Now())
			if adminPermissionAllowed(inviteIdentity.Roles, "admin.tenant.admin") {
				writeCredentialError(w, http.StatusConflict, err)
				return
			}
			writeError(w, http.StatusConflict, fmt.Errorf(
				"this address cannot be invited here — check with your operator"))
			return
		}
		if err != nil {
			writeCredentialError(w, http.StatusBadRequest, err)
			return
		}
		now := time.Now()
		link := activationLink(config.AdminConsoleOrigin, token)
		if err := sendActivationEmail(config.AdminInviteEmailSinkPath, req.Email, link, now); err != nil {
			log.Printf("send admin invite email: %v", err)
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAccountLifecycleAuditLog("admin_account_invited", inviteTenantID, adminPrincipalIDFromRequest(r), principalID, roles, evaluator, r), now)
		// The assembled invitation travels in the response, because the caller is the one who will deliver it.
		// activation_link stays for compatibility with anything already reading it; `invitation` is what the
		// screen shows. See buildAdminInvitation for why this product hands over rather than sends.
		writeJSON(w, http.StatusCreated, map[string]any{
			"email":  req.Email,
			"status": credentialStatusPending,
			// WHICH organization the account joined. It was decided from the caller's context and never said
			// out loud, so an invite that went to the wrong tenant looked exactly like one that went right.
			"tenant_id":       inviteTenantID,
			"activation_link": link,
			"invitation":      buildAdminInvitation(req.Email, link, now),
		})
	}))
	// Per-tenant Administrators management . Every handler is
	// scoped to the caller's own tenant (adminTenantIDFromRequest) and fails closed when no tenant is resolved,
	// so a tenant-admin can list/manage only their own organization's admins.
	mux.HandleFunc("GET /admin/admins", adminEndpoint("admin.accounts.read", func(w http.ResponseWriter, r *http.Request) {
		if config.LocalCredentials == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("first-party admin accounts are not enabled"))
			return
		}
		tenantID := strings.TrimSpace(adminTenantIDFromRequest(r))
		if tenantID == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"admins": config.LocalCredentials.List(tenantID)})
	}))
	// suspend / reactivate share a status-transition body; both require admin.accounts.write and stay tenant-scoped.
	adminAccountStatusHandler := func(targetStatus, eventType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if config.LocalCredentials == nil {
				writeError(w, http.StatusServiceUnavailable, fmt.Errorf("first-party admin accounts are not enabled"))
				return
			}
			tenantID := strings.TrimSpace(adminTenantIDFromRequest(r))
			if tenantID == "" {
				writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
				return
			}
			principalID := strings.TrimSpace(r.PathValue("principal_id"))
			// Suspending the last admin able to manage admins would lock the tenant out — guard it.
			if targetStatus == credentialStatusSuspended && adminTenantStillExists(r.Context(), config.TenantModelStore, tenantID) &&
				adminAccountLockoutWouldOccur(config.LocalCredentials.List(tenantID), principalID, "", nil) {
				writeError(w, http.StatusConflict, fmt.Errorf("cannot suspend the last administrator able to manage admins in this tenant"))
				return
			}
			summary, err := config.LocalCredentials.SetStatus(tenantID, principalID, targetStatus, time.Now())
			if err != nil {
				if errors.Is(err, errAdminAccountNotFound) {
					writeError(w, http.StatusNotFound, fmt.Errorf("admin %s is absent", principalID))
					return
				}
				writeCredentialError(w, http.StatusBadRequest, err)
				return
			}
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAccountLifecycleAuditLog(eventType, tenantID, adminPrincipalIDFromRequest(r), principalID, summary.Roles, evaluator, r), time.Now())
			writeJSON(w, http.StatusOK, summary)
		}
	}
	mux.HandleFunc("POST /admin/admins/{principal_id}/suspend", adminEndpoint("admin.accounts.write", adminAccountStatusHandler(credentialStatusSuspended, "admin_account_suspended")))
	mux.HandleFunc("POST /admin/admins/{principal_id}/reactivate", adminEndpoint("admin.accounts.write", adminAccountStatusHandler(credentialStatusActive, "admin_account_reactivated")))
	mux.HandleFunc("DELETE /admin/admins/{principal_id}", adminEndpoint("admin.accounts.write", func(w http.ResponseWriter, r *http.Request) {
		if config.LocalCredentials == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("first-party admin accounts are not enabled"))
			return
		}
		tenantID := strings.TrimSpace(adminTenantIDFromRequest(r))
		if tenantID == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		principalID := strings.TrimSpace(r.PathValue("principal_id"))
		// Self-deletion guard: never let an admin remove their own account (immediate self-lockout).
		if principalID == adminPrincipalIDFromRequest(r) {
			writeError(w, http.StatusConflict, fmt.Errorf("an administrator cannot delete their own account"))
			return
		}
		// Last-admin guard: never remove the final account able to manage admins in this tenant.
		//
		// ★ UNLESS THE TENANT IS GONE (2026-08-15). The guard keeps an organization MANAGEABLE, and an
		// organization that no longer exists does not need to be. Measured on the lab: deleting a tenant left its
		// administrator behind, and this guard then refused every attempt to remove it — the account could
		// neither be deleted nor suspended, and went on authenticating. A protection that outlives the thing it
		// protects stops being a protection and becomes a trap.
		if adminTenantStillExists(r.Context(), config.TenantModelStore, tenantID) &&
			adminAccountLockoutWouldOccur(config.LocalCredentials.List(tenantID), principalID, "", nil) {
			writeError(w, http.StatusConflict, fmt.Errorf("cannot delete the last administrator able to manage admins in this tenant"))
			return
		}
		summary, err := config.LocalCredentials.Delete(tenantID, principalID, time.Now())
		if err != nil {
			if errors.Is(err, errAdminAccountNotFound) {
				writeError(w, http.StatusNotFound, fmt.Errorf("admin %s is absent", principalID))
				return
			}
			writeCredentialError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAccountLifecycleAuditLog("admin_account_deleted", tenantID, adminPrincipalIDFromRequest(r), principalID, summary.Roles, evaluator, r), time.Now())
		writeJSON(w, http.StatusOK, map[string]any{"principal_id": principalID, "deleted": true})
	}))
	mux.HandleFunc("POST /admin/admins/{principal_id}/roles", adminEndpoint("admin.accounts.write", func(w http.ResponseWriter, r *http.Request) {
		if config.LocalCredentials == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("first-party admin accounts are not enabled"))
			return
		}
		tenantID := strings.TrimSpace(adminTenantIDFromRequest(r))
		if tenantID == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin tenant is required"))
			return
		}
		principalID := strings.TrimSpace(r.PathValue("principal_id"))
		var req struct {
			Roles []string `json:"roles"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		roles := make([]string, 0, len(req.Roles))
		for _, role := range req.Roles {
			role = strings.TrimSpace(role)
			if role == "" {
				continue
			}
			if !adminRoleKnown(role) {
				writeError(w, http.StatusBadRequest, fmt.Errorf("unknown role %q", role))
				return
			}
			roles = append(roles, role)
		}
		if len(roles) == 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("at least one role is required"))
			return
		}
		// Privilege-escalation guard: only a caller holding admin.tenant.admin (a cross-tenant operator) may
		// assign a role that itself grants admin.tenant.admin (owner / super_admin). A tenant-admin cannot mint
		// a cross-tenant operator inside their tenant.
		identity, _ := adminIdentityFromRequest(r)
		if adminRolesGrantTenantAdmin(roles) && !adminPermissionAllowed(identity.Roles, "admin.tenant.admin") {
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminRBACDeniedAuditLog(identity, "admin.tenant.admin", evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("assigning a cross-tenant operator role requires admin.tenant.admin"))
			return
		}
		// Operator-tenant convention (Q5): the operator tenant uses the scoped super_admin role, not owner "*".
		if adminOperatorTenantRejectsOwner(operatorTenantID, tenantID, roles) {
			writeError(w, http.StatusConflict, fmt.Errorf("the operator tenant uses the scoped super_admin role; owner is not assignable in the operator tenant"))
			return
		}
		// Lockout guard: a role change must not remove the tenant's last admin-managing account.
		if adminAccountLockoutWouldOccur(config.LocalCredentials.List(tenantID), "", principalID, roles) {
			writeError(w, http.StatusConflict, fmt.Errorf("this role change would leave the tenant without an administrator able to manage admins"))
			return
		}
		summary, err := config.LocalCredentials.SetRoles(tenantID, principalID, roles, time.Now())
		if err != nil {
			if errors.Is(err, errAdminAccountNotFound) {
				writeError(w, http.StatusNotFound, fmt.Errorf("admin %s is absent", principalID))
				return
			}
			writeCredentialError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminAccountLifecycleAuditLog("admin_account_roles_changed", tenantID, adminPrincipalIDFromRequest(r), principalID, summary.Roles, evaluator, r), time.Now())
		writeJSON(w, http.StatusOK, summary)
	}))
}

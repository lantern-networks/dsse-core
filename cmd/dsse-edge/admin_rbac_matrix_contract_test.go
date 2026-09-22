package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/logs"
)

type adminRBACMatrixRoute struct {
	Method     string
	Path       string
	Permission string
}

func TestAdminRBACMatrixMatchesCatalogForEveryEndpoint(t *testing.T) {
	routes := mustAdminEndpointRBACMatrixRoutes(t)
	if len(routes) == 0 {
		t.Fatalf("admin endpoint RBAC route set is empty")
	}
	for _, route := range routes {
		if !adminRBACMatrixPermissionInCatalog(route.Permission) {
			t.Fatalf("route %s %s requires %q, which is absent from assignable RBAC catalog", route.Method, route.Path, route.Permission)
		}
	}

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth, rawTokensByRole := adminRBACMatrixAuthStore(t)
	defer writer.Close()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	config := adminRBACMatrixServerConfig(writer, adminAuth)
	config.AdminAuditOutbox = outbox
	handler := newServerWithConfig(config)

	for _, route := range routes {
		for _, role := range adminAPITokenAssignableRoles {
			t.Run(fmt.Sprintf("%s %s %s", role, route.Method, route.Path), func(t *testing.T) {
				req := httptest.NewRequest(route.Method, adminRBACMatrixConcretePath(route.Path), adminRBACMatrixBody(route.Method))
				req.Header.Set("authorization", "Bearer "+rawTokensByRole[role])
				req.Header.Set("content-type", "application/json")
				rec := httptest.NewRecorder()

				auditStart := len(outbox.insertedAudits)
				handler.ServeHTTP(rec, req)

				body := rec.Body.String()
				permissionDenied := rec.Code == http.StatusForbidden && strings.Contains(body, fmt.Sprintf("admin permission %s is required", route.Permission))
				roleAllowed := adminPermissionAllowedAny([]string{role}, route.Permission)
				if roleAllowed && permissionDenied {
					t.Fatalf("role %q was denied by RBAC for allowed permission %q: status=%d body=%s", role, route.Permission, rec.Code, body)
				}
				if !roleAllowed && !permissionDenied {
					t.Fatalf("role %q was not denied by RBAC for permission %q: status=%d body=%s", role, route.Permission, rec.Code, body)
				}
				if !roleAllowed {
					rows := outbox.insertedAudits[auditStart:]
					if len(rows) != 1 {
						t.Fatalf("denial audits = %d, want 1", len(rows))
					}
					row := rows[0]
					if row.EventType != "admin_rbac_denied" || row.TenantID != "tenant_lab_001" ||
						row.ActorUserID == nil || *row.ActorUserID != "admin_user_rbac_matrix_"+role ||
						row.TargetID == nil || *row.TargetID != route.Permission ||
						row.Result == nil || *row.Result != "failure" {
						t.Fatalf("incorrect denial audit: %+v", row)
					}
				}
				if rec.Code == http.StatusUnauthorized {
					t.Fatalf("role %q was not authenticated for %s %s: body=%s", role, route.Method, route.Path, body)
				}
			})
		}
	}
}

// These routes live outside main.go. Moving registration must not silently remove
// account, policy, application, or certificate gates from the cross-cutting matrix.
func TestAdminRBACMatrixIncludesSplitRegistrations(t *testing.T) {
	found := map[string]string{}
	for _, route := range mustAdminEndpointRBACMatrixRoutes(t) {
		found[route.Method+" "+route.Path] = route.Permission
	}
	for route, permission := range map[string]string{
		"POST /admin/applications": "admin.applications.write",
		"PUT /admin/certs/{name}":  "admin.certs.write",
		"GET /admin/rbac/catalog":  "admin.api_tokens.read",
	} {
		if found[route] != permission {
			t.Errorf("%s: got permission %q, want %q", route, found[route], permission)
		}
	}
}

func mustAdminEndpointRBACMatrixRoutes(t *testing.T) []adminRBACMatrixRoute {
	t.Helper()

	// Registration is split across feature files. Keep the same package-wide scope
	// as the OpenAPI drift detector; test-only fixtures are not product routes.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	routeExpr := regexp.MustCompile(`mux\.HandleFunc\(\s*"([A-Z]+) ([^"]+)"\s*,\s*adminEndpoint\(\s*"([^"]+)"`)
	var routes []adminRBACMatrixRoute
	seen := map[string]struct{}{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, match := range routeExpr.FindAllStringSubmatch(string(data), -1) {
			route := adminRBACMatrixRoute{Method: match[1], Path: match[2], Permission: match[3]}
			key := route.Method + " " + route.Path
			if _, exists := seen[key]; exists {
				t.Fatalf("duplicate admin endpoint route %q", key)
			}
			seen[key] = struct{}{}
			routes = append(routes, route)
		}
	}
	t.Logf("literal adminEndpoint registrations: %d", len(routes))
	sort.Slice(routes, func(i, j int) bool {
		left := fmt.Sprintf("%s %s", routes[i].Method, routes[i].Path)
		right := fmt.Sprintf("%s %s", routes[j].Method, routes[j].Path)
		return left < right
	})
	return routes
}

func adminRBACMatrixAuthStore(t *testing.T) (*adminAuthStore, map[string]string) {
	t.Helper()

	store := newAdminAuthStore()
	rawTokensByRole := map[string]string{}
	now := time.Now().UTC()
	for _, role := range adminAPITokenAssignableRoles {
		principalID := "admin_user_rbac_matrix_" + role
		rawToken := "raw-rbac-matrix-" + role
		store.UpsertPrincipal(adminPrincipal{
			ID:        principalID,
			TenantID:  "tenant_lab_001",
			Subject:   "sub_rbac_matrix_" + role,
			Email:     role + "@example.invalid",
			Roles:     []string{role},
			IDPID:     "keycloak_lab",
			Status:    "active",
			CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		})
		store.UpsertAPIToken(adminAPIToken{
			ID:                        "admin_token_rbac_matrix_" + role,
			TenantID:                  "tenant_lab_001",
			Name:                      "rbac-matrix-" + role,
			TokenHash:                 adminTokenHash(rawToken),
			Roles:                     []string{role},
			Scopes:                    []string{"*"},
			CreatedByAdminPrincipalID: principalID,
			CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
			ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339),
			Status:                    "active",
		})
		rawTokensByRole[role] = rawToken
	}
	return store, rawTokensByRole
}

func adminRBACMatrixPermissionInCatalog(permission string) bool {
	// Validate every alternative separately: accepting one valid branch must not
	// hide a misspelled permission in the other branch.
	for _, alternative := range strings.Split(permission, "|") {
		known := false
		for _, role := range adminAPITokenAssignableRoles {
			known = known || adminPermissionAllowed([]string{role}, strings.TrimSpace(alternative))
		}
		if !known {
			return false
		}
	}
	return true
}

func adminRBACMatrixConcretePath(path string) string {
	pathParamExpr := regexp.MustCompile(`\{[^}/]+\}`)
	return pathParamExpr.ReplaceAllStringFunc(path, func(match string) string {
		return strings.Trim(match, "{}") + "_rbac_matrix"
	})
}

func adminRBACMatrixBody(method string) *strings.Reader {
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		return strings.NewReader("{}")
	}
	return strings.NewReader("")
}

// Optional CP routes need their dependencies to be registered. These are local
// fixtures only: a handler response is not fleet or database acceptance.
func adminRBACMatrixServerConfig(writer *logs.Writer, auth *adminAuthStore) serverConfig {
	return serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth,
		FleetConfigStatus: newFleetConfigStatusStore(time.Second),
		EnrolmentTokens:   enrolltoken.NewStore(), FleetIdentityClaimer: adminRBACMatrixClaims{},
	}
}

type adminRBACMatrixClaims struct{}

func (adminRBACMatrixClaims) ClaimIdentity(context.Context, string, string, int) (bool, error) {
	return false, fmt.Errorf("matrix fixture has no identity authority")
}
func (adminRBACMatrixClaims) ReleaseIdentity(context.Context, string, string, int) error {
	return fmt.Errorf("matrix fixture has no identity authority")
}
func (adminRBACMatrixClaims) BackfillClaims(context.Context, []enrolledinventory.IdentityClaim) (int, error) {
	return 0, fmt.Errorf("matrix fixture has no identity authority")
}

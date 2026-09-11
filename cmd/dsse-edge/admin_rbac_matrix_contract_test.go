package main

import (
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
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})

	for _, route := range routes {
		for _, role := range adminAPITokenAssignableRoles {
			t.Run(fmt.Sprintf("%s %s %s", role, route.Method, route.Path), func(t *testing.T) {
				req := httptest.NewRequest(route.Method, adminRBACMatrixConcretePath(route.Path), adminRBACMatrixBody(route.Method))
				req.Header.Set("authorization", "Bearer "+rawTokensByRole[role])
				req.Header.Set("content-type", "application/json")
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)

				body := rec.Body.String()
				permissionDenied := rec.Code == http.StatusForbidden && strings.Contains(body, fmt.Sprintf("admin permission %s is required", route.Permission))
				roleAllowed := adminPermissionAllowed([]string{role}, route.Permission)
				if roleAllowed && permissionDenied {
					t.Fatalf("role %q was denied by RBAC for allowed permission %q: status=%d body=%s", role, route.Permission, rec.Code, body)
				}
				if !roleAllowed && !permissionDenied {
					t.Fatalf("role %q was not denied by RBAC for permission %q: status=%d body=%s", role, route.Permission, rec.Code, body)
				}
				if rec.Code == http.StatusUnauthorized {
					t.Fatalf("role %q was not authenticated for %s %s: body=%s", role, route.Method, route.Path, body)
				}
			})
		}
	}
}

func mustAdminEndpointRBACMatrixRoutes(t *testing.T) []adminRBACMatrixRoute {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	routeExpr := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)", adminEndpoint\("([^"]+)"`)
	matches := routeExpr.FindAllStringSubmatch(string(data), -1)
	routes := make([]adminRBACMatrixRoute, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		route := adminRBACMatrixRoute{
			Method:     match[1],
			Path:       match[2],
			Permission: match[3],
		}
		key := fmt.Sprintf("%s %s", route.Method, route.Path)
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate admin endpoint route %q", key)
		}
		seen[key] = struct{}{}
		routes = append(routes, route)
	}
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
	for _, role := range adminAPITokenAssignableRoles {
		if adminPermissionAllowed([]string{role}, permission) {
			return true
		}
	}
	return false
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

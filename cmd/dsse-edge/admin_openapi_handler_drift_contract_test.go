package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestAdminOpenAPIHandlerDriftDetector(t *testing.T) {
	handlerRoutes := mustAdminHandlerRouteSet(t)
	openAPIRoutes := mustAdminOpenAPIRouteSet(t)

	if len(handlerRoutes) == 0 {
		t.Fatalf("handler route set is empty")
	}
	if len(openAPIRoutes) == 0 {
		t.Fatalf("OpenAPI route set is empty")
	}

	handlerOnly := routeSetDiff(handlerRoutes, openAPIRoutes)
	openAPIOnly := routeSetDiff(openAPIRoutes, handlerRoutes)
	if len(handlerOnly) > 0 || len(openAPIOnly) > 0 {
		t.Fatalf("admin OpenAPI/handler route drift detected\nhandler only:\n%s\nOpenAPI only:\n%s", strings.Join(handlerOnly, "\n"), strings.Join(openAPIOnly, "\n"))
	}
}

func mustAdminHandlerRouteSet(t *testing.T) map[string]struct{} {
	t.Helper()

	// Admin routes are registered across several edge source files (main.go plus per-feature
	// registration helpers like grants_admin.go / idp_connections_admin.go), so scan every
	// non-test .go file in the package — not just main.go — or routes registered in a helper
	// look like spec-only drift even though their handlers exist.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob edge sources: %v", err)
	}
	routeExpr := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) (/admin[^"]*)"`)
	routes := map[string]struct{}{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, match := range routeExpr.FindAllStringSubmatch(string(data), -1) {
			method, path := match[1], match[2]
			if path == "/admin" || !strings.HasPrefix(path, "/admin/") {
				continue
			}
			route := fmt.Sprintf("%s %s", method, path)
			if _, exists := routes[route]; exists {
				t.Fatalf("duplicate handler admin route %q", route)
			}
			routes[route] = struct{}{}
		}
	}
	return routes
}

func mustAdminOpenAPIRouteSet(t *testing.T) map[string]struct{} {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	pathExpr := regexp.MustCompile(`^  (/admin[^:]*):\s*$`)
	methodExpr := regexp.MustCompile(`^    (get|post|put|patch|delete|options|head):\s*$`)
	routes := make(map[string]struct{})
	currentPath := ""
	inPaths := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if strings.HasPrefix(line, "components:") {
			break
		}
		if strings.HasPrefix(line, "  /") {
			currentPath = ""
			if match := pathExpr.FindStringSubmatch(line); match != nil {
				path := match[1]
				if path == "/admin" || strings.HasPrefix(path, "/admin/") {
					currentPath = path
				}
			}
			continue
		}
		if currentPath == "" {
			continue
		}
		match := methodExpr.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		route := fmt.Sprintf("%s %s", strings.ToUpper(match[1]), currentPath)
		if _, exists := routes[route]; exists {
			t.Fatalf("duplicate OpenAPI admin route %q", route)
		}
		routes[route] = struct{}{}
	}
	return routes
}

func routeSetDiff(left, right map[string]struct{}) []string {
	var diff []string
	for route := range left {
		if _, ok := right[route]; !ok {
			diff = append(diff, route)
		}
	}
	sort.Strings(diff)
	return diff
}

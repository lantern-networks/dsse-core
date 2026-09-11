package main

// Phase 0 of the edge main.go decomposition plan
// : freeze the externally
// visible surface — every registered route and every CLI flag — as byte-identical
// manifests BEFORE any code moves. Refactor commits (Phases 1–4) must leave both
// manifest files untouched; that is the mechanical proof the move changed nothing
// a client, device, or operator can see.
//
// The manifests cover the WHOLE package, not just main.go, so Phase 1's mechanical
// file moves do not disturb them. Only a functional change (adding, removing or
// renaming a route or flag) may regenerate them — and never in the same commit as
// a refactor move:
//
//	DSSE_UPDATE_EDGE_MANIFESTS=1 go test -run TestEdgeManifest ./cmd/edge/

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
	swg "github.com/lantern-networks/dsse-core/swg"
)

const edgeManifestUpdateEnv = "DSSE_UPDATE_EDGE_MANIFESTS"

// knownCrossPackageRoutePatternConsts resolves route-pattern constants that live in
// OTHER packages, which pure parsing cannot see into. Referencing the real constant
// here means the manifest entry can never drift from the served value. A new entry is
// only needed when a route registration starts using a constant from another package.
var knownCrossPackageRoutePatternConsts = map[string]string{
	"swg.EdgeSWGTLSReadinessStatusPath":                  swg.EdgeSWGTLSReadinessStatusPath,
	"edgeplane.EdgeSWGHTTPEgressPath":                    edgeplane.EdgeSWGHTTPEgressPath,
	"edgeplane.NetworkExtensionRuntimeCopyRoundTripPath": edgeplane.NetworkExtensionRuntimeCopyRoundTripPath,
	"edgeplane.NetworkExtensionRuntimeCopySessionPath":   edgeplane.NetworkExtensionRuntimeCopySessionPath,
	"edgeplane.NetworkExtensionRuntimeCopyTunnelPath":    edgeplane.NetworkExtensionRuntimeCopyTunnelPath,
}

func TestEdgeManifestRoutes(t *testing.T) {
	fset, files := parseEdgePackage(t)
	routes := collectRouteRegistrations(t, fset, files)
	compareOrUpdateManifest(t, filepath.Join("testdata", "route_manifest.txt"), routes)
}

func TestEdgeManifestFlags(t *testing.T) {
	fset, files := parseEdgePackage(t)
	flags := collectFlagDefinitions(t, fset, files)
	compareOrUpdateManifest(t, filepath.Join("testdata", "flag_manifest.txt"), flags)
}

// parseEdgePackage parses every non-test .go file at the package root. Test files are
// excluded on purpose: the manifests describe what the binary serves and accepts, not
// what the tests construct.
func parseEdgePackage(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	files := make(map[string]*ast.File)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = parsed
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files found; test must run from the package directory")
	}
	return fset, files
}

func sortedFileNames(files map[string]*ast.File) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// edgePackageStringConsts collects every package-level string constant, so that
// route registrations via a named constant resolve to the literal path they serve.
func edgePackageStringConsts(files map[string]*ast.File) map[string]string {
	consts := make(map[string]string)
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					if i >= len(value.Values) {
						continue
					}
					lit, ok := value.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						consts[name.Name] = v
					}
				}
			}
		}
	}
	return consts
}

func renderExpr(fset *token.FileSet, expr ast.Expr) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, expr); err != nil {
		return fmt.Sprintf("<unprintable: %v>", err)
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

// resolveStringExpr evaluates the string expressions that appear as route patterns and
// flag names: literals, package-level constants, cross-package constants declared in
// knownCrossPackageRoutePatternConsts, and + concatenations of those.
func resolveStringExpr(fset *token.FileSet, expr ast.Expr, consts map[string]string) (string, error) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return strconv.Unquote(e.Value)
		}
	case *ast.Ident:
		if v, ok := consts[e.Name]; ok {
			return v, nil
		}
		return "", fmt.Errorf("identifier %q is not a package-level string constant; route/flag names must be literals or package-level constants so the manifest can resolve them", e.Name)
	case *ast.ParenExpr:
		return resolveStringExpr(fset, e.X, consts)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			left, err := resolveStringExpr(fset, e.X, consts)
			if err != nil {
				return "", err
			}
			right, err := resolveStringExpr(fset, e.Y, consts)
			if err != nil {
				return "", err
			}
			return left + right, nil
		}
	case *ast.SelectorExpr:
		key := renderExpr(fset, e)
		if v, ok := knownCrossPackageRoutePatternConsts[key]; ok {
			return v, nil
		}
		return "", fmt.Errorf("cross-package constant %s has no entry in knownCrossPackageRoutePatternConsts (edge_main_split_manifest_contract_test.go)", key)
	}
	return "", fmt.Errorf("unsupported expression %s", renderExpr(fset, expr))
}

// collectRouteRegistrations returns one entry per Handle/HandleFunc call in the
// package, resolved to the pattern string it registers, sorted. Duplicates are kept:
// the same pattern registered on two different muxes is two registrations.
func collectRouteRegistrations(t *testing.T, fset *token.FileSet, files map[string]*ast.File) []string {
	t.Helper()
	return collectRouteRegistrationsFrom(t, fset, files, edgePackageStringConsts(files))
}

// collectRouteRegistrationsFrom scans only the given files but resolves constants
// against a caller-supplied table — the ratchet counts main.go alone while route
// patterns may name constants declared in sibling files.
func collectRouteRegistrationsFrom(t *testing.T, fset *token.FileSet, files map[string]*ast.File, consts map[string]string) []string {
	t.Helper()
	var routes []string
	for _, name := range sortedFileNames(files) {
		ast.Inspect(files[name], func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(call.Args) < 2 {
				return true
			}
			pattern, err := resolveStringExpr(fset, call.Args[0], consts)
			if err != nil {
				t.Fatalf("%s: route registration: %v", fset.Position(call.Pos()), err)
			}
			routes = append(routes, pattern)
			return true
		})
	}
	sort.Strings(routes)
	return routes
}

var edgeFlagKinds = map[string]bool{
	"Bool": true, "Duration": true, "Float64": true,
	"Int": true, "Int64": true, "String": true, "Uint": true, "Uint64": true,
}

// collectFlagDefinitions returns "name\tkind\tdefault" per flag.<Kind>/<Kind>Var call,
// sorted by flag name. Usage strings are deliberately NOT frozen — help-text wording
// may improve at any time; the contract is name, type and default.
func collectFlagDefinitions(t *testing.T, fset *token.FileSet, files map[string]*ast.File) []string {
	t.Helper()
	consts := edgePackageStringConsts(files)
	var flags []string
	for _, fileName := range sortedFileNames(files) {
		ast.Inspect(files[fileName], func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "flag" {
				return true
			}
			kind := sel.Sel.Name
			var nameArg, defaultArg ast.Expr
			switch {
			case edgeFlagKinds[kind] && len(call.Args) >= 3:
				nameArg, defaultArg = call.Args[0], call.Args[1]
			case strings.HasSuffix(kind, "Var") && edgeFlagKinds[strings.TrimSuffix(kind, "Var")] && len(call.Args) >= 4:
				nameArg, defaultArg = call.Args[1], call.Args[2]
			default:
				return true
			}
			name, err := resolveStringExpr(fset, nameArg, consts)
			if err != nil {
				t.Fatalf("%s: flag definition: %v", fset.Position(call.Pos()), err)
			}
			flags = append(flags, fmt.Sprintf("%s\t%s\t%s", name, kind, renderExpr(fset, defaultArg)))
			return true
		})
	}
	sort.Strings(flags)
	return flags
}

func compareOrUpdateManifest(t *testing.T, path string, lines []string) {
	t.Helper()
	got := strings.Join(lines, "\n") + "\n"
	if os.Getenv(edgeManifestUpdateEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s (%d entries)", path, len(lines))
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v — regenerate with %s=1 go test -run TestEdgeManifest ./cmd/edge/", path, err, edgeManifestUpdateEnv)
	}
	// Compare CONTENT, not the line endings the checkout happened to produce. git converts these files to
	// CRLF on a machine with core.autocrlf=true, and this generates LF, so a raw byte comparison reported
	// every one of the 356 routes as both added and removed — the manifest was identical and the test was
	// unpassable on that platform. Normalising here keeps "byte-identical" meaning what it is for: the
	// route and flag surface did not move.
	want := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if want == got {
		return
	}
	added, removed := diffLines(strings.Split(strings.TrimSuffix(want, "\n"), "\n"), lines)
	t.Errorf("%s no longer matches the tree (+%d/-%d):\n  added:   %s\n  removed: %s\n"+
		"A refactor commit must leave this manifest byte-identical. If the change is an INTENTIONAL "+
		"functional change (new/removed/renamed route or flag), regenerate in its own commit with "+
		"%s=1 go test -run TestEdgeManifest ./cmd/edge/",
		path, len(added), len(removed), summarizeLines(added), summarizeLines(removed), edgeManifestUpdateEnv)
}

// diffLines is a multiset diff: entries in got but not want (added) and vice versa.
func diffLines(want, got []string) (added, removed []string) {
	counts := make(map[string]int)
	for _, l := range want {
		counts[l]++
	}
	for _, l := range got {
		if counts[l] > 0 {
			counts[l]--
		} else {
			added = append(added, l)
		}
	}
	for _, l := range want {
		if counts[l] > 0 {
			counts[l]--
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func summarizeLines(lines []string) string {
	if len(lines) == 0 {
		return "(none)"
	}
	const max = 10
	if len(lines) > max {
		return strings.Join(lines[:max], " | ") + fmt.Sprintf(" | …and %d more", len(lines)-max)
	}
	return strings.Join(lines, " | ")
}

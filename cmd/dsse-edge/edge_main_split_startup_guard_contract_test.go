package main

// Phase 0 characterization of the ordered startup checks in main.go
// ( caution 3,). Guards of
// this class have been silently reverted before (the canSign startup guard, caught
// only later by grep), so before Phase 2 moves construction into named stages these
// tests pin, structurally: the guard EXISTS and it runs where it must — before the
// process starts serving. Behavior of each guard is covered by its own tests; this
// file only pins the wiring.

import (
	"go/ast"
	"os"
	"strings"
	"testing"
)

func TestStartupGuardsRemainWired(t *testing.T) {
	fset, files := parseEdgePackage(t)
	_ = fset
	mainFile, ok := files["main.go"]
	if !ok {
		t.Fatal("main.go not found in package")
	}
	mainFn := funcDeclNamed(mainFile, "main")
	if mainFn == nil {
		t.Fatal("func main() not found in main.go")
	}
	constructor := funcDeclNamed(mainFile, "newServerWithConfig")
	if constructor == nil {
		t.Fatal("func newServerWithConfig() not found in main.go")
	}

	t.Run("control-plane-required guard runs before server construction", func(t *testing.T) {
		guard := firstCallNamed(mainFn, "requireControlPlaneOrExit")
		if guard == nil {
			t.Fatal("main() no longer calls requireControlPlaneOrExit — an Edge without a control plane must refuse to start (feedback_never_start_an_edge_without_a_control_plane)")
		}
		construct := firstCallNamed(mainFn, "newServerWithConfig")
		if construct == nil {
			t.Fatal("main() no longer calls newServerWithConfig")
		}
		if guard.Pos() >= construct.Pos() {
			t.Error("requireControlPlaneOrExit must run BEFORE newServerWithConfig in main(): the guard is only meaningful if no server is built without a control plane")
		}
	})

	t.Run("served-certificate startup check runs during construction", func(t *testing.T) {
		if firstCallNamed(constructor, "reportServedCertificatesAtStartup") == nil {
			t.Fatal("newServerWithConfig no longer calls reportServedCertificatesAtStartup — every certificate this node presents must be checked as a device would at startup (project_cert_replacement_must_verify_as_a_device)")
		}
	})

	t.Run("unsigned agent-policy refusal still present", func(t *testing.T) {
		if !fatalfLiteralContains(mainFile, "agent-policy signing DISABLED") {
			t.Fatal("the production refusal for a missing agent-policy signing key (log.Fatalf \"agent-policy signing DISABLED…\") is gone from main.go — unsigned steer exclusions would be silently accepted")
		}
	})

	t.Run("interception HSM failure is fatal", func(t *testing.T) {
		if !fatalfLiteralContains(mainFile, "interception HSM agent") {
			t.Fatal("the fatal on interception HSM agent construction failure is gone from main.go — running on with an in-process key after being told to use hardware would silently downgrade custody")
		}
	})

	t.Run("run-mode dispatch characterized", func(t *testing.T) {
		src, err := os.ReadFile("main.go")
		if err != nil {
			t.Fatalf("read main.go: %v", err)
		}
		text := string(src)
		if !strings.Contains(text, `flag.String("mode", "edge"`) {
			t.Error(`the -mode flag no longer defaults to "edge"`)
		}
		for _, mode := range []string{
			`*mode == "postgres-export-worker"`,
			`*mode == "postgres-audit-publisher"`,
			`*mode == "postgres-domain-event-publisher"`,
		} {
			if !strings.Contains(text, mode) {
				t.Errorf("main.go no longer dispatches on %s — if a run mode was intentionally moved or removed, update this characterization in the same commit", mode)
			}
		}
	})
}

func funcDeclNamed(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func firstCallNamed(root ast.Node, name string) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(root, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == name {
			found = call
			return false
		}
		return true
	})
	return found
}

// fatalfLiteralContains reports whether the file contains a log.Fatalf whose format
// string contains the given substring.
func fatalfLiteralContains(file *ast.File, substr string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Fatalf" || len(call.Args) == 0 {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "log" {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && strings.Contains(lit.Value, substr) {
			found = true
			return false
		}
		return true
	})
	return found
}

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// ★ THE FEATURE THAT ADDS A SECOND CUSTOMER MUST NOT STOP THE FIRST ONE (2026-08-16).
//
// Per-tenant interception signing is fail-closed: an organization with no issuer of its own is refused rather
// than signed under somebody else's CA. The organization the NODE-WIDE intermediate belongs to is exempt —
// SetOfflinePrimaryTenant is what names it — and the first bundle can arrive at runtime through
// POST /admin/interception-intermediate/{tenant}. So if that call were made only when the issuer DIRECTORY is
// configured, a deployment that loaded its first tenant bundle through the API would fail closed on the tenant
// it had been serving all along: every existing device, mid-session, because a second customer was onboarded.
//
// This gate exists because the ordering is invisible at the call site — the wrong version compiles and passes
// every unit test (they set the primary explicitly), and breaks only on a deployment that has traffic.
func TestTheOfflinePrimaryTenantIsSetUnconditionally(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", source, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	base := fset.File(file.Pos()).Base()
	text := func(node ast.Node) string {
		return string(source[int(node.Pos())-base : int(node.End())-base])
	}

	callPos := token.NoPos
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetOfflinePrimaryTenant" {
				callPos = call.Pos()
			}
		}
		return true
	})
	if callPos == token.NoPos {
		t.Fatal("main.go never names the organization the node-wide intermediate belongs to; the first per-tenant " +
			"bundle loaded through the admin API would fail closed on the tenant this node already serves")
	}

	ast.Inspect(file, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Cond == nil || ifStmt.Body == nil {
			return true
		}
		if callPos <= ifStmt.Body.Pos() || callPos >= ifStmt.Body.End() {
			return true
		}
		if strings.Contains(text(ifStmt.Cond), "interceptionTenantIssuers.dir") {
			t.Fatal("SetOfflinePrimaryTenant is only reached when the per-tenant issuer DIRECTORY is configured — so a " +
				"deployment that loads its first bundle through POST /admin/interception-intermediate/{tenant} stops " +
				"intercepting its own tenant's live traffic the moment a second customer is onboarded")
		}
		return true
	})
}

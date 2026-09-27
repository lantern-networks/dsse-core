package main

// Phase 0 structural ratchet for main.go
// : main.go may only
// SHRINK. New routes, flags, functions and types belong in a sibling file of this
// package (or a real package), never in main.go. The baselines below were measured
// from the tree on 2026-08-04 and may only be revised DOWNWARD, in the same commit
// as the move that shrank main.go.
//
// This is deliberately an exact match, not a ceiling: a decrease that leaves the
// baseline stale would let the next increase hide inside the slack.

import (
	"go/ast"
	"go/token"
	"testing"
)

const (
	mainGoRouteRegistrationBaseline = 57
	mainGoFlagDefinitionBaseline    = 303
	mainGoFuncDeclBaseline          = 113
	mainGoTypeSpecBaseline          = 5
)

func TestMainGoDecompositionRatchet(t *testing.T) {
	fset, files := parseEdgePackage(t)
	mainFile, ok := files["main.go"]
	if !ok {
		t.Fatal("main.go not found in package")
	}
	mainOnly := map[string]*ast.File{"main.go": mainFile}

	check := func(what string, got, baseline int) {
		t.Helper()
		switch {
		case got > baseline:
			t.Errorf("main.go now has %d %s (frozen baseline: %d). New %s must go in a sibling file of cmd/edge, not main.go — see docs/dev_advisory_2026-08-03_edge_main_split_plan.md (the ratchet).",
				got, what, baseline, what)
		case got < baseline:
			t.Errorf("main.go is down to %d %s (baseline: %d) — good. Lock in the progress by lowering the baseline const in edge_main_split_ratchet_contract_test.go in this same commit.",
				got, what, baseline)
		}
	}

	packageConsts := edgePackageStringConsts(files)
	check("route registrations", len(collectRouteRegistrationsFrom(t, fset, mainOnly, packageConsts)), mainGoRouteRegistrationBaseline)
	check("flag definitions", len(collectFlagDefinitions(t, fset, mainOnly)), mainGoFlagDefinitionBaseline)
	check("function declarations", countFuncDecls(mainFile), mainGoFuncDeclBaseline)
	check("type declarations", countTypeSpecs(mainFile), mainGoTypeSpecBaseline)
}

func countFuncDecls(file *ast.File) int {
	n := 0
	for _, decl := range file.Decls {
		if _, ok := decl.(*ast.FuncDecl); ok {
			n++
		}
	}
	return n
}

func countTypeSpecs(file *ast.File) int {
	n := 0
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		n += len(gen.Specs)
	}
	return n
}

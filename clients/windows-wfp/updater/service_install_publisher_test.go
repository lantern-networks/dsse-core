package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The manual service-install path must carry the publisher pin into the SCM command line.
// The Windows entry point cannot run on a non-Windows CI host, so inspect only this
// load-bearing wiring; the argument formatter itself is covered by Windows builds.
func TestServiceInstallCarriesPublisherPin(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	foundRegistration := false
	foundPublisher := false
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typ, ok := lit.Type.(*ast.Ident)
		if !ok || typ.Name != "serviceRunFlags" {
			return true
		}
		foundRegistration = true
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "publisher" {
				continue
			}
			value, ok := kv.Value.(*ast.StarExpr)
			if !ok {
				continue
			}
			flagValue, ok := value.X.(*ast.Ident)
			foundPublisher = ok && flagValue.Name == "updatePublisher"
		}
		return true
	})
	if !foundRegistration || !foundPublisher {
		t.Fatal("--service-install does not carry --update-publisher into the SCM service arguments")
	}
}

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// -state-dir promises, in its own help text, that "every config-bearing store persists to
// ‹state-dir›/‹store›.json BY DEFAULT — no per-store flag needed, and a store added later inherits durability
// instead of defaulting to memory". This proves it.
//
// ★ Written because it was not true (2026-08-10). Neither -policy-rule-store nor -asset-catalog-store was
// wired into the state-dir defaulting, so both fell back to in-memory unless a deployment named them by hand.
// The reference control plane named one and not the other, which meant a CP restart kept every authored rule
// and dropped the endpoints those rules reference. That was survivable while rules were Edge-local; once the CP
// became the fleet authority for rules it would have DISTRIBUTED the dangling references — inert on egress, and
// on east-west an empty selector is a wildcard, so per-hop authorization would have quietly widened everywhere.
//
// A safety mechanism whose documented promise is broader than its behaviour is worse than no mechanism: the
// deployments that trusted -state-dir are exactly the ones that would not have set the per-store flag.
//
// Checked at the SOURCE, by variable, because that is the coupling that actually broke: the durability warning
// list and the defaulting block are two places that must name the same store, and nothing tied them together.
func TestStateDirDefaultsCoverEveryConfigStoreInTheDurabilityContract(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	fset := token.NewFileSet()
	if _, perr := parser.ParseFile(fset, "main.go", src, parser.SkipObjectResolution); perr != nil {
		t.Fatalf("parse main.go: %v", perr)
	}
	text := string(src)

	// Every CONFIG-class entry of the durability contract, keyed by the flag VARIABLE it reports on. Matching by
	// variable rather than by the store's file name is deliberate: "policy-rule-store" persists to
	// "policy_rules" and "asset-catalog-store" to "asset_catalog", so a name-derived rule would need a table of
	// exceptions and would silently accept a new store that invented a third convention.
	entry := regexp.MustCompile(`\{flag: "([a-z0-9-]+)", value: \*([A-Za-z0-9_]+)[^}]*class: storeClassConfig`)
	// Both author defaults and role-aware receiver caches honor state-dir.
	// Their path behavior is covered by TestBundleReceiverRejectsExplicitSharedAuthority.
	defaulted := regexp.MustCompile(`\*([A-Za-z0-9_]+) = (?:durableStorePath|configBundleStorePath)\(\*stateDir,`)

	covered := map[string]bool{}
	for _, m := range defaulted.FindAllStringSubmatch(text, -1) {
		covered[m[1]] = true
	}

	entries := entry.FindAllStringSubmatch(text, -1)
	if len(entries) < 10 {
		t.Fatalf("found only %d storeClassConfig entries — the regex has drifted from the source and this test "+
			"would pass vacuously", len(entries))
	}

	var missing []string
	for _, m := range entries {
		flagName, variable := m[1], m[2]
		if !covered[variable] {
			missing = append(missing, flagName+" (*"+variable+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("-state-dir does not default %d OPERATOR-CONFIG store(s), so a deployment that set only "+
			"-state-dir gets them in memory and loses them on restart:\n  %s\n"+
			"Add `*<var> = durableStorePath(*stateDir, *<var>, \"<name>\")` beside the others in main.go.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// The pair that must never diverge, asserted by name because their relationship is not visible from either one
// alone: authored rules address their destinations through the asset catalog. Durable rules plus a volatile
// catalog is not "half the config" — it is rules that resolve to nothing, and on east-west that is permissive.
func TestAuthoredRulesAndTheCatalogTheyReferenceShareDurability(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		`*policyRuleStorePath = durableStorePath(*stateDir, *policyRuleStorePath,`,
		`*assetCatalogStorePath = durableStorePath(*stateDir, *assetCatalogStorePath,`,
		`{flag: "policy-rule-store"`,
		`{flag: "asset-catalog-store"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing from main.go: %s\n"+
				"Rules and the catalog they reference must have the SAME durability — a restart that keeps one "+
				"and drops the other distributes rules pointing at nothing.", want)
		}
	}
}

var _ = ast.Print

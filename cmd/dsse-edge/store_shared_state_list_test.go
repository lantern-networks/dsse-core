package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ★★★ THE LIST MUST MATCH THE CALL SITES, OR A STORE COMES UP EMPTY IN SILENCE (2026-08-21).
//
// durableStorePath may answer "postgres" only for stores whose backend is resolved by cpStateBlobPersister.
// The first attempt rewrote every store's value: the ones that understand it fataled loudly and were fixed in
// minutes, and the ones that take a plain file path took "postgres" as a FILE NAME and started empty without
// a word — /admin/endpoints answered 0 on both Edges and the posture check found both real devices gone from
// the inventory.
//
// A hand-maintained list drifts the first time somebody wires a new store, and the drift is invisible until a
// node comes up empty. So this regenerates it from the call sites and compares.
func TestTheSharedStateListMatchesTheCallSites(t *testing.T) {
	callSite := regexp.MustCompile(`(?s)(?:must)?[Cc][Pp]StateBlobPersister\((.*?)\)`)
	keyLiteral := regexp.MustCompile(`"([a-z_]+)"`)
	durable := regexp.MustCompile(`durableStorePath\([^)]*"([a-z_]+)"\)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	resolvedByPersister := map[string]bool{}
	defaultedByStatePath := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(filepath.Join(".", name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, m := range callSite.FindAllStringSubmatch(string(src), -1) {
			keys := keyLiteral.FindAllStringSubmatch(m[1], -1)
			if len(keys) > 0 {
				resolvedByPersister[keys[len(keys)-1][1]] = true
			}
		}
		for _, m := range durable.FindAllStringSubmatch(string(src), -1) {
			defaultedByStatePath[m[1]] = true
		}
	}
	if len(resolvedByPersister) == 0 || len(defaultedByStatePath) == 0 {
		t.Fatal("the scan found no call sites at all — this gate would pass on an empty tree")
	}

	want := []string{}
	for key := range defaultedByStatePath {
		if resolvedByPersister[key] {
			want = append(want, key)
		}
	}
	sort.Strings(want)

	got := []string{}
	for key := range defaultedByStatePath {
		if storeUnderstandsSharedState(key) {
			got = append(got, key)
		}
	}
	sort.Strings(got)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("storeUnderstandsSharedState has drifted from the call sites.\n  it says:      %v\n  the tree says: %v\n"+
			"A store on the list that is NOT resolved by cpStateBlobPersister will be handed the string \"postgres\" "+
			"as a file name and come up empty without saying so.", got, want)
	}

	// And the claim the list makes about a name it does not know: a store outside the persister's call sites
	// must never be on it, whichever way the list is written.
	if storeUnderstandsSharedState("device_inventory") {
		t.Fatal("device_inventory takes a plain path — putting it on the list is the defect this gate exists for")
	}
}

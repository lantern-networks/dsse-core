package console

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ THERE ARE TWO PLACES A SCREEN IS REGISTERED AND ONLY ONE OF THEM RENDERS IT (2026-09-01, found by
// opening a screen that had just been added and seeing its title, its one-line description, and nothing else).
//
// CUSTOM_VIEWS is a map of custom-view keys to renderer names; it drives the "N screens did not load" banner.
// The dispatch is a separate if-chain further down. A screen present in the map and absent from the chain
// falls through to the GENERIC renderer, which prints the group's title and description and then iterates its
// (empty) endpoint list — so the screen looks like it rendered, the banner says every screen loaded, and
// nothing the screen is for is on the page.
func TestEveryCustomScreenIsInBothRegistries(t *testing.T) {
	body, err := os.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(body)

	start := strings.Index(app, "const CUSTOM_VIEWS = {")
	if start < 0 {
		t.Fatal("CUSTOM_VIEWS is gone; this check needs rewriting rather than deleting")
	}
	end := strings.Index(app[start:], "\n};")
	if end < 0 {
		t.Fatal("could not find the end of CUSTOM_VIEWS")
	}
	entry := regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*:\s*"([A-Za-z0-9_]+)"`)
	missing := []string{}
	for _, m := range entry.FindAllStringSubmatch(app[start:start+end], -1) {
		key, renderer := m[1], m[2]
		if !strings.Contains(app, `group.custom === "`+key+`"`) {
			missing = append(missing, key+" -> "+renderer)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d custom screen(s) are in CUSTOM_VIEWS and NOT in the dispatch, so they render as a title "+
			"and a description with nothing under them: %s", len(missing), strings.Join(missing, ", "))
	}
}

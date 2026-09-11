package main

// bypass_dest_merge.go — how the never-steer DESTINATIONS from the package and from the signed install profile
// combine. Untagged (no //go:build windows) so the rule is unit-tested on any platform; the call site is in
// main_windows.go, which is where the reasoning for merging rather than replacing is written down.

import (
	"fmt"
	"strings"
)

// mergeBypassDests combines the destinations the PACKAGE baked into the service arguments with the ones a
// verified install profile names. Returns the CSV the capture config parses, and a sentence to log when the
// two sources are not the same thing (empty when there is nothing worth saying).
//
// Duplicates are dropped, packaged order first: the same destination named by both is one rule, and a repeat
// would otherwise appear twice in the startup line operators read to see what is exempt.
func mergeBypassDests(packaged string, profile []string) (csv string, note string) {
	seen := map[string]bool{}
	var out []string
	add := func(src []string) int {
		n := 0
		for _, s := range src {
			if s = strings.TrimSpace(s); s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
				n++
			}
		}
		return n
	}
	fromPackage := add(strings.Split(packaged, ","))
	add(profile)

	prof := strings.TrimSpace(strings.Join(profile, ","))
	switch {
	case fromPackage > 0 && prof != "":
		return strings.Join(out, ","), fmt.Sprintf("bypass destinations MERGED — packaged %q + profile %q. "+
			"The profile can add destinations but cannot remove a packaged one; reinstall the package to change "+
			"that set.", strings.TrimSpace(packaged), prof)
	case fromPackage > 0:
		return strings.Join(out, ","), fmt.Sprintf("bypass destinations come from the PACKAGE (%q); the profile "+
			"names none. These destinations are NOT steered on this device.", strings.TrimSpace(packaged))
	default:
		return strings.Join(out, ","), ""
	}
}

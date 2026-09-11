package main

// authored_exclusions_are_applied.go -- an exclusion an organization authored has to reach the device that
// is supposed to honour it.
//
// ★★★ MEASURED 2026-08-30. The Console authors a deployment's never-steer list into
// deployment.steer_exclusions, the Edge fills that block per organization when it issues a profile, and this
// agent read a DIFFERENT field: the profile's top-level bypass_apps, which is filled from whatever the
// profile-issuing request supplied. So an operator could author an exclusion, see it in the signed profile
// the device verified, and watch the device steer the application anyway. Nothing was wrong with the
// document. It was read from the other field.
//
// This box spent 2026-08-30 steering the session that was doing the measuring, with no exclusion at all --
// Sakura Foods had authored none, and had it authored some, this device would not have applied them.

import "strings"

// mergeIdentifiers joins identifier LISTS, keeping order and dropping repeats and blanks.
//
// ★★★ IT TAKES LISTS, NOT COMMA-SEPARATED STRINGS (2026-08-30, caught by --mode bypass-observe before arming).
//
// The authored exclusions arrive from the signed profile as a JSON ARRAY, where a comma inside one identifier
// is just a character. Flattening that array into a comma-separated string and splitting it again destroys
// any identifier that legitimately contains a comma -- and subject: identifiers are X.500 Organization names,
// where a comma is ORDINARY: "Anthropic, PBC", "Example, Inc.". Measured:
//
//	authored : subject:Anthropic, PBC
//	applied  : [... subject:anthropic] [pbc]      <- two rules, neither of which matches anything
//	bypass-observe: pid=16388 image=<the excluded tool>   <- no BYPASS mark
//
// So the strongest practical identifier form this agent offers was unusable for most real organizations, and
// the failure is silent: the Console shows the exclusion, the profile carries it, the device reports applying
// N of them, and the process stays steered. The peer session hit the same shape in its authoring tool the
// same hour -- a comma is the one separator an X.500 name is guaranteed to contain.
//
// The --bypass-app FLAG stays comma-separated: that is an operator typing a list, and it is documented. The
// split happens THERE, once, and never again to something already parsed.
func mergeIdentifiers(lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range lists {
		for _, raw := range list {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			// Identifier forms are matched case-insensitively downstream (publisher:, subject:, signed:), so
			// two spellings of one identifier are one entry here rather than two rules to reason about.
			key := strings.ToLower(v)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

// mergeCSV is the string-shaped form, for the operator's comma-separated flag only.
//
// ★ MERGED, NOT REPLACED, because the two lists have different authors: bypass_apps is what the
// profile-issuing request said, steer_exclusions is what the ORGANIZATION authored in the Console. If either
// could replace the other, one operator's screen would quietly unprotect what another operator's screen
// protected -- and neither operator would see it happen. Same rule as the bypass DESTINATIONS below it in
// main_windows.go, which were inert for the same reason until 2026-08-17.
func mergeCSV(lists ...string) string {
	parsed := make([][]string, 0, len(lists))
	for _, l := range lists {
		parsed = append(parsed, trimmedNonEmptyCSV(l))
	}
	return strings.Join(mergeIdentifiers(parsed...), ",")
}

// trimmedNonEmptyCSV splits a comma-separated list, trims each entry and drops the empties -- a trailing
// comma or a blank between two commas is a typo, not an identifier that matches everything.
func trimmedNonEmptyCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// effectiveBypassApps is the identifier list this device actually applies.
//
// The FLAG is comma-separated because an operator types it; that is the one place a comma means "next
// identifier", and it is split exactly once, here. Everything the signed profile authored is already a list
// and is never split again -- which is what lets `subject:Anthropic, PBC` survive.
//
// A profile that names identifiers REPLACES the flag rather than merging with it: the flag is what this
// install was built with, the profile is what the organization authored now, and a stale packaged default
// must not resurrect itself alongside a deliberate list. When the profile names none, the flag stands.
func effectiveBypassApps(flag string, authored []string) []string {
	if len(authored) > 0 {
		return mergeIdentifiers(authored)
	}
	return mergeIdentifiers(trimmedNonEmptyCSV(flag))
}

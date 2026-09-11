// priority_config.go — turning an OPERATOR'S written region preference into RegionEndpoint.Priority.
//
// This lives beside the selector, not beside any one client, because the rule it encodes is the selector's:
// lower is preferred, 1 is the highest, and 0 means UNSPECIFIED and ranks LAST (effectiveRegionPriority). Every
// place a human writes a preference has to agree with that rule, and the ways to disagree are all silent — so
// there is one parser here rather than one per caller. Today that is the profile-authoring tool and the Windows
// agent's bootstrap flag; the macOS agent mirrors the same rule in Swift.
package regionfailover

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePriority parses `region=N,region=N` (region ids lowercased, whitespace tolerated) into the map the
// profile carries and ApplyPriority consumes. Empty input is not an error and yields nil: no preference
// configured is the ordinary state, and every fleet that exists today is in it.
//
// It REFUSES rather than repairs in three cases, each because the repair would be silent and wrong:
//
//   - a form that is not region=N, or an N that is not a whole number
//   - N <= 0. The selector reads 0 as UNSPECIFIED and ranks it LAST, so an operator writing `tokyo=0` reaching
//     for "first" — zero-based is the ordinary instinct — would get the exact inverse of what they wrote, on
//     every device the profile reaches, with a healthy log and a working tunnel to the wrong PoP.
//   - the same region twice. Two priorities for one region is a contradiction the operator wrote; honouring
//     either one silently decides which of their two intentions to keep.
func ParsePriority(raw string) (map[string]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := map[string]int{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, prio, ok := strings.Cut(entry, "=")
		region = strings.ToLower(strings.TrimSpace(region))
		prio = strings.TrimSpace(prio)
		if !ok || region == "" || prio == "" {
			return nil, fmt.Errorf("region priority %q must be region=N (lower is preferred, 1 is highest)", entry)
		}
		n, err := strconv.Atoi(prio)
		if err != nil {
			return nil, fmt.Errorf("region priority %q: %q is not a whole number", entry, prio)
		}
		if err := checkRank(entry, n); err != nil {
			return nil, err
		}
		if _, dup := out[region]; dup {
			return nil, fmt.Errorf("region priority: %q is given two priorities", region)
		}
		out[region] = n
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// ValidatePriority checks an ALREADY-DECODED map — the form the signed install profile carries, where nobody
// went through ParsePriority. Same rule, so a profile authored by hand cannot express what the flag refuses.
// It returns every problem rather than the first, because the caller is usually a human being told to fix a
// document, and one error per edit-and-resign cycle is an expensive way to find three.
func ValidatePriority(pri map[string]int) []error {
	if len(pri) == 0 {
		return nil
	}
	regions := make([]string, 0, len(pri))
	for r := range pri {
		regions = append(regions, r)
	}
	sort.Strings(regions) // deterministic: the same document reports the same errors in the same order
	var errs []error
	seen := map[string]string{} // normalised id -> the first spelling that produced it
	for _, r := range regions {
		if strings.TrimSpace(r) == "" {
			errs = append(errs, fmt.Errorf("region priority: an entry has an empty region id"))
			continue
		}
		// Capitals and surrounding space are NOT reported: ApplyPriority normalises both sides, so `JP-Tokyo`
		// works and matches what the macOS agent does with the same document. What IS reported is two spellings
		// of ONE region carrying different ranks, because that is a contradiction the operator wrote and the
		// resolution (the stronger rank wins) is ours, not theirs.
		k := normalizeRegionID(r)
		if first, already := seen[k]; already {
			if pri[first] != pri[r] {
				errs = append(errs, fmt.Errorf("region priority: %q and %q are the same region with different "+
					"ranks (%d and %d); the stronger (lower) rank is used", first, r, pri[first], pri[r]))
			}
		} else {
			seen[k] = r
		}
		if err := checkRank(r, pri[r]); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// checkRank is the single statement of "what is a rank", shared by both entry points so the flag and the
// profile cannot drift into accepting different things.
func checkRank(what string, n int) error {
	if n <= 0 {
		return fmt.Errorf("region priority %q: %d is not a rank — 1 is the highest priority, and 0 means "+
			"UNSPECIFIED to the selector, which ranks LAST", what, n)
	}
	return nil
}

// ApplyPriority stamps the operator's preference onto endpoints the EDGE supplied, by lookup.
//
// ★ It returns a new slice and NEVER grows it. The served list IS the residency boundary, and this function is
// on the wrong side of it to widen one: a configured region the Edge did not serve is not added. That is what
// makes it safe for the preference to be less trusted than the list — whatever an operator writes, it can only
// reorder regions the Edge already permitted.
//
// A region not named keeps Priority 0 (unspecified), which the selector ranks last, so a partially-configured
// fleet still prefers the regions that were ranked. A nil/empty preference leaves every endpoint exactly as it
// was, so callers may apply it unconditionally on every path a list arrives by.
// ★ BOTH SIDES of the lookup are normalised, and that is a fix, not a tidy-up. Until 2026-08-10 only the
// SERVED region id was lowercased, so a preference written `JP-Tokyo` was not wrong-looking — it was INERT. The
// macOS agent lowercased its keys and the same document therefore did two different things on two platforms,
// which is worse than either behaviour alone: an operator who tests on one Mac ships a file that silently
// configures nothing on every Windows box. Normalising here is what makes one written document mean one thing.
func ApplyPriority(eps []RegionEndpoint, pri map[string]int) []RegionEndpoint {
	if len(eps) == 0 {
		return eps
	}
	norm := normalizePriorityKeys(pri)
	out := make([]RegionEndpoint, 0, len(eps))
	for _, ep := range eps {
		if n, ok := norm[normalizeRegionID(ep.Region)]; ok {
			ep.Priority = n
		}
		out = append(out, ep)
	}
	return out
}

// normalizeRegionID is the ONE definition of how a written region id is matched against a served one. Both the
// lookup and the validation go through it, so "what counts as the same region" cannot be answered two ways.
func normalizeRegionID(r string) string { return strings.ToLower(strings.TrimSpace(r)) }

// normalizePriorityKeys folds written ids onto their matched form. On a collision — two spellings of one region
// carrying DIFFERENT ranks — it keeps the STRONGER (numerically lower) preference. That is a repair, which this
// file otherwise refuses to do, and it is bounded on purpose: ValidatePriority reports the collision so the
// operator is told, and the fallback has to be deterministic because map iteration order is not. Preferring the
// stronger rank means the outcome never depends on which spelling the author happened to write first.
func normalizePriorityKeys(pri map[string]int) map[string]int {
	if len(pri) == 0 {
		return nil
	}
	out := make(map[string]int, len(pri))
	for r, n := range pri {
		k := normalizeRegionID(r)
		if prev, ok := out[k]; ok && prev <= n {
			continue
		}
		out[k] = n
	}
	return out
}

// RenderPriority formats a preference for a log line, ordered BY PREFERENCE rather than by map iteration so two
// machines with the same configuration print the same string and can be compared. Empty when nothing is set.
func RenderPriority(pri map[string]int) string {
	if len(pri) == 0 {
		return ""
	}
	type kv struct {
		region string
		prio   int
	}
	all := make([]kv, 0, len(pri))
	for r, p := range pri {
		all = append(all, kv{r, p})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].prio != all[j].prio {
			return all[i].prio < all[j].prio
		}
		return all[i].region < all[j].region
	})
	parts := make([]string, 0, len(all))
	for _, e := range all {
		parts = append(parts, fmt.Sprintf("%s=%d", e.region, e.prio))
	}
	return strings.Join(parts, ",")
}

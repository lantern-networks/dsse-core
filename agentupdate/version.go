// Package agentupdate is step 1 of docs/agent_auto_update_design.ja.md: the signed update manifest, and the
// rules under which an endpoint agent will REFUSE to act on one.
//
// The framing that matters: an auto-update channel is a permanent privileged-code-execution path to every
// managed endpoint, worth more to an attacker than anything DSSE itself protects. So this package is written
// as the set of conditions under which an update CANNOT happen, not as a delivery mechanism. Every check
// fails closed — a manifest that cannot be fully verified leaves the agent running the build it already has,
// which is the safe outcome, not an outage.
package agentupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed agent version: the semver core, an optional pre-release, and the build metadata.
//
// Build metadata is what this fleet actually stamps, and it is NOT ordered — the macOS agent stamps a build
// timestamp ("0.1.0+20260808104421") while the Windows agent stamps a commit ("0.1.0+fb5ed5e7"). Semver says
// build metadata is ignored when comparing, and that is the only defensible rule here: there is no total order
// over "20260808104421" and "fb5ed5e7".
//
// The consequence is a real limitation, stated rather than papered over: TWO BUILDS OF THE SAME VERSION ARE
// INDISTINGUISHABLE TO A ROLLOUT. Moving a fleet from 0.1.0+a to 0.1.0+b cannot be expressed; shipping a fix
// requires bumping the VERSION file. That is the correct trade — the alternative is an ordering rule that
// silently means something different on each platform — but it means the release process, not this package,
// is what makes a rollout possible.
type Version struct {
	Major, Minor, Patch int
	PreRelease          string // "" for a release; "dev" in the unstamped 0.0.0-dev default
	Build               string // ignored in every comparison; kept so callers can display/log it
}

// Dirty reports whether the build metadata carries the ".dirty" marker that build_stamp.sh adds when the
// working tree had modifications. An artefact that matches no commit is precisely the one that must never be
// published as a release target — see Manifest.Validate.
func (v Version) Dirty() bool {
	for _, part := range strings.Split(v.Build, ".") {
		if strings.EqualFold(part, "dirty") {
			return true
		}
	}
	return false
}

// Core is the comparable part of the version, without build metadata.
func (v Version) Core() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		s += "-" + v.PreRelease
	}
	return s
}

func (v Version) String() string {
	if v.Build == "" {
		return v.Core()
	}
	return v.Core() + "+" + v.Build
}

// ParseVersion parses the "<major>.<minor>.<patch>[-prerelease][+build]" shape both agents report. It is
// strict: an unparseable version is an error and never a zero value, because a version that silently reads as
// 0.0.0 would compare as older than everything and make every endpoint a candidate for an update it may not
// be entitled to. "Cannot read the version" and "is running an old version" must not be the same value —
// that conflation is the silent-failure shape this codebase keeps finding.
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, fmt.Errorf("%w: version is empty", ErrMalformed)
	}
	var v Version
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		v.Build = raw[i+1:]
		raw = raw[:i]
		if v.Build == "" {
			return Version{}, fmt.Errorf("%w: version %q has an empty build metadata field", ErrMalformed, s)
		}
	}
	if i := strings.IndexByte(raw, '-'); i >= 0 {
		v.PreRelease = raw[i+1:]
		raw = raw[:i]
		if v.PreRelease == "" {
			return Version{}, fmt.Errorf("%w: version %q has an empty pre-release field", ErrMalformed, s)
		}
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: version %q is not major.minor.patch", ErrMalformed, s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("%w: version %q has a non-numeric component %q", ErrMalformed, s, p)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

// SameVersion reports whether two version strings name the same release, IGNORING build metadata — the rule
// this package already states everywhere else and, until 2026-08-11, applied nowhere that mattered.
//
// ★ WHAT IT COST TO NOT HAVE THIS. A manifest offers "0.2.1"; the Mac that installs it reports
// "0.2.1+20260811035942", because the agent's version is CFBundleShortVersionString plus the build stamp.
// Reconcile compared those two as STRINGS, so a successful update could never be confirmed: the attempt stayed
// open, Run then declared it interrupted, wrote `failed`, and — the phase being `executing` — told the operator
// that this box's NETWORK must be checked. Read off a live device's journal, on a machine that had updated
// perfectly and was inspecting traffic. The ten-minute install grace added earlier did not fix this; it delayed
// it by ten minutes.
//
// The same conflation reaches the poison map: a version refused as "0.2.1+2026…" would never match a manifest
// offering "0.2.1", so a device that had just been rolled back would take the bad build again on its next tick.
//
// An UNPARSEABLE version falls back to exact string equality rather than being called equal to anything. Two
// things this must never do are treat garbage as a match, and treat "cannot read the version" as an answer.
func SameVersion(a, b string) bool {
	as, bs := strings.TrimSpace(a), strings.TrimSpace(b)
	if as == "" || bs == "" {
		return false
	}
	av, aerr := ParseVersion(as)
	bv, berr := ParseVersion(bs)
	if aerr != nil || berr != nil {
		return as == bs
	}
	return CompareVersions(av, bv) == 0
}

// CompareVersions orders two versions: -1 if a < b, 0 if equal, +1 if a > b. Build metadata is ignored
// (see Version). A pre-release sorts BELOW the same core release, so the unstamped 0.0.0-dev default is older
// than every real build — an unstamped agent is correctly seen as needing an update rather than as current.
func CompareVersions(a, b Version) int {
	for _, pair := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.PreRelease == b.PreRelease:
		return 0
	case a.PreRelease == "": // a is the release, b is a pre-release of it
		return 1
	case b.PreRelease == "":
		return -1
	default:
		return comparePreRelease(a.PreRelease, b.PreRelease)
	}
}

// comparePreRelease orders two pre-release strings the way semver defines it, which is NOT the way strings
// compare.
//
// ★ rc.10 SORTED BELOW rc.9 (2026-08-13, twenty-ninth review). The comparison was `a.PreRelease <
// b.PreRelease`, so publishing 0.3.0-rc.10 to a fleet on 0.3.0-rc.9 made every device refuse it as
// ErrNotAnUpgrade — the rollout simply stopped, with no reason shown anywhere — and a replayed rc.9 would
// pass the downgrade guard in the other direction. Ten is the first release where this bites, which is late
// enough that the fleet is already relying on it.
//
// The rule: dot-separated identifiers, compared left to right. All-digit identifiers compare NUMERICALLY and
// rank below alphanumeric ones; a shorter prefix ranks below its longer extension.
func comparePreRelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aNum := strconv.Atoi(as[i])
		bn, bNum := strconv.Atoi(bs[i])
		anIsNum, bnIsNum := aNum == nil, bNum == nil
		switch {
		case anIsNum && bnIsNum:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case anIsNum:
			return -1 // numeric identifiers have lower precedence than alphanumeric ones
		case bnIsNum:
			return 1
		case as[i] < bs[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	default:
		return 0
	}
}

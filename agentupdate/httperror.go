package agentupdate

import (
	"io"
	"strings"
	"unicode"
)

// httperror.go — what a failed HTTP response is allowed to contribute to an endpoint's account of itself.

// errorBodyLimit bounds what a failed fetch may write into an endpoint's log. Long enough for the sentences
// this product's own Edge writes, short enough that a hostile or broken origin cannot use a failed download as
// a channel into the log file of a machine running with system privileges.
const errorBodyLimit = 300

// DescribeHTTPErrorBody renders a failed response's body for a human, or "" when there is nothing to say.
//
// ★ IT EXISTS BECAUSE A STATUS CODE IS NOT A DIAGNOSIS (2026-08-11, measured while breaking the artifact path
// on purpose). Two different 404s reach a device from the same endpoint: an Edge that PREDATES the artifact
// route answers with net/http's own "404 page not found", and an Edge that has the route but lost the file
// answers "the published manifest's artifact is not on this edge". The repairs are different — rebuild the
// Edge, or put the package where the manifest says it is — and the device is where somebody is standing when
// they need to know which. Dropping the body made them identical, and I read the first as the second.
//
// It lives here rather than in either platform's staging code because it is one decision. A device's account of
// why it could not update must not depend on which operating system is telling it.
//
// Whitespace is collapsed and control characters dropped: this string ends up in somebody's log, and the body
// is not ours — an origin does not get to reformat it or to smuggle terminal escapes through it.
func DescribeHTTPErrorBody(r io.Reader) string {

	raw, err := io.ReadAll(io.LimitReader(r, errorBodyLimit+1))
	if err != nil || len(raw) == 0 {
		return ""
	}
	truncated := len(raw) > errorBodyLimit
	if truncated {
		raw = raw[:errorBodyLimit]
	}
	var b strings.Builder
	space := false
	for _, r := range string(raw) {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ':
			space = true
		case unicode.IsControl(r):
			// dropped
		default:
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		}
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return ""
	}
	if truncated {
		s += "…"
	}
	return " — " + s
}

// ArtifactVersionHeader is how the Edge names the version whose bytes it is handing over.
//
// The artifact URL deliberately carries no version — nothing a caller controls should select a file on a
// server. The cost is that a device whose manifest is a release behind downloads the CURRENT artifact and
// refuses it against its own manifest, in the words of a substitution attack. This header exists so the
// endpoint can tell those two apart and say which one it is.
//
// A HINT, NEVER AN AUTHORITY. The digest in the signed manifest is what decides whether bytes may run, and
// nothing here changes that: a lying header produces the same refusal, with a sentence that mentions the lie.
const ArtifactVersionHeader = "X-Dsse-Agent-Update-Version"

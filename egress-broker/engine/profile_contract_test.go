package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The impersonation profile is named in four places: this package's fallback default, both Dockerfiles' ENV, and
// the README. On 2026-08-04 three of them said chrome146 and the code said chrome116, and the disagreement was
// reported as a live defect — it was not (the image ENV wins), but establishing that took reading four files and
// a running container. This test makes the disagreement itself fail, so the next reader does not have to.
//
// It deliberately does NOT assert which profile is correct. Bumping to a newer generation is a real operation;
// this only demands that when it happens, every source moves together.

var profilePattern = regexp.MustCompile(`curl_chrome\d+[a-z_]*`)

func TestImpersonateProfileAgreesAcrossEverySource(t *testing.T) {
	sources := map[string]string{
		"code default (impersonateBinary)": impersonateBinaryDefault(t),
		"Dockerfile ENV":                   envProfileFrom(t, "Dockerfile"),
		"Dockerfile.runtime ENV":           envProfileFrom(t, "Dockerfile.runtime"),
		"Dockerfile.runtime.amd64 ENV":     envProfileFrom(t, "Dockerfile.runtime.amd64"),
		"README documented default":        readmeProfile(t),
	}
	var first, firstName string
	for name, got := range sources {
		if got == "" {
			t.Errorf("%s: no impersonation profile found — a source that names nothing cannot be kept in step", name)
			continue
		}
		if first == "" {
			first, firstName = got, name
			continue
		}
		if got != first {
			t.Errorf("impersonation profile disagreement: %s says %q but %s says %q", firstName, first, name, got)
		}
	}
	// Only claim agreement when there was some. A "all sources agree" line printed by a failing test is the kind
	// of reassuring output that gets read instead of the failure above it.
	if first != "" && !t.Failed() {
		t.Logf("all %d sources agree on %s", len(sources), first)
	}
}

// The profile must also exist in the engine that ships. Pointing every source at the same non-existent target
// would satisfy the agreement check above and fail at runtime with a 502 from curl_easy_impersonate — there is no
// fallback, so that is every decrypt-all flow. Skipped when the (gitignored) engine artifacts are not fetched.
func TestImpersonateProfileExistsInTheShippedEngine(t *testing.T) {
	want := strings.TrimPrefix(impersonateBinaryDefault(t), "curl_")
	entries, err := os.ReadDir(filepath.Join(brokerRoot, "cli"))
	if err != nil {
		t.Skipf("engine CLI not fetched (see README build steps): %v", err)
	}
	for _, e := range entries {
		if e.Name() == "curl_"+want {
			t.Logf("profile %s present in the shipped engine", want)
			return
		}
	}
	var have []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "curl_chrome") {
			have = append(have, e.Name())
		}
	}
	t.Errorf("profile curl_%s is not in the shipped engine; available: %v", want, have)
}

// impersonateBinaryDefault reads the fallback the code returns when the environment says nothing. It clears the
// env for the duration so a developer's shell cannot make this test pass.
func impersonateBinaryDefault(t *testing.T) string {
	t.Helper()
	t.Setenv("EGRESS_IMPERSONATE_BIN", "")
	return ImpersonateBinary()
}

func envProfileFrom(t *testing.T, dockerfile string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join(brokerRoot, dockerfile)))
	if err != nil {
		t.Fatalf("read %s: %v", dockerfile, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ENV ") && strings.Contains(line, "EGRESS_IMPERSONATE_BIN") {
			return profilePattern.FindString(line)
		}
	}
	return ""
}

// readmeProfile reads the line documenting the default, not merely any mention of a profile — the README discusses
// several by name.
func readmeProfile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(brokerRoot, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "EGRESS_IMPERSONATE_BIN") && strings.Contains(line, "default") {
			return profilePattern.FindString(line)
		}
	}
	return ""
}

// brokerRoot is the broker module root, where the Dockerfiles, README and the fetched `cli/` engine live. The
// engine moved down into this package so the Edge can import it; the artifacts it must agree with did not, so
// the contract test reaches up one level rather than the sources being scattered to sit next to it.
const brokerRoot = ".."

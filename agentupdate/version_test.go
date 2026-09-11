package agentupdate

import "testing"

// ★ rc.10 SORTED BELOW rc.9 (2026-08-13, twenty-ninth review). A string comparison put 0.3.0-rc.10 below
// 0.3.0-rc.9, so publishing the tenth release candidate to a fleet on the ninth stopped the rollout with
// ErrNotAnUpgrade on every device and no reason shown — and a replayed rc.9 passed the downgrade guard.
func TestPreReleaseIdentifiersCompareNumericallyNotAsText(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.3.0-rc.10", "0.3.0-rc.9", 1},
		{"0.3.0-rc.9", "0.3.0-rc.10", -1},
		{"0.3.0-rc.2", "0.3.0-rc.2", 0},
		// A numeric identifier ranks below an alphanumeric one, per semver.
		{"0.3.0-rc.1", "0.3.0-rc.alpha", -1},
		// A shorter prefix ranks below its longer extension.
		{"0.3.0-rc", "0.3.0-rc.1", -1},
		// And the release itself is still above any pre-release of it.
		{"0.3.0", "0.3.0-rc.10", 1},
	} {
		av, err := ParseVersion(c.a)
		if err != nil {
			t.Fatalf("%s: %v", c.a, err)
		}
		bv, err := ParseVersion(c.b)
		if err != nil {
			t.Fatalf("%s: %v", c.b, err)
		}
		if got := CompareVersions(av, bv); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

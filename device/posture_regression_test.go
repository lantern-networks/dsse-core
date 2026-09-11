package device

import "testing"

func TestPostureRegressed(t *testing.T) {
	cases := []struct {
		prev, cur string
		want      bool
	}{
		{"managed", "noncompliant", true}, // regression
		{"trusted", "unknown", true},      // regression
		{"managed", "managed", false},     // unchanged
		{"noncompliant", "noncompliant", false},
		{"noncompliant", "managed", false}, // improvement, not regression
		{"", "noncompliant", false},        // never-trusted, no standing access to revoke
		{"compliant", "low", true},
	}
	for _, c := range cases {
		if got := PostureRegressed(c.prev, c.cur); got != c.want {
			t.Fatalf("PostureRegressed(%q,%q)=%v want %v", c.prev, c.cur, got, c.want)
		}
	}
	if !TrustLevelIsManaged("managed") || TrustLevelIsManaged("noncompliant") || TrustLevelIsManaged("") {
		t.Fatalf("TrustLevelIsManaged mismatch")
	}
}

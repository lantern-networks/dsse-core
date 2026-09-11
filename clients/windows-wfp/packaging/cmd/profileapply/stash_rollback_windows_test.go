//go:build windows

package main

import "testing"

// TestParseVersionOutput guards the string that becomes a filename and, months later, a lookup key. The
// failure this prevents is quiet: a key with a stray token in it stores real material under a name nothing
// will ever ask for, so the box looks stocked and refuses every update anyway.
func TestParseVersionOutput(t *testing.T) {
	ok := []struct {
		name string
		out  string
		want string
	}{
		{"bare", "0.1.0+2e39256d\n", "0.1.0+2e39256d"},
		{"crlf", "0.1.0+2e39256d\r\n", "0.1.0+2e39256d"},
		{"dirty tree", "0.1.0+2e39256d.dirty\n", "0.1.0+2e39256d.dirty"},
		{"no trailing newline", "0.1.0", "0.1.0"},
		{"leading blank lines", "\n\n0.2.0\n", "0.2.0"},
		// Anything the runtime decides to print after the version must not reach the key.
		{"trailing noise line", "0.1.0\nsome warning from the runtime\n", "0.1.0"},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseVersionOutput(tc.out)
			if err != nil {
				t.Fatalf("parseVersionOutput(%q) errored: %v", tc.out, err)
			}
			if got != tc.want {
				t.Fatalf("parseVersionOutput(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}

	bad := []struct {
		name string
		out  string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		// Refused rather than trimmed into shape: whitespace means this was not a version line at all, and
		// guessing which token is the version is how you invent a key nothing looks up.
		{"banner form", "dsse-steer version 0.1.0\n"},
		{"version with trailing comment", "0.1.0 (dev build)\n"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseVersionOutput(tc.out); err == nil {
				t.Fatalf("parseVersionOutput(%q) = %q, want an error", tc.out, got)
			}
		})
	}
}

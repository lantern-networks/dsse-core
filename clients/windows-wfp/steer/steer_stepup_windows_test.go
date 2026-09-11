//go:build windows

package main

import "testing"

// sanitizeResource must keep host:port-safe characters and drop anything that could break out of the
// PowerShell toast string literal (quotes, $, ;, backticks, spaces) -- the injection guard for the balloon.
func TestSanitizeResource(t *testing.T) {
	// Valid host:port forms pass through unchanged.
	for _, ok := range []string{"203.0.113.9:3389", "h.example.com:3389", "[2001:db8::1]:445"} {
		if got := sanitizeResource(ok); got != ok {
			t.Errorf("sanitizeResource(%q) = %q, want unchanged", ok, got)
		}
	}
	// Injection-dangerous characters (quotes, $, ;, backtick, parens, spaces, #) must be stripped so the
	// value cannot break out of the PowerShell toast string literal.
	for _, danger := range []rune{'\'', '"', '$', ';', '`', '(', ')', ' ', '#', '\n', '&', '|'} {
		in := "host" + string(danger) + "evil:22"
		if got := sanitizeResource(in); got != "hostevil:22" {
			t.Errorf("sanitizeResource(%q) = %q, want danger char %q stripped", in, got, string(danger))
		}
	}
}

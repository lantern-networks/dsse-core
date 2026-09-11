package main

import (
	"strings"
	"testing"
)

// ★★★ THE EDGE IS A RELYING PARTY FOR BOTH KINDS OF CREDENTIAL (2026-08-23).
//
// Taking the admin-auth database off the enforcement Edges left them able to resolve a session cookie the
// control plane minted — and nothing else. An API token lives in the same store, so every automation
// authenticating with a bearer started getting 401 from an Edge. Measured on the lab's own posture check: six
// readings lost in one run, and the failures read as missing data rather than as refused authentication.
//
// Read from the source, because building the real resolution chain needs most of main().

func TestAnEdgeIntrospectsBothCredentialKindsAgainstTheAuthority(t *testing.T) {
	src := readSourceFile(t, "main.go")
	if !strings.Contains(src, "adminSessionAuthority.introspect(") {
		t.Fatal("nothing introspects a session cookie against the authority: an Edge with no local session " +
			"store would refuse every administrator the control plane signed in")
	}
	if !strings.Contains(src, "adminSessionAuthority.introspectAPIToken(") {
		t.Fatal("nothing introspects an API TOKEN against the authority: an Edge with no local auth store " +
			"refuses every automation that authenticates with a bearer, and the refusal reads as missing data")
	}
}

// The two paths must not stand in for one another. A cookie that resolves to something which is not a session
// is not a session; a bearer that resolves to a session means the authority answered about something other
// than what was sent.
func TestTheTwoIntrospectionsRefuseEachOthersAnswers(t *testing.T) {
	src := readSourceFile(t, "admin_session_authority.go")
	if !strings.Contains(src, `parsed.AuthMethod != "admin_session"`) {
		t.Fatal("the cookie path no longer requires the authority to describe a session")
	}
	if !strings.Contains(src, `parsed.AuthMethod == "admin_session"`) {
		t.Fatal("the api-token path does not refuse a session answer: one credential's resolution could stand " +
			"in for another's")
	}
}

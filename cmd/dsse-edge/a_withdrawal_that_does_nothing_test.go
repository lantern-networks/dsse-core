package main

import (
	"os"
	"strings"
	"testing"
)

// ★★ A WITHDRAWAL THAT DOES NOTHING ANSWERED 200 (2026-08-22, found while walking the envelope).
//
// Every field on PUT /admin/operator-delegation is a pointer, so that "not mentioned" and "set to false" stay
// different. That is right, and it made a body naming NONE of them a silent success. The trap is one field
// name apart: the tenant record calls this operator_managed and GET /admin/tenants prints it that way, so a
// caller reading the record and writing back the name it saw sends operator_managed — and is told it worked.
//
// For this control that is the worst outcome available: a customer who believes they revoked their provider's
// standing access, and did not.
func TestADelegationBodyThatChangesNothingIsRefused(t *testing.T) {
	raw, err := os.ReadFile("operator_access_routes.go")
	if err != nil {
		t.Fatalf("read the routes: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, `mux.HandleFunc("PUT /admin/operator-delegation"`)
	if start < 0 {
		t.Fatal("the delegation route is gone — this gate is reading the wrong file")
	}
	end := strings.Index(src[start+10:], "mux.HandleFunc(")
	handler := src[start:]
	if end > 0 {
		handler = src[start : start+10+end]
	}
	if !strings.Contains(handler, "body.Managed == nil && body.ElevationNeedsApproval == nil") {
		t.Fatal("a delegation body naming no recognised field is still answered as a success")
	}
	// ★ THE REFUSAL HAS TO NAME THE CONFUSION, or the caller retries the same wrong spelling.
	if !strings.Contains(handler, "operator_managed") {
		t.Fatal("the refusal does not mention operator_managed, which is the spelling the record uses and the " +
			"one a caller will send")
	}
	// ★ AND THE FIELDS STAY POINTERS. Making them plain bools would fix the 200 by making "not mentioned" mean
	// false — which would turn a request that only changes the approval flag into a silent WITHDRAWAL.
	for _, want := range []string{"Managed                  *bool", "ElevationNeedsApproval   *bool"} {
		if !strings.Contains(handler, want) {
			t.Fatalf("%q is no longer a pointer: omitting it would now read as false, and a request that only "+
				"sets the approval flag would withdraw the delegation", want)
		}
	}
}

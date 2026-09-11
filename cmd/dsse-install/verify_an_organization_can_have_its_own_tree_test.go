package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ THE CHECK BESIDE THIS ONE CERTIFIED A DEPLOYMENT THAT COULD NEVER SEPARATE TWO CUSTOMERS (2026-08-27).
// "the deployment inspects under ONE authority — ok" is fleet consistency and reads as an endorsement of the
// one thing an organization must never have. This asks the other question, and it must FAIL on the shape that
// was walked: a control plane with no store for the authorities organizations delegate to it.
func TestADeploymentWithNowhereToKeepAnOrganizationsAuthorityFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"interception is not enabled on this node, so it cannot say what this organization's traffic is inspected under"}`))
	}))
	defer srv.Close()

	got := verifyAnOrganizationCanHaveItsOwnTree(srv.Client(), srv.URL, "tok")
	if len(got) != 1 {
		t.Fatalf("expected one answer, got %d", len(got))
	}
	if got[0].ok {
		t.Fatalf("a control plane with nowhere to keep an organization's authority was passed: %s", got[0].note)
	}
	// The finding has to name the flag, or an operator is told they have a problem and not what to do.
	for _, want := range []string{"-tenant-interception-authority-store", "shared root"} {
		if !strings.Contains(got[0].note, want) {
			t.Errorf("the finding does not mention %q: %s", want, got[0].note)
		}
	}
}

// ★ THE CONTROL, AND IT IS THE ANSWER THAT LOOKS LIKE AN ERROR. A control plane declining an Edge's question
// — "I hold organizations' authorities but serve no traffic" — is exactly the separation being asked about.
// Without this the check would be satisfied by refusing everything.
func TestAControlPlaneThatHoldsOrganizationsAuthoritiesPasses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"this node holds organizations' interception AUTHORITIES but serves no traffic"}`))
	}))
	defer srv.Close()

	got := verifyAnOrganizationCanHaveItsOwnTree(srv.Client(), srv.URL, "tok")
	if len(got) != 1 || !got[0].ok {
		t.Fatalf("a control plane that holds organizations' authorities was reported as a problem: %+v", got)
	}
}

// ★★ AND AN EDGE IS NOT A CONTROL PLANE. Pointed at a node that INSPECTS, the honest answer is that the wrong
// node was named — not that the deployment is fine. A check that accepts an Edge here would pass on every
// deployment, because an Edge always answers 200.
func TestAnEdgeNamedAsTheControlPlaneIsNotAPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"default_root_pem":"-----BEGIN CERTIFICATE-----\n…"}`))
	}))
	defer srv.Close()

	got := verifyAnOrganizationCanHaveItsOwnTree(srv.Client(), srv.URL, "tok")
	if len(got) != 1 || got[0].ok {
		t.Fatalf("an Edge answering as the control plane was accepted: %+v", got)
	}
	if !strings.Contains(got[0].note, "Edge") {
		t.Errorf("the finding does not say which node answered: %s", got[0].note)
	}
}

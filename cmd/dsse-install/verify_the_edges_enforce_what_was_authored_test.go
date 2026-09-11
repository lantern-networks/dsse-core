package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// deploymentWhere builds a control plane that lists one organization and says whether it has an interception
// authority of its own, and an Edge that says what it actually signs under.
func deploymentWhere(t *testing.T, organizationHasItsOwn, edgeSignsPerTenant bool) (cp, edge *httptest.Server) {
	t.Helper()
	cp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/tenants":
			_, _ = w.Write([]byte(`{"tenants":[{"tenant_id":"tenant_kaede","display_name":"Kaede Logistics"}]}`))
		case "/admin/tenant-interception-authority":
			if r.Header.Get("X-Operate-Tenant") != "tenant_kaede" {
				// The read resolves the CALLER's organization without this header, so a check that forgot it
				// would silently measure the operator's own and report every customer as having none.
				_, _ = w.Write([]byte(`{"has_authority":false,"tenant_id":"tenant_default"}`))
				return
			}
			if organizationHasItsOwn {
				_, _ = w.Write([]byte(`{"has_authority":true,"tenant_id":"tenant_kaede",` +
					`"root":{"subject":"CN=Kaede Logistics Interception Root","sha256":"1cfd"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"has_authority":false,"tenant_id":"tenant_kaede"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(cp.Close)
	edge = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if edgeSignsPerTenant {
			_, _ = w.Write([]byte(`{"default_root_pem":"-----BEGIN CERTIFICATE-----\n…","signing_scope":` +
				`{"configured":"shared","effective":"per_tenant_offline_intermediate","per_tenant_signing":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"default_root_pem":"-----BEGIN CERTIFICATE-----\n…","signing_scope":` +
			`{"configured":"shared","effective":"shared_root_direct","per_tenant_signing":false,` +
			`"note":"one root for every tenant; provisioned per-tenant roots are not used to sign"}}`))
	}))
	t.Cleanup(edge.Close)
	return cp, edge
}

// ★★★ THE SHAPE THAT WAS WALKED, AND IT MUST FAIL. The control plane holds Kaede Logistics' own interception
// root and the screen says their traffic is inspected under it. The Edge that terminates that traffic signs
// every organization under the deployment's ONE shared CA.
func TestAnAuthorityHeldByTheControlPlaneAndUsedByNoEdgeFails(t *testing.T) {
	cp, edge := deploymentWhere(t, true, false)
	got := verifyTheEdgesEnforceWhatWasAuthored(cp.Client(), cp.URL, []string{edge.URL}, "tok")
	if len(got) != 1 {
		t.Fatalf("expected one answer, got %d", len(got))
	}
	if got[0].ok {
		t.Fatalf("a deployment inspecting every organization under one root was passed: %s", got[0].note)
	}
	// The finding must name the organization and the remedy, or the operator is told they have a problem and
	// not which customer has it or what to do.
	for _, want := range []string{"Kaede Logistics", "-tenant-transport-material-from-cp", "shared"} {
		if !strings.Contains(got[0].note, want) {
			t.Errorf("the finding does not mention %q: %s", want, got[0].note)
		}
	}
}

// ★ THE CONTROL, AND IT IS THE ONE THAT MATTERS: with the same organization set up, an Edge that signs
// per-tenant passes. Without this the check could be satisfied by failing every deployment.
func TestAnEdgeUsingEachOrganizationsOwnAuthorityPasses(t *testing.T) {
	cp, edge := deploymentWhere(t, true, true)
	got := verifyTheEdgesEnforceWhatWasAuthored(cp.Client(), cp.URL, []string{edge.URL}, "tok")
	if len(got) != 1 || !got[0].ok {
		t.Fatalf("a deployment where every Edge signs per-organization was reported as a problem: %+v", got)
	}
	if !strings.Contains(got[0].note, "Kaede Logistics") {
		t.Errorf("a pass that does not say what was measured is not evidence: %s", got[0].note)
	}
}

// ★★ AND A DEPLOYMENT WITH NO CUSTOMER PKI IS NOT A FAILURE — but it must SAY it measured nothing. An "ok"
// that reads the same whether a thing was checked or was absent is how the check beside this one certified a
// shared root.
func TestNoOrganizationHasItsOwnAuthorityYetSaysSo(t *testing.T) {
	cp, edge := deploymentWhere(t, false, false)
	got := verifyTheEdgesEnforceWhatWasAuthored(cp.Client(), cp.URL, []string{edge.URL}, "tok")
	if len(got) != 1 || !got[0].ok {
		t.Fatalf("a deployment with no per-organization authority was reported as a problem: %+v", got)
	}
	if !strings.Contains(got[0].note, "no organization") {
		t.Errorf("the pass does not say that nothing was there to measure: %s", got[0].note)
	}
}

// ★★ AN EDGE THAT COULD NOT BE ASKED IS NOT AN EDGE THAT PASSED. A fleet where the one reachable node is fine
// and the rest are silent must not read as "every Edge".
func TestAnUnreachableEdgeIsNamedRatherThanCountedAsPassing(t *testing.T) {
	cp, edge := deploymentWhere(t, true, true)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer dead.Close()
	got := verifyTheEdgesEnforceWhatWasAuthored(cp.Client(), cp.URL, []string{edge.URL, dead.URL}, "tok")
	if len(got) != 1 {
		t.Fatalf("expected one answer, got %d", len(got))
	}
	if !strings.Contains(got[0].note, "NOT measured on") || !strings.Contains(got[0].note, dead.URL) {
		t.Errorf("an Edge that never answered is not named in the result: %s", got[0].note)
	}
}

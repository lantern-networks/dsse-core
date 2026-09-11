package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// leafOf is a device leaf carrying an identity, which is all this route needs of one.
func leafOf(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

// ★★★ WHICH VERSION AN ORGANIZATION RUNS IS THE ORGANIZATION'S OWN, AND THIS ROUTE NEVER ASKED (2026-08-28).
//
// The operator publishes what EXISTS, once, to the deployment's catalogue. Choosing among what is offered —
// staying on a version, going back after a bad build — is the customer's, and their rollout plan has carried
// DesiredVersion since the plan existed. The device-facing manifest route handed every device of every
// organization the catalogue's current release regardless, so a customer could pin on their own screen and
// their fleet would move anyway.
//
// The freeze, the waves and the window already reach a device per organization through
// /steer/agent-update-plan, which was itself found answering the wrong tenant's halt. This is the one field of
// the same decision that never followed.
func TestTheManifestServedIsTheVersionThisOrganizationRuns(t *testing.T) {
	_, registry, _, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Suzuran Device CA")
	if _, err := registry.Register("tenant_suzuran", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}

	plans := agentrollout.NewAgentRolloutStore()
	facing := &publishedUpdates{byTarget: map[string]publishedUpdate{
		updateTargetKey("darwin", "arm64"): {
			Manifest: agentupdate.Manifest{Version: "0.3.0", Platform: "darwin", Arch: "arm64"},
			Envelope: agentpolicy.Envelope{PayloadSHA256: "catalogue"},
		},
	}}

	mux := http.NewServeMux()
	registerSteerAgentUpdateRoutes(mux, serverConfig{
		PublishedUpdates:  facing,
		AgentRolloutPlans: plans,
		TenantCARegistry:  registry,
	})

	ask := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/steer/agent-update-manifest?platform=darwin&arch=arm64", nil)
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leafOf("suzuran-1")},
			VerifiedChains:   [][]*x509.Certificate{{leafOf("suzuran-1"), caCert}},
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// Following the catalogue is the default and is unchanged.
	if rec := ask(); rec.Code != http.StatusOK {
		t.Fatalf("an organization that has chosen nothing was not served the catalogue's release: %d %s",
			rec.Code, rec.Body.String())
	}

	// ★ THE ORGANIZATION SAYS IT RUNS SOMETHING ELSE. It must not be moved onto the catalogue's release.
	if _, err := plans.Apply("tenant_suzuran", agentrollout.AgentRolloutPlan{DesiredVersion: "0.2.9"}, time.Now()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rec := ask()
	if rec.Code == http.StatusOK {
		t.Fatal("the organization runs 0.2.9 and was handed the catalogue's 0.3.0 — a customer can pin on " +
			"their own screen and their fleet moves anyway, which is the whole of what this field is for")
	}

	// ★ AND NAMING THE VERSION THIS EDGE HAS IS THE ORDINARY CASE, not a refusal.
	if _, err := plans.Apply("tenant_suzuran", agentrollout.AgentRolloutPlan{DesiredVersion: "0.3.0"}, time.Now()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rec := ask(); rec.Code != http.StatusOK {
		t.Fatalf("an organization running exactly what this edge publishes was refused: %d %s",
			rec.Code, rec.Body.String())
	}
}

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/steerexclusion"
)

// ★★★ "THERE IS A NEWER ONE", ON A CALL THAT ALREADY HAPPENS EVERY MINUTE (2026-08-20).
//
// Agents fetch the trust bundle on their own schedule — about a minute on macOS, six hours on Windows — so
// every rotation, overlap and withdrawal lands up to six hours late. Twice in one day somebody had to restart
// a service on a box to pull the fleet forward, which does not scale past the two machines in this lab. The
// Windows side asked for the serial on the report response; this is that.
//
// The hint cannot move a device: the serial is meaningful only inside the SIGNED bundle, which the device
// verifies and accepts only strictly above what it holds. A wrong number here costs one wasted fetch.
func TestTheReportResponseCarriesTheCurrentTrustSerial(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	material := trustPayloadForTest(t, d, publishTrustForTest(t, d, tr)["tenant_a"])
	// ★ Real devices are enrolled; the fallback that let an unenrolled one be served the NODE's organization
	// is gone (2026-09-05). The harness says which organization each device is in, as the control plane does.
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, id := range []string{"win-dev-1", "mac-dev-1"} {
		if _, err := ledger.Enroll(id, "t1", "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "t1"}},
		EnrolledLedger:     ledger,
		AdminAuth:          newAdminAuthStore(),
		SteerExclusions:    steerexclusion.NewStore(),
		ObservedExclusions: newObservedExclusionStore(0),
		AgentPolicySigner:  d.config.AgentPolicySigner,
		TrustBundleCAPEM:   material.TransportCAPEM,
		TrustBundleSerial:  84,
	})

	body, _ := json.Marshal(map[string]any{"platform": "windows", "adopted_trust_serial": 63})
	cert := leafWithCN(t, "win-dev-1")
	req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("the report response changed shape (HTTP %d) — every agent that has never heard of the hint "+
			"still has to read this the way it always did", rec.Code)
	}
	if got := rec.Header().Get("X-DSSE-Trust-Serial"); got != "84" {
		t.Fatalf("the response does not tell the device what is being served: %q — a device on six-hour ticks "+
			"has no way to learn that a rotation happened", got)
	}
}

// A migrated device already holds an epoch-sized durable serial. A node-local
// counter (33) can never wake it again; the next signed revision must be hinted.
func TestTrustHintFollowsTheServedTenantEnvelope(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	if _, err := tr.EnsureCA("tenant_b", "b.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	bundles := publishTrustForTest(t, d, tr)
	cache := &tenantTrustDistributionCache{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}
	if err := cache.Adopt(bundles); err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	for _, tenant := range []string{"tenant_a", "tenant_b"} {
		if _, err := ledger.Enroll(tenant+"-device", tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	h := newServerWithConfig(serverConfig{Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_default"}}, EnrolledLedger: ledger, AdminAuth: newAdminAuthStore(), SteerExclusions: steerexclusion.NewStore(), ObservedExclusions: newObservedExclusionStore(0), AgentPolicySigner: d.config.AgentPolicySigner, TrustBundleCAPEM: trustPayloadForTest(t, d, bundles["tenant_a"]).TransportCAPEM, TrustBundleSerial: 33, DistributedTenantTrust: cache})
	hint := func(tenant string) string {
		cert := leafWithCN(t, tenant+"-device")
		r := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", strings.NewReader(`{"platform":"windows","adopted_trust_serial":1788853692053}`))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatalf("report HTTP %d: %s", w.Code, w.Body.String())
		}
		return w.Header().Get("X-DSSE-Trust-Serial")
	}
	compare := func(tenant string) int64 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bootstrap/trust-bundle?tenant="+tenant, nil))
		if w.Code != 200 {
			t.Fatalf("bootstrap HTTP %d: %s", w.Code, w.Body.String())
		}
		var envelope agentpolicy.Envelope
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		p, err := agentpolicy.VerifyTrustBundle(envelope, d.config.AgentPolicySigner.PublicKeyHex(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if p.TenantID != tenant || hint(tenant) != strconv.FormatInt(p.Serial, 10) {
			t.Fatalf("hint does not name the served revision for %s: hint %s, signed %d", tenant, hint(tenant), p.Serial)
		}
		return p.Serial
	}
	first := compare("tenant_a")
	other := compare("tenant_b")
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if err := cache.Adopt(publishTrustForTest(t, d, tr)); err != nil {
		t.Fatal(err)
	}
	if got := compare("tenant_a"); got <= first {
		t.Fatal("new revision did not advance the hint")
	}
	if got := compare("tenant_b"); got != other {
		t.Fatal("unrelated tenant revision changed")
	}
	if err := cache.Adopt(map[string]tenantTrustDistribution{}); err != nil {
		t.Fatal(err)
	}
	if got := hint("tenant_a"); got != "" {
		t.Fatalf("missing tenant envelope fell back to another serial: %s", got)
	}
}

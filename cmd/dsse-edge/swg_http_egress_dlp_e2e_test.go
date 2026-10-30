package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	swg "github.com/lantern-networks/dsse-core/swg"
)

// redirectAllToServer sends every request the SWG egress proxy makes to a local recording server, regardless
// of the (policy-allowed) target host — so the decision path sees accounts.google.com (allowed + forwarded)
// while the bytes actually land on a server we can inspect.
type redirectAllToServer struct {
	host string
	rt   http.RoundTripper
}

func (t redirectAllToServer) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.host
	req.Host = t.host
	return t.rt.RoundTrip(req)
}

// End-to-end verification through the REAL egress handler, a REAL http.Client, and a REAL upstream server:
// observe forwards the secret and records it; block denies the upload and the secret never reaches upstream.
func TestSWGHTTPEgressDLPEndToEnd(t *testing.T) {
	secret := "123456789018" // synthetic valid My Number

	// Recording upstream: capture whatever bytes actually arrive (partial on an aborted/blocked upload).
	var mu sync.Mutex
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	operatorConfigPath := t.TempDir() + "/operator_config.json"
	if werr := os.WriteFile(operatorConfigPath, []byte(`{
  "schema_version": "swg_tenant_restriction_operator_config.v1",
  "status": "active",
  "tenant_id": "tenant_swg_lab",
  "header_values": [
    {
      "ref": "operator_config_ref:google_workspace_allowed_domains",
      "tenant_id": "tenant_swg_lab",
      "saas_application_id": "saas_google_workspace",
      "provider": "google_workspace",
      "header_name": "X-GoogApps-Allowed-Domains",
      "header_value_kind": "configured_allowed_domains",
      "value": "allowed.example",
      "status": "active",
      "metadata": {
        "operator_managed": true,
        "operator_config_value_secret": false,
        "captured_secret_material_committed": false,
        "report_value_material_logged": false
      }
    }
  ],
  "metadata": { "designated_operator_config_file": true }
}`), 0600); werr != nil {
		t.Fatalf("write operator config: %v", werr)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true,
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig: %v", err)
	}

	newConfig := func() edgeSWGHTTPEgressHandlerConfig {
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		return edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				Policies:      policies,
				PolicyBundle:  bundle,
				EdgeRegionID:  "local",
				EdgeClusterID: "local-edge-001",
			},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			DeviceAuthenticatedInProcess: true, // trusted in-process NE/WFP forward
			LabMode:                      false,
		}
	}

	uploadReq := func() *http.Request {
		body := `{"note":"quarterly report attached","my_number":"` + secret + `","ok":true}`
		req := httptest.NewRequest(http.MethodPost, edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(body))
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
		req.Header.Set("Content-Type", "application/json")
		return req
	}

	getReceived := func() string { mu.Lock(); defer mu.Unlock(); return received }
	setReceived := func(s string) { mu.Lock(); received = s; mu.Unlock() }

	tenant := bundle.TenantID

	// newConfigWithDLPRule builds a config whose bundle carries a single DLP rule, so DLP fires via the dlp_inspect
	// directive — the ONLY path now that detection is policy-gated (docs/dlp_policy_ux_integration.md): with no rule
	// a flow is not inspected at all.
	newConfigWithDLPRule := func(rule model.DLPRule) edgeSWGHTTPEgressHandlerConfig {
		rule.TenantID = tenant
		if rule.Status == "" {
			rule.Status = "active"
		}
		b := bundle
		b.DLPRules = []model.DLPRule{rule}
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		return edgeSWGHTTPEgressHandlerConfig{
			Evaluator:                    decision.Evaluator{Policies: policies, PolicyBundle: b, EdgeRegionID: "local", EdgeClusterID: "local-edge-001"},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			DeviceAuthenticatedInProcess: true,
		}
	}

	// (0) POLICY GATE: with NO DLP rule, the flow is NOT inspected — forwarded, and no finding recorded. This is
	// the core of destination-scoped DLP (no blanket scanning → no all-traffic false positives).
	t.Run("no dlp rule = not inspected", func(t *testing.T) {
		setReceived("")
		cfg := newConfig()
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code >= 400 {
			t.Fatalf("no-rule upload denied: status=%d", rec.Code)
		}
		if !strings.Contains(getReceived(), secret) {
			t.Errorf("no-rule: upstream did not receive the body")
		}
		if ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match"); ev != nil {
			t.Errorf("no-rule: a finding was recorded despite no DLP rule (blanket scanning not removed): %+v", ev)
		}
	})

	// (1) OBSERVE under a destination-scoped rule: the upload is forwarded and a dlp_match observe event with the
	// destination is recorded.
	t.Run("observe under a rule forwards and records", func(t *testing.T) {
		setReceived("")
		cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"my_number"}, OnMatch: "observe"})
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code >= 400 {
			t.Fatalf("observe upload denied: status=%d body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(getReceived(), secret) {
			t.Errorf("observe: upstream did not receive the body (got %q)", getReceived())
		}
		ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match")
		if ev == nil {
			t.Errorf("observe: no dlp_match event recorded for tenant %q", tenant)
		} else if ev.Metadata["dlp_destination"] != "accounts.google.com" {
			t.Errorf("observe: finding should carry the destination host, got dlp_destination=%v", ev.Metadata["dlp_destination"])
		}
	})

	// (2) BLOCK: with a block rule, the upload is denied (403) and the secret NEVER reaches the upstream.
	t.Run("block denies and secret never leaves", func(t *testing.T) {
		setReceived("")
		cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"my_number"}, OnMatch: "block"})
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("block: status=%d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(getReceived(), secret) {
			t.Errorf("block: secret leaked to upstream (received %q)", getReceived())
		}
		ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match")
		if ev == nil || ev.Metadata["dlp_action"] != "block" {
			t.Errorf("block: expected a dlp_match event with action=block, got %+v", ev)
		}
	})

	// A .docx FILE uploaded via multipart carrying a My Number in its text: block denies it and the file is
	// never forwarded upstream (buffered file path, decided before Do).
	t.Run("block denies a docx file upload", func(t *testing.T) {
		setReceived("")
		cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"my_number"}, OnMatch: "block"})
		body, ct := dlpMultipartDocx(t, "My number "+secret)
		req := httptest.NewRequest(http.MethodPost, edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(body))
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
		req.Header.Set("Content-Type", ct)

		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("docx block: status=%d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if getReceived() != "" {
			t.Errorf("docx block: the file was forwarded upstream (%d bytes)", len(getReceived()))
		}
		if ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match"); ev == nil || ev.Metadata["dlp_action"] != "block" {
			t.Errorf("docx block: expected dlp_match action=block, got %+v", ev)
		}
	})

	// A clean .docx (no identifiers) under an active BLOCK rule is scanned and forwarded unchanged.
	t.Run("clean docx passes under block rule", func(t *testing.T) {
		setReceived("")
		cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"my_number"}, OnMatch: "block"})
		body, ct := dlpMultipartDocx(t, "quarterly notes, nothing sensitive")
		req := httptest.NewRequest(http.MethodPost, edgeplane.EdgeSWGHTTPEgressPath, strings.NewReader(body))
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://accounts.google.com/")
		req.Header.Set("Content-Type", ct)

		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
		if rec.Code >= 400 {
			t.Fatalf("clean docx denied: status=%d body=%s", rec.Code, rec.Body.String())
		}
		if getReceived() == "" {
			t.Errorf("clean docx was not forwarded upstream")
		}
	})

	// DLP configured as an OPTION ON the egress policy (a model.DLPRule in the bundle), NOT the standalone
	// store: the evaluator surfaces a dlp_inspect directive and the handler blocks the My Number upload.
	t.Run("dlp rule on the egress policy drives block", func(t *testing.T) {
		setReceived("")
		bundleWithDLP := bundle
		bundleWithDLP.DLPRules = []model.DLPRule{{
			ID: "dlp-google", TenantID: tenant, Status: "active",
			Identifiers: []string{"my_number"}, OnMatch: "block",
		}}
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		cfg := edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				Policies:      policies,
				PolicyBundle:  bundleWithDLP,
				EdgeRegionID:  "local",
				EdgeClusterID: "local-edge-001",
			},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			DeviceAuthenticatedInProcess: true,
			LabMode:                      false,
			// DLPPolicy (standalone store) intentionally NOT set — the egress-policy rule drives DLP.
		}
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("rule-driven block: status=%d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(getReceived(), secret) {
			t.Errorf("rule-driven block: secret leaked to upstream")
		}
		if ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match"); ev == nil || ev.Metadata["dlp_action"] != "block" {
			t.Errorf("rule-driven: expected dlp_match action=block, got %+v", ev)
		}
	})

	// A RUNTIME-authored DLP rule (/admin/dlp-rules → dlpRuleRuntimeStore) is overlaid onto the bundle and
	// surfaces as a dlp_inspect directive, blocking the upload — no bundle edit, no standalone store.
	t.Run("runtime dlp rule overlay drives block", func(t *testing.T) {
		setReceived("")
		ruleStore := newDLPRuleRuntimeStore()
		ruleStore.SetRules(tenant, []model.DLPRule{{
			ID: "rt-1", TenantID: tenant, Status: "active",
			Identifiers: []string{"my_number"}, OnMatch: "block",
		}})
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		cfg := edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				Policies:      policies,
				PolicyBundle:  bundle,
				EdgeRegionID:  "local",
				EdgeClusterID: "local-edge-001",
			},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			DLPRules:                     ruleStore, // runtime-authored rules overlaid onto the bundle
			DeviceAuthenticatedInProcess: true,
			LabMode:                      false,
		}
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("runtime-rule block: status=%d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(getReceived(), secret) {
			t.Errorf("runtime-rule block: secret leaked to upstream")
		}
	})

	// DLP configured AS A FIELD ON the egress policy rule (model.Policy.DLP — what the GUI's Access Rules editor
	// writes): when the rule matches and the flow is intercepted, its DLP spec surfaces the directive and blocks.
	t.Run("dlp on the egress policy rule drives block", func(t *testing.T) {
		setReceived("")
		pols := make([]model.Policy, len(policies))
		copy(pols, policies)
		for i := range pols {
			pols[i].DLP = &model.DLPSpec{Identifiers: []string{"my_number"}, OnMatch: "block"}
		}
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		cfg := edgeSWGHTTPEgressHandlerConfig{
			Evaluator: decision.Evaluator{
				Policies:      pols,
				PolicyBundle:  bundle,
				EdgeRegionID:  "local",
				EdgeClusterID: "local-edge-001",
			},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			DeviceAuthenticatedInProcess: true,
			LabMode:                      false,
		}
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReq())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("policy-DLP block: status=%d, want 403; body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(getReceived(), secret) {
			t.Errorf("policy-DLP block: secret leaked to upstream")
		}
	})

	// Request token claims are account hints, not proof of the destination SaaS account.
	// Even an authenticated device cannot use an unverified hint to exempt a scoped DLP rule.
	instanceCfg := func(scope, action string) edgeSWGHTTPEgressHandlerConfig {
		bundleWithDLP := bundle
		bundleWithDLP.DLPRules = []model.DLPRule{{
			ID: "dlp-personal-only", TenantID: tenant, Status: "active",
			Identifiers: []string{"my_number"}, OnMatch: action, InstanceScope: scope,
		}}
		writer, werr := logs.NewWriter(t.TempDir())
		if werr != nil {
			t.Fatalf("NewWriter: %v", werr)
		}
		return edgeSWGHTTPEgressHandlerConfig{
			Evaluator:                    decision.Evaluator{Policies: policies, PolicyBundle: bundleWithDLP, EdgeRegionID: "local", EdgeClusterID: "local-edge-001"},
			Writer:                       writer,
			Registry:                     connector.NewRegistry(),
			ProxyClient:                  &http.Client{Transport: redirectAllToServer{host: upstreamURL.Host, rt: http.DefaultTransport}},
			SWGRuntime:                   swgRuntime,
			DecisionStore:                newAccessDecisionStore(),
			InspectionEvents:             newInspectionEventStore(),
			CorporateDomains:             func(string) []string { return []string{"corp.example"} },
			DeviceAuthenticatedInProcess: true,
			LabMode:                      false,
		}
	}

	jwtFor := func(algorithm, claims string) string {
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		return b64(`{"alg":"`+algorithm+`","typ":"JWT"}`) + "." + b64(claims) + ".forged"
	}
	corporate := jwtFor("none", `{"email":"bob@corp.example"}`)
	personal := jwtFor("none", `{"email":"alice@gmail.com"}`)
	hints := []struct {
		name, authorization, cookie string
		wantHint                    bool
	}{
		{"unsigned_corporate_bearer", "Bearer " + corporate, "", true},
		{"unsigned_personal_bearer", "Bearer " + personal, "", true},
		{"forged_signed_bearer", "Bearer " + jwtFor("RS256", `{"email":"bob@corp.example","iss":"https://trusted.example","aud":"saas"}`), "", true},
		{"corporate_cookie", "", "session=" + corporate, true},
		{"personal_cookie", "", "session=" + personal, true},
		{"opaque_bearer_corporate_cookie", "Bearer opaque-token", "session=" + corporate, true},
		{"personal_bearer_corporate_cookie", "Bearer " + personal, "session=" + corporate, true},
		{"corporate_subject_fallback", "Bearer " + jwtFor("none", `{"sub":"bob@corp.example"}`), "", true},
		{"opaque_bearer", "Bearer opaque-token", "", false},
		{"opaque_cookie", "", "session=opaque-token", false},
		{"malformed_jwt", "Bearer not.a.jwt", "", false},
		{"no_token", "", "", false},
	}
	for _, scope := range []string{"personal", "corporate"} {
		for _, action := range []string{"block", "authenticate"} {
			for _, hint := range hints {
				t.Run("unverified_instance/"+scope+"/"+action+"/"+hint.name, func(t *testing.T) {
					setReceived("")
					cfg := instanceCfg(scope, action)
					req := uploadReq()
					req.Header.Set("Authorization", hint.authorization)
					req.Header.Set("Cookie", hint.cookie)
					rec := httptest.NewRecorder()
					newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
					wantStatus := http.StatusForbidden
					if action == "authenticate" {
						wantStatus = http.StatusUnauthorized
					}
					if rec.Code != wantStatus {
						t.Fatalf("status=%d, want %d; body=%s", rec.Code, wantStatus, rec.Body.String())
					}
					if strings.Contains(getReceived(), secret) {
						t.Fatal("secret reached upstream despite the instance-scoped rule")
					}
					ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match")
					if ev == nil || ev.Metadata["dlp_action"] != action {
						t.Fatalf("missing scoped DLP finding: %+v", ev)
					}
					if class, _ := ev.Metadata["dlp_instance_class"].(string); class != "" {
						t.Fatalf("unverified account recorded as %q", class)
					}
					if hint.wantHint {
						if ev.Metadata["dlp_account_trust"] != "unverified_request_hint" {
							t.Fatalf("standalone finding must label the account hint unverified: %+v", ev.Metadata)
						}
						if ev.AccessDecisionID == nil {
							t.Fatal("finding has no decision reference")
						}
						dec, ok := cfg.DecisionStore.Get(*ev.AccessDecisionID)
						if !ok || dec.Metadata["ai_identity_trust"] != "unverified_request_hint" {
							t.Fatalf("account hint must be labeled unverified: %+v", dec.Metadata)
						}
					}
				})
			}
		}
		for _, domains := range []string{"missing_resolver", "empty_domains"} {
			t.Run("unverified_instance/"+scope+"/"+domains, func(t *testing.T) {
				setReceived("")
				cfg := instanceCfg(scope, "block")
				cfg.CorporateDomains = nil
				if domains == "empty_domains" {
					cfg.CorporateDomains = func(string) []string { return nil }
				}
				req := uploadReq()
				req.Header.Set("Authorization", "Bearer "+corporate)
				rec := httptest.NewRecorder()
				newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden || strings.Contains(getReceived(), secret) {
					t.Fatalf("missing domain evidence must not exempt DLP: status=%d upstream=%q", rec.Code, getReceived())
				}
			})
		}
		t.Run("unverified_instance/"+scope+"/benign_body", func(t *testing.T) {
			setReceived("")
			cfg := instanceCfg(scope, "block")
			req := uploadReq()
			req.Body = io.NopCloser(strings.NewReader(`{"note":"ordinary text"}`))
			req.ContentLength = -1
			req.Header.Set("Authorization", "Bearer "+corporate)
			rec := httptest.NewRecorder()
			newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || getReceived() != `{"note":"ordinary text"}` {
				t.Fatalf("unknown instance alone must not deny benign content: status=%d upstream=%q", rec.Code, getReceived())
			}
		})
	}

	t.Run("retention refusal is not a content match or authentication", func(t *testing.T) {
		prior := dlp.DefaultRetentionBudget().Status()
		budget, err := dlp.ConfigureProcessRetention(1<<20, 2<<20)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := dlp.ConfigureProcessRetention(prior.PerStreamBytes, prior.ProcessBytes); err != nil {
				t.Error(err)
			}
		}()
		for _, html := range []bool{false, true} {
			setReceived("")
			cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"email"}, OnMatch: "authenticate"})
			cfg.DLPRetentionBudget = budget
			req := uploadReq()
			req.Body = io.NopCloser(strings.NewReader("a@b" + strings.Repeat(".cc", 400000)))
			req.ContentLength = -1
			if html {
				req.Header.Set("Accept", "text/html")
				req.Header.Set("Accept-Language", "ja")
			}
			rec := httptest.NewRecorder()
			newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || strings.Contains(getReceived(), "a@b") {
				t.Fatalf("resource refusal failed: status=%d", rec.Code)
			}
			if html && !strings.Contains(rec.Body.String(), "アップロードを検査できませんでした") {
				t.Fatal("Japanese resource refusal was not rendered")
			}
			if !html && !strings.Contains(rec.Body.String(), "dlp_inspection_resource_exhausted") {
				t.Fatal("missing non-secret refusal reason")
			}
			events := cfg.InspectionEvents.ListByTenant(tenant)
			if dlpEventByFindingType(events, "dlp_match") != nil || dlpEventByFindingType(events, "dlp_inspection_resource_exhausted") == nil {
				t.Fatal("resource refusal fabricated a DLP finding")
			}
			if budget.Status().UsedBytes != 0 {
				t.Fatal("handler retained budget")
			}
			_ = cfg.Writer.Close()
		}
	})

	for _, lateLimit := range []bool{false, true} {
		t.Run(map[bool]string{false: "early response preserves duplex upload", true: "late resource refusal stops undecided upload"}[lateLimit], func(t *testing.T) {
			prior := dlp.DefaultRetentionBudget().Status()
			budget, err := dlp.ConfigureProcessRetention(1<<20, 2<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := dlp.ConfigureProcessRetention(prior.PerStreamBytes, prior.ProcessBytes); err != nil {
					t.Error(err)
				}
			}()
			cfg := newConfigWithDLPRule(model.DLPRule{Identifiers: []string{"email"}, OnMatch: "block"})
			cfg.DLPRetentionBudget = budget
			defer cfg.Writer.Close()
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			body := &dlpEnteredBody{ReadCloser: pr, entered: make(chan struct{})}
			upload := "ordinary duplex body"
			if lateLimit {
				upload = "a@b" + strings.Repeat(".cc", 400000)
			}
			done := make(chan struct {
				n   int64
				err error
			}, 1)
			cfg.ProxyClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				go func() {
					n, e := io.Copy(io.Discard, r.Body)
					_ = r.Body.Close()
					done <- struct {
						n   int64
						err error
					}{n, e}
				}()
				<-body.entered
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &dlpLazyResponse{Reader: strings.NewReader("ok"), start: func() {
					go func() { _, _ = io.WriteString(pw, upload); _ = pw.Close() }()
					select {
					case result := <-done:
						if lateLimit {
							if result.n != 0 || !errors.Is(result.err, dlp.ErrRetentionLimit) {
								t.Errorf("late refusal leaked or misclassified: %d %v", result.n, result.err)
							}
						} else if result.err != nil || result.n != int64(len(upload)) {
							t.Errorf("successful early response cut upload: %d %v", result.n, result.err)
						}
					case <-time.After(3 * time.Second):
						t.Error("duplex upload deadlocked")
					}
				}}}, nil
			})}
			req := uploadReq()
			req.Body = body
			req.ContentLength = -1
			rec := httptest.NewRecorder()
			finished := make(chan struct{})
			go func() { defer close(finished); newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, req) }()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				_ = pr.Close()
				_ = pw.Close()
				<-finished
				t.Fatal("early response waited for upload Read")
			}
			if rec.Code != 200 {
				t.Fatalf("upstream early response changed: %d", rec.Code)
			}
			if budget.Status().UsedBytes != 0 {
				t.Fatal("early-response handler leaked retention")
			}
			if lateLimit && dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_inspection_resource_exhausted") == nil {
				t.Fatal("late resource refusal was not reported")
			}
		})
	}

}

type dlpEnteredBody struct {
	io.ReadCloser
	entered chan struct{}
	once    sync.Once
}

func (b *dlpEnteredBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	return b.ReadCloser.Read(p)
}

type dlpLazyResponse struct {
	io.Reader
	start func()
	once  sync.Once
}

func (b *dlpLazyResponse) Read(p []byte) (int, error) { b.once.Do(b.start); return b.Reader.Read(p) }
func (*dlpLazyResponse) Close() error                 { return nil }

// dlpMultipartDocx builds a multipart/form-data body whose file part is a minimal .docx (a ZIP with
// word/document.xml) containing the given text. Returns (body, contentType).
func dlpMultipartDocx(t *testing.T, text string) (string, string) {
	t.Helper()
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	w.Write([]byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`))
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	var mbuf bytes.Buffer
	mw := multipart.NewWriter(&mbuf)
	part, err := mw.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="file"; filename="report.docx"`},
		"Content-Type":        {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	})
	if err != nil {
		t.Fatalf("multipart part: %v", err)
	}
	part.Write(zbuf.Bytes())
	mw.Close()
	return mbuf.String(), mw.FormDataContentType()
}

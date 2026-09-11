package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
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

	// INSTANCE-AWARE action (slice I, sovereign "here not there"): a personal-scoped block rule fires only when the
	// signed-in account is NOT a corporate (verified-domain) one. Same rule + same secret; only the account differs.
	// The account is carried in a real Bearer JWT the handler decodes (ai_account) and classified against the
	// tenant's corporate domains — the exact runtime path proven live on the reference lab.
	instanceCfg := func() edgeSWGHTTPEgressHandlerConfig {
		bundleWithDLP := bundle
		bundleWithDLP.DLPRules = []model.DLPRule{{
			ID: "dlp-personal-only", TenantID: tenant, Status: "active",
			Identifiers: []string{"my_number"}, OnMatch: "block", InstanceScope: "personal",
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
	// jwtFor builds a decodable (unsigned) JWT carrying an email claim — the handler decodes the middle segment.
	jwtFor := func(email string) string {
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		return b64(`{"alg":"none","typ":"JWT"}`) + "." + b64(`{"email":"`+email+`"}`) + ".sig"
	}
	uploadReqAs := func(email string) *http.Request {
		req := uploadReq()
		req.Header.Set("Authorization", "Bearer "+jwtFor(email))
		return req
	}

	t.Run("personal-scoped rule blocks a personal account", func(t *testing.T) {
		setReceived("")
		cfg := instanceCfg()
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReqAs("alice@gmail.com"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("personal account: status=%d, want 403 (block); body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(getReceived(), secret) {
			t.Errorf("personal account: secret leaked to upstream despite block")
		}
		ev := dlpEventByFindingType(cfg.InspectionEvents.ListByTenant(tenant), "dlp_match")
		if ev == nil || ev.Metadata["dlp_instance_class"] != "personal" {
			t.Errorf("expected a dlp_match stamped instance_class=personal, got %+v", ev)
		}
	})

	t.Run("personal-scoped rule does NOT touch a corporate account", func(t *testing.T) {
		setReceived("")
		cfg := instanceCfg()
		rec := httptest.NewRecorder()
		newEdgeSWGHTTPEgressHandler(cfg).ServeHTTP(rec, uploadReqAs("bob@corp.example"))
		if rec.Code >= 400 {
			t.Fatalf("corporate account: status=%d, want allowed (rule scoped to personal); body=%s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(getReceived(), secret) {
			t.Errorf("corporate account: upload should have been forwarded (rule does not apply), got %q", getReceived())
		}
	})
}

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

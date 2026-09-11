//go:build sitecompat

// Package main — SWG site-compatibility (interoperability) harness.
//
// Release gate: the SWG forward proxy decrypts (MITM) almost every site (default posture decrypt_all, no
// bypass for the big sites), so a protocol/Cookie/redirect regression in the egress path silently breaks real
// browsing. This harness drives the PRODUCTION egress handler `handleSWGHTTPEgress` directly (no NE/tunnel —
// it is a plain http.Handler) against a list of real sites, and DIFFS each site's result against a direct
// (no-proxy) baseline so that only PROXY-INDUCED regressions are reported (site-side bot-blocks / outages /
// geo differences hit BOTH paths and cancel out).
//
// It is isolated behind the `sitecompat` build tag so it never runs under `go test ./...` (it needs live
// network). Run it explicitly:
//
//	go test -tags sitecompat -run TestSWGSiteCompat ./cmd/edge/
//	SITE_COMPAT_LIST=/path/to/hosts.txt SITE_COMPAT_TOP_N=500 SITE_COMPAT_SCENARIO=both \
//	  go test -tags sitecompat -run TestSWGSiteCompat ./cmd/edge/
//
// Output: var/swg-site-compat/<scenario>-results.csv and <scenario>-summary.md (root-cause classified).
package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	swg "github.com/lantern-networks/dsse-core/swg"
)

const (
	siteCompatMaxHops    = 10
	siteCompatConcurrent = 12
	siteCompatPerHopTO   = 25 * time.Second
	// A modern desktop Chrome UA, used on BOTH the direct and SWG paths so a site that user-agent-gates
	// (bot detection) treats the two paths identically — its block is not counted as a proxy regression.
	siteCompatUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

// compatRecorder captures the SWG handler's diagnostic side-channels (outcome + upstream error category) in
// addition to the normal response.
type compatRecorder struct {
	*httptest.ResponseRecorder
	outcome  string
	category string
}

func newCompatRecorder() *compatRecorder {
	return &compatRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (c *compatRecorder) SetSWGHTTPEgressOutcome(o string)                 { c.outcome = o }
func (c *compatRecorder) SetSWGHTTPEgressUpstreamErrorCategory(cat string) { c.category = cat }

// hopResult is one request hop (direct or via the SWG handler).
type hopResult struct {
	status   int
	header   http.Header
	location string
	cookies  []*http.Cookie
	outcome  string
	category string
	err      error
}

type hopFetcher func(ctx context.Context, target *url.URL, reqCookies []*http.Cookie) hopResult

// chainOutcome is the end state of following a redirect chain.
type chainOutcome struct {
	finalStatus  int
	finalURL     string
	setCookies   int
	outcome      string
	category     string
	transportErr string
}

// followChain walks the redirect chain (manually, symmetric for both paths) carrying a cookie jar so the two
// paths are compared apples-to-apples. The SWG handler returns one hop at a time (CheckRedirect=
// ErrUseLastResponse) so the loop is required for it; the direct path uses the same loop for symmetry.
func followChain(ctx context.Context, start *url.URL, fetch hopFetcher) chainOutcome {
	jar, _ := cookiejar.New(nil)
	cur := start
	out := chainOutcome{finalURL: start.String()}
	for hop := 0; hop < siteCompatMaxHops; hop++ {
		res := fetch(ctx, cur, jar.Cookies(cur))
		out.finalURL = cur.String()
		out.outcome = res.outcome
		out.category = res.category
		if res.err != nil {
			out.transportErr = res.err.Error()
			out.finalStatus = res.status
			return out
		}
		if len(res.cookies) > 0 {
			jar.SetCookies(cur, res.cookies)
			out.setCookies += len(res.cookies)
		}
		out.finalStatus = res.status
		if res.status >= 300 && res.status < 400 && strings.TrimSpace(res.location) != "" {
			next, err := cur.Parse(res.location)
			if err != nil || next.Host == "" {
				return out
			}
			cur = next
			continue
		}
		return out
	}
	return out
}

// directHopFetcher fetches one hop with no proxy (the baseline). It reuses the production error classifier so
// the direct and SWG error categories are directly comparable.
func directHopFetcher(client *http.Client) hopFetcher {
	return func(ctx context.Context, target *url.URL, reqCookies []*http.Cookie) hopResult {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return hopResult{err: err, category: swgHTTPEgressUpstreamRequestErrorCategory(err)}
		}
		req.Header.Set("User-Agent", siteCompatUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		for _, c := range reqCookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			return hopResult{err: err, category: swgHTTPEgressUpstreamRequestErrorCategory(err)}
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return hopResult{status: resp.StatusCode, header: resp.Header, location: resp.Header.Get("Location"), cookies: resp.Cookies()}
	}
}

// swgHopFetcher fetches one hop through the real SWG egress handler (decrypt-and-forward path).
func swgHopFetcher(handler http.HandlerFunc) hopFetcher {
	return func(ctx context.Context, target *url.URL, reqCookies []*http.Cookie) hopResult {
		req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil).WithContext(ctx)
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, target.String())
		req.Header.Set(edgeplane.EdgeSWGHTTPEgressNERuntimeHeader, "true") // production-equiv pooled h2 transport
		req.Header.Set("User-Agent", siteCompatUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		for _, c := range reqCookies {
			req.AddCookie(c)
		}
		rec := newCompatRecorder()
		handler(rec, req)
		res := rec.Result()
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return hopResult{
			status:   rec.Code,
			header:   res.Header,
			location: res.Header.Get("Location"),
			cookies:  res.Cookies(),
			outcome:  rec.outcome,
			category: rec.category,
		}
	}
}

// siteResult is one site's direct-vs-SWG comparison.
type siteResult struct {
	Host          string
	DirectStatus  int
	DirectURL     string
	DirectCookies int
	DirectErr     string
	SWGStatus     int
	SWGURL        string
	SWGCookies    int
	SWGOutcome    string
	SWGCategory   string
	SWGErr        string
	Regressed     bool
	RootCause     string
	Note          string
}

// classifySite decides whether the SWG path regressed relative to the direct baseline and assigns a root
// cause. A site whose DIRECT baseline already failed/blocked is excluded (not a proxy problem).
func classifySite(r *siteResult) {
	directOK := r.DirectErr == "" && r.DirectStatus > 0 && r.DirectStatus < 400
	if !directOK {
		r.Regressed = false
		r.RootCause = ""
		r.Note = "direct_baseline_not_ok"
		return
	}
	switch {
	case r.SWGErr != "" || r.SWGStatus == 0:
		r.Regressed = true
		r.RootCause = "upstream/intercept(③/④)"
		r.Note = firstNonEmpty(r.SWGCategory, "transport_error")
	case r.SWGOutcome == edgeplane.EdgeSWGHTTPEgressOutcomePolicyDenied || r.SWGStatus == http.StatusUnauthorized || r.SWGStatus == http.StatusForbidden:
		r.Regressed = true
		r.RootCause = "decision_substitution(①)"
		r.Note = firstNonEmpty(r.SWGOutcome, fmt.Sprintf("swg=%d", r.SWGStatus))
	case r.SWGStatus == http.StatusBadGateway:
		r.Regressed = true
		r.RootCause = "bad_gateway(③)"
		r.Note = firstNonEmpty(r.SWGCategory, "502")
	case r.SWGStatus >= 400:
		r.Regressed = true
		r.RootCause = "status_regression"
		r.Note = fmt.Sprintf("direct=%d swg=%d", r.DirectStatus, r.SWGStatus)
	case r.DirectCookies > 0 && r.SWGCookies == 0:
		r.Regressed = true
		r.RootCause = "cookie_loss(①/③)"
		r.Note = fmt.Sprintf("direct_cookies=%d swg=0", r.DirectCookies)
	default:
		r.Regressed = false
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// buildPassthroughEgressConfig builds an egress config that forwards EVERY destination, so a compatibility
// run measures pure protocol behaviour (Cookie / redirect / 3xx / h2) independent of policy decisions.
//
// It used to get that by pinning Policy Learning to observe, which deferred Default Deny. Policy Learning was
// removed on 2026-08-05, so passthrough is now what it always meant: a lowest-priority catch-all ALLOW. That
// is also the more honest fixture — it says "everything is permitted here" in the policy set the evaluator
// reads, rather than in a mode that silently rewrote the verdict afterwards.
func buildPassthroughEgressConfig(t *testing.T) edgeSWGHTTPEgressHandlerConfig {
	t.Helper()
	cfg := buildBaseEgressConfig(t)
	cfg.Evaluator.Policies = append(cfg.Evaluator.Policies, model.Policy{
		ID:         "pol_site_compat_passthrough_catch_all",
		TenantID:   cfg.Evaluator.PolicyBundle.TenantID,
		Name:       "site-compat harness: allow everything",
		Priority:   10000,
		Conditions: map[string]any{},
		Action:     model.PolicyAction{Decision: "allow"},
		Status:     "active",
	})
	return cfg
}

// buildEnforceEgressConfig builds an egress config in enforce posture (Default Deny applies; only the bundle's
// explicit allow rules pass). Measures the decision-substitution impact (root cause ①).
func buildEnforceEgressConfig(t *testing.T) edgeSWGHTTPEgressHandlerConfig {
	t.Helper()
	return buildBaseEgressConfig(t) // no learning store => evaluator's own Default Deny
}

func buildBaseEgressConfig(t *testing.T) edgeSWGHTTPEgressHandlerConfig {
	t.Helper()
	bundle, policies := testNetworkExtensionLabTLSSWGPolicyBundle()
	// The test bundle carries active tenant-restriction rules, so LoadRuntimeConfig requires the operator
	// config that supplies their header values (same fixture as swg_egress_nonlab_integration_test.go).
	operatorConfigPath := filepath.Join(t.TempDir(), "operator_config.json")
	if err := os.WriteFile(operatorConfigPath, []byte(`{
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
}`), 0o600); err != nil {
		t.Fatalf("write operator config: %v", err)
	}
	swgRuntime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: operatorConfigPath,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        true, // clear the non-lab readiness precondition (428)
		MacCATrustObserved:                  true,
	})
	if err != nil {
		t.Fatalf("swg.LoadRuntimeConfig: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("logs.NewWriter: %v", err)
	}
	return edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{
			Policies:      policies,
			PolicyBundle:  bundle,
			EdgeRegionID:  "local",
			EdgeClusterID: "local-edge-001",
		},
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		ProxyClient:      siteCompatUpstreamClient(),
		SWGRuntime:       swgRuntime,
		DecisionStore:    newAccessDecisionStore(),
		InspectionEvents: newInspectionEventStore(),
		LabMode:          false, // PRODUCTION posture
		StripAltSvc:      true,  // production default (QUIC disabled)
		// Trusted in-process caller: skip the connector authorization gate (this models the NE/WFP forward,
		// which is authenticated at the (T) transport layer, not by connector creds).
		DeviceAuthenticatedInProcess: true,
	}
}

func siteCompatUpstreamClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Timeout: siteCompatPerHopTO, Transport: transport}
}

// directBaselineClient is the no-proxy baseline client. It returns each hop raw (ErrUseLastResponse) so the
// harness drives the redirect chain identically to the SWG path.
func directBaselineClient() *http.Client {
	c := siteCompatUpstreamClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func TestSWGSiteCompat(t *testing.T) {
	hosts := loadSiteCompatHosts(t)
	if len(hosts) == 0 {
		t.Skip("no sites to test (set SITE_COMPAT_LIST or ship testdata/swg_site_compat_seed.txt)")
	}
	scenario := strings.ToLower(strings.TrimSpace(os.Getenv("SITE_COMPAT_SCENARIO")))
	if scenario == "" {
		scenario = "passthrough"
	}
	scenarios := []string{scenario}
	if scenario == "both" {
		scenarios = []string{"passthrough", "enforce"}
	}

	outDir := filepath.Join("..", "..", "..", "var", "swg-site-compat")
	if d := strings.TrimSpace(os.Getenv("SITE_COMPAT_OUT_DIR")); d != "" {
		outDir = d
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out dir: %v", err)
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc, func(t *testing.T) {
			var cfg edgeSWGHTTPEgressHandlerConfig
			switch sc {
			case "enforce":
				cfg = buildEnforceEgressConfig(t)
			default:
				cfg = buildPassthroughEgressConfig(t)
			}
			handler := newEdgeSWGHTTPEgressHandler(cfg)
			results := runSiteCompat(t, hosts, handler)
			writeSiteCompatReport(t, outDir, sc, results)
		})
	}
}

func runSiteCompat(t *testing.T, hosts []string, handler http.HandlerFunc) []siteResult {
	t.Helper()
	results := make([]siteResult, len(hosts))
	directClient := directBaselineClient()
	directFetch := directHopFetcher(directClient)
	swgFetch := swgHopFetcher(handler)

	sem := make(chan struct{}, siteCompatConcurrent)
	var wg sync.WaitGroup
	for i, host := range hosts {
		i, host := i, host
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start, err := url.Parse("https://" + host + "/")
			if err != nil {
				results[i] = siteResult{Host: host, DirectErr: "bad_host", Note: err.Error()}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			direct := followChain(ctx, start, directFetch)
			swgOut := followChain(ctx, start, swgFetch)
			r := siteResult{
				Host:          host,
				DirectStatus:  direct.finalStatus,
				DirectURL:     direct.finalURL,
				DirectCookies: direct.setCookies,
				DirectErr:     direct.transportErr,
				SWGStatus:     swgOut.finalStatus,
				SWGURL:        swgOut.finalURL,
				SWGCookies:    swgOut.setCookies,
				SWGOutcome:    swgOut.outcome,
				SWGCategory:   swgOut.category,
				SWGErr:        swgOut.transportErr,
			}
			classifySite(&r)
			results[i] = r
		}()
	}
	wg.Wait()
	return results
}

func writeSiteCompatReport(t *testing.T, outDir, scenario string, results []siteResult) {
	t.Helper()
	// CSV
	csvPath := filepath.Join(outDir, scenario+"-results.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		t.Fatalf("create csv: %v", err)
	}
	cw := csv.NewWriter(f)
	_ = cw.Write([]string{"host", "direct_status", "swg_status", "direct_cookies", "swg_cookies", "swg_outcome", "swg_error_category", "direct_err", "swg_err", "regressed", "root_cause", "note"})
	for _, r := range results {
		_ = cw.Write([]string{
			r.Host, strconv.Itoa(r.DirectStatus), strconv.Itoa(r.SWGStatus),
			strconv.Itoa(r.DirectCookies), strconv.Itoa(r.SWGCookies),
			r.SWGOutcome, r.SWGCategory, r.DirectErr, r.SWGErr,
			strconv.FormatBool(r.Regressed), r.RootCause, r.Note,
		})
	}
	cw.Flush()
	_ = f.Close()

	// Aggregate by root cause.
	total := len(results)
	regressed := 0
	excluded := 0
	byCause := map[string]int{}
	var regressedRows []siteResult
	for _, r := range results {
		if r.Note == "direct_baseline_not_ok" {
			excluded++
		}
		if r.Regressed {
			regressed++
			byCause[r.RootCause]++
			regressedRows = append(regressedRows, r)
		}
	}
	tested := total - excluded
	sort.Slice(regressedRows, func(i, j int) bool {
		if regressedRows[i].RootCause != regressedRows[j].RootCause {
			return regressedRows[i].RootCause < regressedRows[j].RootCause
		}
		return regressedRows[i].Host < regressedRows[j].Host
	})

	var b strings.Builder
	fmt.Fprintf(&b, "# SWG サイト互換性レポート (%s)\n\n", scenario)
	fmt.Fprintf(&b, "- 対象サイト: %d / うち直結ベースライン成功(評価対象): %d / 除外(直結も失敗): %d\n", total, tested, excluded)
	fmt.Fprintf(&b, "- プロキシ起因の回帰: **%d** / %d (%.1f%%)\n\n", regressed, tested, pct(regressed, tested))
	fmt.Fprintf(&b, "## 主因別\n\n| 主因 | 件数 |\n|---|---|\n")
	causes := make([]string, 0, len(byCause))
	for c := range byCause {
		causes = append(causes, c)
	}
	sort.Slice(causes, func(i, j int) bool { return byCause[causes[i]] > byCause[causes[j]] })
	for _, c := range causes {
		fmt.Fprintf(&b, "| %s | %d |\n", c, byCause[c])
	}
	fmt.Fprintf(&b, "\n## 回帰サイト一覧\n\n| host | 主因 | direct | swg | outcome/cat | note |\n|---|---|---|---|---|---|\n")
	for _, r := range regressedRows {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %s | %s |\n", r.Host, r.RootCause, r.DirectStatus, r.SWGStatus, firstNonEmpty(r.SWGOutcome, r.SWGCategory), r.Note)
	}
	mdPath := filepath.Join(outDir, scenario+"-summary.md")
	if err := os.WriteFile(mdPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write md: %v", err)
	}

	t.Logf("[%s] tested=%d regressed=%d (%.1f%%) excluded=%d\n  CSV: %s\n  MD:  %s",
		scenario, tested, regressed, pct(regressed, tested), excluded, csvPath, mdPath)
	for _, c := range causes {
		t.Logf("  %s: %d", c, byCause[c])
	}
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

// loadSiteCompatHosts reads hosts from SITE_COMPAT_LIST (one host per line, # comments allowed) or falls back
// to the bundled seed list. SITE_COMPAT_TOP_N caps the count (0 = all).
func loadSiteCompatHosts(t *testing.T) []string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("SITE_COMPAT_LIST"))
	if path == "" {
		path = filepath.Join("testdata", "swg_site_compat_seed.txt")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("site list %q not readable: %v", path, err)
		return nil
	}
	var hosts []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept "rank,host" (Tranco CSV) or bare host.
		if i := strings.LastIndex(line, ","); i >= 0 {
			line = strings.TrimSpace(line[i+1:])
		}
		line = strings.TrimPrefix(strings.TrimPrefix(line, "https://"), "http://")
		line = strings.TrimSuffix(line, "/")
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		hosts = append(hosts, line)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SITE_COMPAT_TOP_N"))); err == nil && n > 0 && n < len(hosts) {
		hosts = hosts[:n]
	}
	return hosts
}

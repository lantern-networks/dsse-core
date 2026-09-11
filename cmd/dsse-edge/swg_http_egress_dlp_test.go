package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/inspection"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func newDLPTestConfig(t *testing.T) (edgeSWGHTTPEgressHandlerConfig, *inspection.Store) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() }) // Windows: TempDir cleanup fails while the jsonl handle is open
	store := inspection.NewStore(0)
	return edgeSWGHTTPEgressHandlerConfig{Writer: writer, InspectionEvents: store}, store
}

// dlpDecWithInspect returns a decision carrying a dlp_inspect directive — the policy-gated path that activates the
// DLP hook (now that detection is destination-scoped, a bare decision with no directive is inert). Mirrors what
// the evaluator surfaces from a matching egress DLP rule.
func dlpDecWithInspect(id, tenant, appID, action string, identifiers ...string) model.AccessDecision {
	return model.AccessDecision{ID: id, TenantID: tenant, ApplicationID: appID, Actions: []model.DecisionAction{{
		Type:     "dlp_inspect",
		Metadata: map[string]any{"dlp_rule_id": "r_" + action, "action": action, "identifiers": identifiers},
	}}}
}

func dlpEventByFindingType(events []model.InspectionEvent, ft string) *model.InspectionEvent {
	for i := range events {
		if events[i].FindingType != nil && *events[i].FindingType == ft {
			return &events[i]
		}
	}
	return nil
}

// Observe-only (no interrupting policy): a scannable upload carrying a My Number is detected and recorded as a
// NON-SECRET dlp_match event, and the body forwarded upstream is byte-for-byte unchanged.
func TestEdgeSWGHTTPEgressDLPObserveEmitsMatchAndPassesBodyUnchanged(t *testing.T) {
	config, store := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-1", "tenant-a", "app-1", "observe", "my_number", "credit_card")
	body := `{"my_number":"123456789018","card":"4111111111111111","note":"hello"}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	forwarded, err := io.ReadAll(req.Body) // simulate the upstream client reading (forwarding) the body
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(forwarded) != body {
		t.Fatalf("observe altered the body: got %q want %q", forwarded, body)
	}
	hook.finalizeObserve(context.Background())

	ev := dlpEventByFindingType(store.ListByTenant("tenant-a"), "dlp_match")
	if ev == nil {
		t.Fatalf("no dlp_match event recorded")
	}
	if ev.PayloadStored || !ev.Masked {
		t.Errorf("expected PayloadStored=false, Masked=true")
	}
	raw, _ := json.Marshal(ev.Metadata)
	if strings.Contains(string(raw), "123456789018") || strings.Contains(string(raw), "4111111111111111") {
		t.Errorf("raw secret leaked into event metadata: %s", raw)
	}
	if !strings.Contains(string(raw), "my_number") || !strings.Contains(string(raw), "credit_card") {
		t.Errorf("identifier types missing from non-secret metadata: %s", raw)
	}
	if !strings.Contains(string(raw), `"dlp_action":"observe"`) {
		t.Errorf("expected observe action: %s", raw)
	}
}

// S2 policy-scoped detection: a rule that selects ONLY my_number does not report an incidental credit card that
// the built-in pass also sees — only the rule's chosen identifiers are recorded.
func TestEdgeSWGHTTPEgressDLPRecordsOnlySelectedIdentifiers(t *testing.T) {
	config, store := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-sel", "tenant-a", "app-1", "observe", "my_number") // credit_card NOT selected
	body := `{"my_number":"123456789018","card":"4111111111111111"}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	hook.finalizeObserve(context.Background())

	ev := dlpEventByFindingType(store.ListByTenant("tenant-a"), "dlp_match")
	if ev == nil {
		t.Fatalf("no dlp_match recorded")
	}
	raw, _ := json.Marshal(ev.Metadata)
	if !strings.Contains(string(raw), "my_number") {
		t.Errorf("selected my_number should be reported: %s", raw)
	}
	if strings.Contains(string(raw), "credit_card") {
		t.Errorf("credit_card was NOT selected by the rule but was reported (detection not policy-scoped): %s", raw)
	}
}

// A non-text body is not scanned: no dlp_match is produced even when the bytes contain a valid identifier.
func TestEdgeSWGHTTPEgressDLPSkipsNonTextBody(t *testing.T) {
	config, store := newDLPTestConfig(t)
	dec := model.AccessDecision{ID: "dec-2", TenantID: "tenant-a"}
	body := "123456789018 4111111111111111 binary-ish payload"

	req := httptest.NewRequest(http.MethodPost, "https://cdn.example.com/blob", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	if _, err := io.ReadAll(req.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	hook.finalizeObserve(context.Background())

	if ev := dlpEventByFindingType(store.ListByTenant("tenant-a"), "dlp_match"); ev != nil {
		t.Errorf("dlp_match emitted for non-text body; want skipped")
	}
}

// Review #18: the Content-Type is client-asserted — relabeling a governed text upload as octet-stream must
// not skip the scan. The actual bytes decide: text bodies scan (and the forwarded bytes are unchanged);
// genuinely binary bodies still skip.
func TestEdgeSWGHTTPEgressDLPSniffsMislabeledTextBody(t *testing.T) {
	config, _ := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-sniff", "tenant-a", "", "block", "my_number")
	body := `{"my_number":"123456789018"}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream") // lie: the body is JSON

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	forwarded, err := io.ReadAll(req.Body)
	if !errors.Is(err, dlp.ErrBlocked) {
		t.Fatalf("mislabeled text upload must still trip the block guard, got err=%v body=%q", err, forwarded)
	}
	if !hook.blocked() {
		t.Fatal("hook.blocked() = false, want true for mislabeled text upload")
	}

	// A clean mislabeled text body passes through byte-identical (the sniff prefix must be re-stitched).
	config2, _ := newDLPTestConfig(t)
	clean := `{"note":"nothing sensitive"}`
	req2 := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(clean))
	req2.Header.Set("Content-Type", "application/octet-stream")
	hook2 := installEdgeSWGHTTPEgressDLP(req2, config2, dec)
	forwarded2, err := io.ReadAll(req2.Body)
	if err != nil || string(forwarded2) != clean {
		t.Fatalf("clean sniffed body must forward unchanged: %q err=%v", forwarded2, err)
	}
	if hook2.blocked() {
		t.Fatal("clean sniffed body must not block")
	}

	// Genuinely binary bytes (PNG magic) still skip even under the same policy.
	config3, _ := newDLPTestConfig(t)
	req3 := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader("\x89PNG\r\n\x1a\n123456789018"))
	req3.Header.Set("Content-Type", "application/octet-stream")
	hook3 := installEdgeSWGHTTPEgressDLP(req3, config3, dec)
	if _, err := io.ReadAll(req3.Body); err != nil {
		t.Fatalf("binary body must forward: %v", err)
	}
	if hook3.blocked() || hook3.skipReason == "" {
		t.Fatalf("binary body must skip with a reason, blocked=%v skip=%q", hook3.blocked(), hook3.skipReason)
	}
}

// A GET (no body) is a no-op.
func TestEdgeSWGHTTPEgressDLPNoBodyIsNoop(t *testing.T) {
	config, store := newDLPTestConfig(t)
	dec := model.AccessDecision{ID: "dec-3", TenantID: "tenant-a"}
	req := httptest.NewRequest(http.MethodGet, "https://storage.example.com/list", nil)

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	hook.finalizeObserve(context.Background())

	if store.Count() != 0 {
		t.Errorf("expected no events for a bodyless GET, got %d", store.Count())
	}
}

// Block policy: the guard trips before the secret leaves; respondBlocked returns 403 with a non-secret event.
func TestEdgeSWGHTTPEgressDLPBlockDeniesUpload(t *testing.T) {
	config, store := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-4", "tenant-a", "", "block", "my_number")
	body := `{"my_number":"123456789018"}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	forwarded, err := io.ReadAll(req.Body) // the "upstream client" reading the guarded body
	if !errors.Is(err, dlp.ErrBlocked) {
		t.Fatalf("reading guarded body err = %v, want ErrBlocked", err)
	}
	if strings.Contains(string(forwarded), "123456789018") {
		t.Errorf("secret leaked to the upstream: %q", forwarded)
	}
	if !hook.blocked() {
		t.Fatalf("hook.blocked() = false, want true")
	}
	rec := httptest.NewRecorder()
	hook.respondBlocked(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	ev := dlpEventByFindingType(store.ListByTenant("tenant-a"), "dlp_match")
	if ev == nil {
		t.Fatalf("no dlp_match event on block")
	}
	raw, _ := json.Marshal(ev.Metadata)
	if !strings.Contains(string(raw), `"dlp_action":"block"`) {
		t.Errorf("expected block action in event: %s", raw)
	}
	if strings.Contains(string(raw), "123456789018") {
		t.Errorf("raw secret leaked into block event: %s", raw)
	}
}

// Authenticate policy: respondBlocked returns 401 (step-up required).
func TestEdgeSWGHTTPEgressDLPAuthenticateReturns401(t *testing.T) {
	config, _ := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-5", "tenant-a", "", "authenticate", "my_number")
	body := `{"my_number":"123456789018"}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	if _, err := io.ReadAll(req.Body); !errors.Is(err, dlp.ErrBlocked) {
		t.Fatalf("reading guarded body err = %v, want ErrBlocked", err)
	}
	if !hook.blocked() {
		t.Fatalf("hook.blocked() = false, want true")
	}
	rec := httptest.NewRecorder()
	hook.respondBlocked(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// Review #13: an encrypted/corrupt PDF under an interrupting rule is a DLP bypass vehicle when forwarded
// uninspected. With -dlp-block-uninspectable-files the upload is denied; without it (default) it is
// forwarded but the skip is recorded (fail loud, not silent).
func TestEdgeSWGHTTPEgressDLPUninspectableFile(t *testing.T) {
	newReq := func() *http.Request {
		// A body that claims application/pdf but is not parseable — the extractor errors (as an encrypted or
		// deliberately corrupted PDF would), it does NOT merely classify as binary.
		req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader("%PDF-1.7 not really a pdf 123456789018"))
		req.Header.Set("Content-Type", "application/pdf")
		return req
	}
	dec := dlpDecWithInspect("dec-7", "tenant-a", "", "block", "my_number")

	// Opt-in: uninspectable + interrupting rule => blocked with the "could not be inspected" response.
	config, _ := newDLPTestConfig(t)
	config.DLPBlockUninspectableFiles = true
	hook := installEdgeSWGHTTPEgressDLP(newReq(), config, dec)
	if !hook.blocked() {
		t.Fatalf("uninspectable file under an interrupting rule must be blocked when opted in")
	}
	rec := httptest.NewRecorder()
	hook.respondBlocked(rec, newReq())
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "dlp_uninspectable") {
		t.Errorf("deny response should say the file was uninspectable: %s", rec.Body.String())
	}

	// Default (off): forwarded uninspected, but the skip is recorded on the hook (not silent).
	config2, _ := newDLPTestConfig(t)
	hook2 := installEdgeSWGHTTPEgressDLP(newReq(), config2, dec)
	if hook2.blocked() {
		t.Fatalf("default posture must not block an uninspectable file")
	}
	if hook2.skipReason != "extract_error_not_inspected" {
		t.Errorf("skipReason = %q, want extract_error_not_inspected", hook2.skipReason)
	}

	// An observe-only rule never blocks, opt-in or not.
	config3, _ := newDLPTestConfig(t)
	config3.DLPBlockUninspectableFiles = true
	hook3 := installEdgeSWGHTTPEgressDLP(newReq(), config3, dlpDecWithInspect("dec-8", "tenant-a", "", "observe", "my_number"))
	if hook3.blocked() {
		t.Fatalf("observe-only rule must not block an uninspectable file")
	}
}

// Review #19: a file padded past the inspection cap is uninspectable in exactly the same way as a corrupt
// one, so it gets the same treatment — forward-and-log by default, block under the opt-in.
func TestEdgeSWGHTTPEgressDLPOversizeFile(t *testing.T) {
	// A PDF-typed body larger than the buffering cap. The content is irrelevant — it is never inspected.
	oversize := "%PDF-1.7 " + strings.Repeat("A", edgeSWGHTTPEgressFileInspectCap+1)
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(oversize))
		req.Header.Set("Content-Type", "application/pdf")
		return req
	}
	dec := dlpDecWithInspect("dec-os", "tenant-a", "", "block", "my_number")

	// Opt-in + interrupting rule => blocked as uninspectable.
	config, _ := newDLPTestConfig(t)
	config.DLPBlockUninspectableFiles = true
	hook := installEdgeSWGHTTPEgressDLP(newReq(), config, dec)
	if !hook.blocked() {
		t.Fatalf("oversize file under an interrupting rule must be blocked when opted in")
	}

	// Default (off): forwarded, skip recorded as oversize (fail loud, not silent), and the FULL body still
	// forwards byte-identical (the buffered prefix + remainder are re-stitched).
	config2, _ := newDLPTestConfig(t)
	req2 := newReq()
	hook2 := installEdgeSWGHTTPEgressDLP(req2, config2, dec)
	if hook2.blocked() {
		t.Fatalf("default posture must not block an oversize file")
	}
	if hook2.skipReason != "oversize_not_inspected" {
		t.Errorf("skipReason = %q, want oversize_not_inspected", hook2.skipReason)
	}
	forwarded, err := io.ReadAll(req2.Body)
	if err != nil || string(forwarded) != oversize {
		t.Fatalf("oversize body must forward byte-identical (len got=%d want=%d, err=%v)", len(forwarded), len(oversize), err)
	}
}

// A block policy still lets a clean upload (no governed identifier) through unchanged.
func TestEdgeSWGHTTPEgressDLPBlockPolicyPassesCleanUpload(t *testing.T) {
	config, _ := newDLPTestConfig(t)
	dec := dlpDecWithInspect("dec-6", "tenant-a", "", "block", "my_number")
	body := `{"note":"nothing sensitive here","n":42}`

	req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	hook := installEdgeSWGHTTPEgressDLP(req, config, dec)
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("clean upload under block policy err = %v, want nil", err)
	}
	if string(forwarded) != body {
		t.Errorf("clean upload altered: got %q", forwarded)
	}
	if hook.blocked() {
		t.Errorf("clean upload was blocked")
	}
}

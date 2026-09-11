package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// breakGlassHarness builds a server whose only configured credential is the shared token.
func breakGlassHarness(t *testing.T) http.Handler {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	return newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		AdminAuth:  newAdminAuthStore(),
		AdminToken: "break-glass-secret",
	})
}

func breakGlassCall(t *testing.T, handler http.Handler, method, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("authorization", "Bearer break-glass-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// ★ IT WAS NOT A BREAK-GLASS, IT WAS THE ORDINARY CREDENTIAL (the machine-credential separation, 2026-08-16). Its own comment called it a
// path for when the durable auth store is unavailable, and it was accepted on every request by virtue of
// being configured — authorising as OWNER and attributing every act to a synthetic principal. A full day of
// PKI work on the reference lab is recorded against admin_legacy_token and answers "who" with nothing.
//
// Using it is a decision now. The secret alone does not authenticate.
func TestTheSharedTokenDoesNothingUnlessItIsArmed(t *testing.T) {
	handler := breakGlassHarness(t)

	previousArmed, previousConfigured := adminBreakGlass.Armed, adminBreakGlass.Configured
	t.Cleanup(func() { adminBreakGlass.Armed, adminBreakGlass.Configured = previousArmed, previousConfigured })

	adminBreakGlass.Armed, adminBreakGlass.Configured = false, true
	if code, body := breakGlassCall(t, handler, http.MethodGet, "/admin/tenants"); code != http.StatusUnauthorized {
		t.Fatalf("a disarmed break-glass token authenticated: HTTP %d %s", code, body)
	}

	// The control, same secret and same route: armed, it works. Without it, "refused" is also what a broken
	// harness looks like.
	adminBreakGlass.Armed = true
	if code, body := breakGlassCall(t, handler, http.MethodGet, "/admin/tenants"); code == http.StatusUnauthorized {
		t.Fatalf("the control failed: an ARMED break-glass token was refused too: HTTP %d %s", code, body)
	}
}

// And using it leaves a mark that says what it was, separately from the ordinary config-change row: "what
// changed" and "was anybody holding the master key today" are different questions, and burying the second in
// a field of the first makes it something you find only if you already suspected it.
func TestEveryBreakGlassActIsRecordedAsOne(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:  testEvaluator(),
		Writer:     writer,
		AdminAuth:  newAdminAuthStore(),
		AdminToken: "break-glass-secret",
	})
	armBreakGlassForTest(t)

	before := adminBreakGlass.uses.Load()
	if code, body := breakGlassCall(t, handler, http.MethodPost, "/admin/tenants"); code == http.StatusUnauthorized {
		t.Fatalf("the armed token was refused: HTTP %d %s", code, body)
	}
	if adminBreakGlass.uses.Load() <= before {
		t.Fatal("the node did not count the acceptance, so 'is anybody still using this' has no answer")
	}

	if !auditTrailContains(t, dir, "admin_break_glass_used") {
		t.Fatal("an act performed with the shared token left no break-glass record — it is indistinguishable " +
			"from a named administrator's work except by a synthetic principal id nobody reads")
	}
}

// The armed state has to be ASKABLE. Before this it was discoverable only by reading a boot-time log line on
// a node somebody set up months ago, which is to say not discoverable.
func TestTheArmedStateIsReportedRatherThanInferred(t *testing.T) {
	handler := breakGlassHarness(t)
	armBreakGlassForTest(t)

	code, body := breakGlassCall(t, handler, http.MethodGet, "/admin/break-glass-token")
	if code != http.StatusOK {
		t.Fatalf("HTTP %d %s", code, body)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report["armed"] != true || report["configured"] != true {
		t.Fatalf("the report does not state the armed condition: %v", report)
	}
	if note, _ := report["note"].(string); !strings.Contains(note, "cannot answer") && !strings.Contains(note, "names no person") {
		t.Fatalf("the report does not say what is wrong with using it: %q", note)
	}
}

// auditTrailContains reports whether any audit line in dir mentions the event type.
func auditTrailContains(t *testing.T, dir, eventType string) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if grepAuditFiles(t, dir, eventType) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// grepAuditFiles walks the log directory looking for the event type. It walks rather than reading one file
// because the writer partitions by tenant, and a test that reads only the root file passes on a deployment
// with no tenant model and fails on the one this change is for.
func grepAuditFiles(t *testing.T, dir, needle string) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr == nil && strings.Contains(string(raw), needle) {
			found = true
		}
		return nil
	})
	return found
}

// ★ THE MIGRATION IS ONLY AS GOOD AS THE NAME IN THE RECORD (the machine-credential separation, found on the lab). Moving the lab's
// automation off the shared break-glass token replaced a synthetic principal with an opaque principal id: the
// uniform config-change audit resolved the caller's email only for SESSIONS, so an act performed by a named
// API token said "adm_1e9a9d56…" and a reader still could not tell who. A token belongs to a principal
// exactly as a session does.
func TestAnApiTokensActsNameThePersonBehindThem(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	now := time.Now().UTC()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_human", TenantID: "tenant_lab_001", Subject: "sub_human",
		Email: "a.person@example.invalid", Roles: []string{"admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_automation", TenantID: "tenant_lab_001", Name: "automation",
		TokenHash: adminTokenHash("automation-secret"), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_human",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth})

	req := httptest.NewRequest(http.MethodPost, "/admin/enrolment-tokens", strings.NewReader(`{"expires_in_hours":1}`))
	req.Header.Set("authorization", "Bearer automation-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("the harness token did not authenticate: %s", rec.Body.String())
	}

	if !auditTrailContains(t, dir, "a.person@example.invalid") {
		t.Fatal("an act performed by a named API token records an opaque principal id and no person — which " +
			"is the question the whole migration off the shared token exists to answer")
	}
}

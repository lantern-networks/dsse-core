package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Reported by the operator, looking at the AI service usage screen: "I only used Claude and ChatGPT in Chrome on
// Windows — why is there a row with a blank app, and why three rows per service for one session?"
//
// The table keyed on (identity, device, app, service, AI account), and two of those change WITHIN a session. The
// account is only visible on requests that carry its token — a chat is hundreds of requests and most of them are
// assets and polling, which carry none — and the endpoint agent omits the app when it cannot resolve the
// process. So one browser, one session, produced three rows: unattributed, app-known, and app-and-account-known.
func aiActivityRow(user, device, app, service, account, method string, at time.Time) map[string]any {
	md := map[string]any{"http_method": method, "bytes_sent": 10, "bytes_received": 20}
	if app != "" {
		md["ai_app"] = app
	}
	if account != "" {
		md["ai_account"] = account
		md["ai_name"] = account
	}
	return map[string]any{
		"tenant_id": "acme", "saas_application_id": service, "saas_name": service,
		"user_id": user, "device_id": device,
		"timestamp": at.Format(time.RFC3339), "metadata": md,
	}
}

func TestActivityRowsFromOneSessionCollapseToOne(t *testing.T) {
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	const user, device, svc = `WIN-DEV-01\jdoe`, "win-dev-1", "saas_anthropic_claude"
	rows := []map[string]any{
		// the shape actually observed: some flows lost the app, most carried no account, a few carried both
		aiActivityRow(user, device, "", svc, "", "GET", base),
		aiActivityRow(user, device, "chrome.exe", svc, "", "GET", base.Add(time.Minute)),
		aiActivityRow(user, device, "chrome.exe", svc, "Shin Kusanagi", "POST", base.Add(2*time.Minute)),
	}
	report := buildAIUsageReport(rows, []model.SaaSCatalogEntry{{SaaSApplicationID: svc, AIService: true}}, "2026-08-08T12:00:00Z")

	if len(report.ByActivity) != 1 {
		for _, a := range report.ByActivity {
			t.Logf("row: app=%q account=%q accesses=%d", a.App, a.AIAccount, a.Accesses)
		}
		t.Fatalf("one browser in one session produced %d activity rows, want 1", len(report.ByActivity))
	}
	got := report.ByActivity[0]
	if got.App != "chrome.exe" {
		t.Fatalf("app = %q, want chrome.exe — an unattributed flow is unknown, not a different app", got.App)
	}
	if got.AIAccount != "Shin Kusanagi" {
		t.Fatalf("ai_account = %q, want the account that WAS seen — the requests that carried no token are not a second activity", got.AIAccount)
	}
	if got.Accesses != 3 {
		t.Fatalf("accesses = %d, want all 3 — merging must not drop counts", got.Accesses)
	}
	if got.Sessions != 1 {
		t.Fatalf("sessions = %d, want 1 — the merged rows share one 30-minute bucket and a bucket is a set", got.Sessions)
	}
	if got.Messages != 1 || got.BytesSent != 30 {
		t.Fatalf("measures did not survive the merge: messages=%d bytes_sent=%d", got.Messages, got.BytesSent)
	}
}

// The case this table exists for must survive. Two accounts on the SAME browser is shadow AI — a corporate
// person also signed into a personal account — and collapsing that would delete the signal the screen is for.
func TestTwoAccountsOnOneBrowserStayApart(t *testing.T) {
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	const user, device, svc = "alice", "mac-1", "saas_openai_chatgpt"
	rows := []map[string]any{
		aiActivityRow(user, device, "chrome", svc, "alice@corp.example", "POST", base),
		aiActivityRow(user, device, "chrome", svc, "alice@gmail.com", "POST", base.Add(time.Minute)),
		// an unattributed flow alongside them: with TWO candidates, merging it would be a guess about which
		aiActivityRow(user, device, "chrome", svc, "", "GET", base.Add(2*time.Minute)),
	}
	report := buildAIUsageReport(rows, []model.SaaSCatalogEntry{{SaaSApplicationID: svc, AIService: true}}, "2026-08-08T12:00:00Z")
	if len(report.ByActivity) != 3 {
		for _, a := range report.ByActivity {
			t.Logf("row: app=%q account=%q accesses=%d", a.App, a.AIAccount, a.Accesses)
		}
		t.Fatalf("got %d rows, want 3 — two known accounts must stay apart, and the unknown one must not be guessed into either", len(report.ByActivity))
	}
}

// Same rule for the app: two apps reached this service, so a flow with no app cannot be assigned to one.
func TestUnattributedAppIsNotGuessedWhenTwoAppsAreKnown(t *testing.T) {
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	const user, device, svc = "alice", "mac-1", "saas_anthropic_claude"
	rows := []map[string]any{
		aiActivityRow(user, device, "chrome", svc, "", "GET", base),
		aiActivityRow(user, device, "curl", svc, "", "GET", base.Add(time.Minute)),
		aiActivityRow(user, device, "", svc, "", "GET", base.Add(2*time.Minute)),
	}
	report := buildAIUsageReport(rows, []model.SaaSCatalogEntry{{SaaSApplicationID: svc, AIService: true}}, "2026-08-08T12:00:00Z")
	if len(report.ByActivity) != 3 {
		t.Fatalf("got %d rows, want 3 — with chrome AND curl present, an unattributed flow belongs to neither", len(report.ByActivity))
	}
}

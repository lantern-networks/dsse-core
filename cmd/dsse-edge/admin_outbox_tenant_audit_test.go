package main

import "testing"

func TestOutboxReplayAuditBelongsToReplayedTenant(t *testing.T) {
	evaluator := testEvaluator()
	evaluator.PolicyBundle.TenantID = "node-default"
	const selectedTenant = "operator-selected"
	adminAudit := adminAuditOutboxReplayAuditLog(postgresAdminAuditOutboxReplayResult{
		TenantID: selectedTenant,
		OutboxID: "audit-dead",
	}, evaluator, "operator", "127.0.0.1", "test", "retry")
	if adminAudit.TenantID != selectedTenant {
		t.Fatalf("admin outbox replay audit tenant = %q, want %q", adminAudit.TenantID, selectedTenant)
	}
	domainAudit := domainEventOutboxReplayAuditLog(postgresDomainEventOutboxReplayResult{
		TenantID: selectedTenant,
		OutboxID: "domain-dead",
	}, evaluator, "operator", "127.0.0.1", "test", "retry")
	if domainAudit.TenantID != selectedTenant {
		t.Fatalf("domain outbox replay audit tenant = %q, want %q", domainAudit.TenantID, selectedTenant)
	}
}

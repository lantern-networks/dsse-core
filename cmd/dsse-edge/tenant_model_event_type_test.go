package main

import (
	"testing"
	"time"
)

// ★★ AN EVENT TYPE IS A KEY, NOT A SENTENCE (2026-08-17, read off a customer's own audit screen).
//
// The builder appended "d" to the action to make the past tense — right for create/update/delete/purge, and
// wrong for every act on the operator envelope, which passes an action that is ALREADY past tense. All four
// became "…grantedd", "…endedd", "…approvedd", "…changedd".
//
// Those are the governance rows: what the company running this service did inside a customer's organization.
// An event type is the stable key a label map, an export and a retention rule all match on, so a misspelt one
// is a row nothing can classify — which is how it reached the screen as raw English prose next to a customer's
// Japanese audit log.
func TestTheEventTypeIsThePastTenseOfTheActionAndNotTheActionPlusAD(t *testing.T) {
	cases := map[string]string{
		// The ordinary lifecycle, unchanged.
		"create": "admin_tenant_model_created",
		"update": "admin_tenant_model_updated",
		"delete": "admin_tenant_model_deleted",
		"purge":  "admin_tenant_model_purged",
		// The operator envelope: already past tense, so nothing is appended.
		"operator_delegation_changed": "admin_tenant_model_operator_delegation_changed",
		"operator_elevation_granted":  "admin_tenant_model_operator_elevation_granted",
		"operator_elevation_approved": "admin_tenant_model_operator_elevation_approved",
		"operator_elevation_ended":    "admin_tenant_model_operator_elevation_ended",
	}
	for action, want := range cases {
		record := adminTenantModelLifecycleAuditLog(adminTenantModel{TenantID: "tenant_x"}, action, testEvaluator(), time.Now())
		if record.EventType != want {
			t.Errorf("action %q produced event_type %q, want %q", action, record.EventType, want)
		}
		// The action itself stays exactly what the caller passed — it is the other half of the record and is
		// not the place to do grammar.
		if record.Action == nil || *record.Action != action {
			t.Errorf("action %q was rewritten to %v", action, record.Action)
		}
	}
}

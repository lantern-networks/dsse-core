package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Keep the rule identity and outcome without recording private selectors or names.
func authoredRuleAuditLog(r *http.Request, rule policyrule.Rule, operation, result string, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	encoded, _ := json.Marshal(rule)
	target := rule.ID
	if target == "" {
		target = "new_rule"
	}
	metadata := map[string]any{"plane": ruleAuditEnum(rule.Plane, "egress", "east_west"), "status": ruleAuditEnum(rule.Status, "active", "disabled"), "access": ruleAuditEnum(rule.Action.Access, "allow", "deny", "authenticate"), "inspection": ruleAuditEnum(rule.Action.Inspection, "inspect", "bypass"), "source_count": len(rule.Source), "destination_count": len(rule.Destination), "rule_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded))}
	return model.AuditLog{ID: randomEdgeID("audit_", now), TenantID: rule.TenantID, ActorUserID: auditActorPrincipal(r), EventType: "admin_authored_rule_changed", TargetType: stringPtr("authored_rule"), TargetID: &target, Action: &operation, Result: &result, Timestamp: now.UTC().Format(time.RFC3339), EdgeRegionID: &evaluator.EdgeRegionID, EdgeClusterID: &evaluator.EdgeClusterID, Metadata: metadata}
}

func ruleAuditEnum(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

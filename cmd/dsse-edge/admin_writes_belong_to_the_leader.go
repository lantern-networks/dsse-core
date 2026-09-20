package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_writes_belong_to_the_leader.go — an administrative write is authored where leadership is.
//
// ★★★ A BLOCK ACCEPTED BY A STANDBY IS A BLOCK THAT NEVER HAPPENS (2026-08-26, measured with its control on
// the two-region lab):
//
//	the same device, blocked on the STANDBY  -> 200, and still admitted two minutes later
//	the same device, blocked on the LEADER   -> 200, and refused fifteen seconds later
//
// The deployment's authored state is held by whoever holds leadership. A standby re-reads it on a timer, so
// its own writes are what the next re-read overwrites — and the leader, correctly, never re-reads at all,
// because it is the author. The write is therefore accepted, recorded, shown on the screen that made it, and
// discarded. For a security control that is the worst of the three possible outcomes: an administrator who
// blocks a machine has been told it is stopped, and it is not.
//
// ★ AN OPERATOR USING THE CONSOLE NEVER MEETS THIS. The Console talks to the front door, which health-checks
// GET /leader and routes there. What meets it is anything addressing a control plane DIRECTLY — a script, a
// check, an operator who noted a node's address, or a front door in a region that has lost leadership.
//
// So a node that is not the leader REFUSES the write and says where the leader is. Refusing is not a
// limitation to apologise for: it is the difference between a control that failed and a control that lied.

// adminWriteRefusedOnAStandby reports the refusal and returns true when the caller must stop.
//
// This guard applies only to write permissions. Individual read routes must also
// check authority when their state is not refreshed on a standby, as admission
// and risk do; a healthy local snapshot alone does not establish currentness.
func adminWriteRefusedOnAStandby(w http.ResponseWriter, permission string) bool {
	if !adminPermissionWrites(permission) {
		return false
	}
	if cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		// No election here means this node is the only author there is — a single control plane, which is the
		// ordinary shape of a small deployment and must keep working exactly as it did.
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf(
		"this control plane does not hold leadership, and an administrative change written here would be "+
			"accepted and then discarded — the deployment's authored state belongs to the node that leads, and "+
			"this one re-reads it. Send this to the leader: the Console reaches it through the front door, and "+
			"GET /leader answers 200 only there"))
	return true
}

// recordAdminStandbyRefusal records a routing decision, not a judged credential or
// attempted configuration change. The guard runs before identity/tenant resolution:
// only the node's configured audit scope and the server-registered permission are
// known. Deliberately accept no request, so bodies, paths, credentials, user-agent,
// forwarded addresses and claimed tenant/actor cannot enter this record.
func recordAdminStandbyRefusal(writer *logs.Writer, evaluator decision.Evaluator, permission string, now, first, last time.Time, count uint64) {
	if writer == nil {
		logErrorf("admin_audit_write_failed event=%q: audit writer is not configured", "admin_write_refused_on_standby")
		logErrorf("standby audit summary unconfirmed permission=%q request_count=%d", permission, count)
		return
	}
	audit := model.AuditLog{
		ID:            randomEdgeID("audit_admin_write_refused_on_standby_", now),
		TenantID:      evaluator.PolicyBundle.TenantID,
		EventType:     "admin_write_refused_on_standby",
		TargetType:    stringPtr("admin_endpoint"),
		Action:        stringPtr("admin_route"),
		Result:        stringPtr("refused"),
		Reason:        stringPtr("not_leader"),
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		Timestamp:     now.UTC().Format(time.RFC3339Nano),
		Metadata: map[string]any{
			"audit_scope":         "node",
			"authentication":      "not_evaluated",
			"request_tenant":      "not_evaluated",
			"required_permission": permission,
			"http_status":         http.StatusConflict,
			"aggregation":         "permission_window",
			"request_count":       count,
			"first_seen":          first.UTC().Format(time.RFC3339Nano),
			"last_seen":           last.UTC().Format(time.RFC3339Nano),
			"interval_seconds":    int(adminStandbyAuditInterval / time.Second),
		},
	}
	// No synchronous authority/outbox call on this pre-authentication path. The
	// node-local JSONL and its configured append hooks remain in use. Local failure
	// is reported by the shared writer health/error path and cannot undo the 409.
	if err := appendAdminAudit(context.Background(), writer, nil, audit, now); err != nil {
		logErrorf("standby audit summary unconfirmed permission=%q request_count=%d first_seen=%s last_seen=%s", permission, count, first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano))
	}
}

// adminPermissionWrites reports whether a permission names a change rather than a question.
//
// By the scope's own suffix, so a permission added tomorrow is covered the day it exists rather than the day
// somebody remembers to add it to a list here.
func adminPermissionWrites(permission string) bool {
	p := strings.ToLower(strings.TrimSpace(permission))
	for _, suffix := range []string{".write", ".admin", ".cancel", ".create", ".review"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

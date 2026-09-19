package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func adminSetEnrolledDeviceEnabled(w http.ResponseWriter, r *http.Request, ledger *enrolledinventory.Ledger, writer *logs.Writer, outbox adminAuditOutboxDeadReader, evaluator decision.Evaluator, or503 func(http.ResponseWriter) bool, enabled bool) {
	if !pinnedTenantContextMatches(w, r) {
		return
	}
	if !or503(w) {
		return
	}
	identity := strings.TrimSpace(r.PathValue("identity"))
	// Tenant isolation (review finding #2): a device in another tenant is treated as not-found so this admin can't
	// enable/disable it (empty tenant on either side stays visible — lockout-safe, same rule as device groups).
	if cur, ok := ledger.EntryFor(identity); !ok || !deviceGroupVisibleToTenant(cur.TenantID, adminTenantIDFromRequest(r)) {
		writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
		return
	}
	// ★ THE MANUAL REVOCATION PATH MUST NOT REPORT SUCCESS IT DID NOT ACHIEVE (2026-08-13, twenty-seventh
	// review). This used to take a best-effort write: an operator disabling a compromised device got 200 and a
	// success audit record whether or not the change was recorded, and the next restart readmitted the machine
	// with an audit trail saying it had been revoked.
	entry, serr := ledger.SetEnabledContext(r.Context(), identity, adminTenantIDFromRequest(r), enabled, time.Now().UTC().Format(time.RFC3339))
	if errors.Is(serr, enrolledinventory.ErrIdentityNotFound) {
		writeError(w, http.StatusNotFound, fmt.Errorf("identity %q is not in the enrolled inventory", identity))
		return
	}
	if serr != nil {
		writeError(w, http.StatusInternalServerError, serr)
		return
	}
	tenantID := adminTenantIDFromRequest(r)
	action := "disable"
	if enabled {
		action = "enable"
	}
	record := enrolledInventoryAuditLog(tenantID, action, entry, evaluator, sourceIPFromRequest(r))
	record.ActorUserID = auditActorPrincipal(r)
	_ = appendAdminAudit(r.Context(), writer, outbox, record, time.Now().UTC())
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_enrolled_inventory.v1", "device": entry, "tenant_id": adminTenantIDFromRequest(r)})
}

// enrolledInventoryAuditLog records an admin enroll/enable/disable/remove of the Enrolled Inventory (
// lifecycle is audited).
func enrolledInventoryAuditLog(tenantID, action string, entry enrolledinventory.Entry, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	act := "enrolled_inventory_" + action
	result := "success"
	reason := "Enrolled Inventory updated by admin."
	targetType := "device"
	id := entry.Identity
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       tenantID,
		EventType:      "enrolled_inventory_updated",
		TargetType:     &targetType,
		TargetID:       &id,
		Action:         &act,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"action":  action,
			"enabled": entry.Enabled,
		},
	}
}

// A failed save can follow an applied local mutation, including an unconfirmed
// backend write. Do not describe either local application or persistence as absent.
var errEnrolledMutationPartial = errors.New("The change is active on this node, but saving could not be confirmed. Reload to review the current state and retry after storage is available.")

func appendEnrolledMutationAudit(r *http.Request, writer *logs.Writer, outbox adminAuditOutboxDeadReader, evaluator decision.Evaluator, action string, entry enrolledinventory.Entry, applied bool, saveErr error) {
	record := enrolledInventoryAuditLog(adminTenantIDFromRequest(r), action, entry, evaluator, sourceIPFromRequest(r))
	record.ActorUserID = auditActorPrincipal(r)
	record.Metadata["applied_locally"] = applied
	switch action {
	case "enroll", "assign_group":
		record.Metadata["group"] = entry.Group
	case "set_kind":
		kind := entry.Kind
		if kind == "" {
			kind = enrolledinventory.KindEndpoint
		}
		record.Metadata["kind"] = kind
	}
	if saveErr != nil {
		result, reason := "failed", "Saving could not be confirmed; the previous local state is still in use."
		if applied {
			result, reason = "partial", errEnrolledMutationPartial.Error()
		}
		record.Result, record.Reason = &result, &reason
		record.Metadata["persistence_error"] = true
	}
	_ = appendAdminAudit(r.Context(), writer, outbox, record, time.Now().UTC())
}

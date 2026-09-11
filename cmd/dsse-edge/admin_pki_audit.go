package main

import (
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// Who rotated the CA, and when.
//
// Neither of the two operations that change what endpoints trust left any record at all. Rotating the
// interception intermediate — the signer behind every certificate a steered endpoint accepts — wrote nothing,
// not even a log line. Replacing the certificate a component serves was versioned, so there was a record of
// WHAT changed and none of who changed it.
//
// That is the wrong way round for these particular acts. A certificate replacement can be reasoned about
// afterwards from the versions; a CA rotation cannot be reasoned about at all if nobody wrote it down, and it
// is precisely the operation somebody will ask about six months later when a certificate nobody recognises
// turns up in a capture.
//
// recordPKIMaterialChange writes the entry. Named for what it does rather than ending in AuditLog, because in
// this package that suffix means "builds an entry" — and the inventory check that enforces every builder is
// covered by the non-secret invariant reads exactly that convention.
//
// The metadata is non-secret by construction: names, fingerprints and counts, never key material. An audit
// entry that has to be handled as a secret is an audit entry people stop reading.
func recordPKIMaterialChange(writer *logs.Writer, r *http.Request, evaluator decision.Evaluator, tenantID, action, targetType, targetID, reason string, metadata map[string]any) {
	if writer == nil {
		return
	}
	_ = writer.Append("audit.log.jsonl", pkiMaterialAuditLog(tenantID, action, targetType, targetID, reason,
		metadata, principalIDForAudit(r), sourceIPFromRequest(r), evaluator))
}

// principalIDForAudit names the administrator behind the act, on the same terms as every other admin action.
func principalIDForAudit(r *http.Request) string {
	if identity, ok := adminIdentityFromRequest(r); ok {
		return identity.PrincipalID
	}
	return ""
}

// pkiMaterialAuditLog builds the entry. Split from the append so it is a pure function of its inputs, which is
// what lets the audit non-secret invariant test assert on it — and PKI metadata is exactly where key material
// would leak if anybody ever put it there.
func pkiMaterialAuditLog(tenantID, action, targetType, targetID, reason string, metadata map[string]any,
	principalID, sourceIP string, evaluator decision.Evaluator) model.AuditLog {
	act := action
	result := "success"
	tt, tid, rsn := targetType, targetID, reason
	meta := map[string]any{"action": action}
	for k, v := range metadata {
		meta[k] = v
	}
	if principalID != "" {
		meta["principal_id"] = principalID
	}
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       tenantID,
		EventType:      "pki_material_changed",
		TargetType:     &tt,
		TargetID:       &tid,
		Action:         &act,
		Result:         &result,
		Reason:         &rsn,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata:       meta,
	}
}

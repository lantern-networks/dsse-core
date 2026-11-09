package main

// a_node_tells_only_its_operator_what_it_is.go — /healthz and /metrics answer anybody with whether the node
// can take traffic, and answer what the node IS only to the deployment's operator.
//
// ★★★ EVERY MOUTH OF THIS DEPLOYMENT IS 443, AND 443 IS OPEN TO EVERYBODY (2026-11-09, found by counting who
// reached a lab whose entrance was open to the internet). /healthz carried the build commit, the machine's name,
// the regions, the control channel and audit destinations, the database's replica members and the node's
// counters, and /metrics carried the decision rates. Both were written for "the management network", and the
// comments said so. There is no management network: the admin listener is reached through the same public
// entrance as everything else, by name, and a caller with no name at all is handed the transport listener —
// which answered /healthz too. In twelve and a half hours 184 sources reached the entrance; every one of them
// could have read the deployment's shape and its exact build without presenting anything.
//
// Who reads what was counted before choosing the rule:
//
//	the entrance's health checks, the start script's wait, the Windows and macOS agents' probes
//	    -> the status code only. They keep getting it from anybody, unchanged.
//	dsse-install -verify
//	    -> the fields. It already holds the deployment's credentials, and now presents one.
//
// So the status code and {"status": ...} stay public — a balancer that has to authenticate to learn whether to
// send traffic is a balancer that drains the fleet when the authority moves — and the rest is for a caller that
// the node's ordinary administrator authentication resolves to the OPERATOR's organization. A customer
// organization's administrator is an administrator of that organization, not of the machines it runs on.
//
// It is not a new credential and not a quota: the credentials are the ones every administrative route on this
// node already accepts (a session, a named API token — the fleet's own included — or the break-glass bearer
// while it is armed), resolved by the same code — and judged by the same rules. What a node says about itself
// is what GET /admin/state says, so it is gated on the permission that route is gated on, admin.state.read,
// held by the role AND granted to the token (review HEALTH-R1, 2026-11-09: a valid token of the operator's
// organization scoped to admin.logs.read alone read ten fields and the metrics, while /admin/state told it 403).

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// nodeDetailReader answers whether this request may see what a node says about itself beyond its status.
type nodeDetailReader func(*http.Request) bool

func newNodeDetailReader(evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader,
	adminAuth adminAuthRuntimeStore, adminToken string, devMode bool, credentials *localAdminCredentialStore) nodeDetailReader {
	return func(r *http.Request) bool {
		// Nothing presented, nothing resolved: the entrance probes this every second, and it must not cost a
		// store lookup or a question to the authority to be told the status.
		if !adminRequestCarriedCredentials(r) {
			return false
		}
		identity, ok, err := adminRequestIdentity(r, evaluator.PolicyBundle.TenantID, adminToken, adminAuth, devMode, time.Now())
		if ok && err == nil {
			identity, ok, err = refreshManagedAdminIdentity(r.Context(), adminAuth, credentials, identity)
		}
		if err != nil || !ok {
			// A credential that was presented and did not resolve is the same event the administrative routes
			// record. When the deployment's authority reported that it could not be asked, the credential was
			// not judged, so nothing is recorded (the flag is shared and request-free, as on the admin routes;
			// a session whose introspection failed does not raise it and is recorded as a failure). Either
			// way the caller gets the status, and -verify says it could not read the rest.
			if err == nil && !AuthorityWasUnreachable() {
				_ = appendAdminAudit(context.WithoutCancel(r.Context()), writer, adminAuditOutbox,
					adminAuthFailureAuditLog("admin_auth_failed", evaluator, sourceIPFromRequest(r), r.UserAgent(),
						"node_detail_authentication_failed"), time.Now())
			}
			return false
		}
		if !adminIdentityIsTheOperators(identity) {
			return false
		}
		// The same two gates the administrative routes apply, in the same order: the role must hold the
		// permission, and an API token must have been granted it. A caller who passed authentication and is
		// refused here is recorded as the admin routes record it.
		if !adminPermissionAllowedAny(identity.Roles, nodeDetailPermission) || !adminScopeAllowed(identity, nodeDetailPermission) {
			_ = appendAdminAudit(context.WithoutCancel(r.Context()), writer, adminAuditOutbox,
				adminRBACDeniedAuditLog(identity, nodeDetailPermission, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
			return false
		}
		return true
	}
}

// nodeDetailPermission is what reading a node's own account of itself requires: the permission GET /admin/state
// is gated on. The fleet token and the installation's read-only token both carry it; a token minted for
// something else (logs, exports) does not.
const nodeDetailPermission = "admin.state.read"

// adminIdentityIsTheOperators is the organization half of the rule: the operator's, or — on a deployment with
// no tenant model — the only one there is. The node's own break-glass credential, while it is armed, is the
// deployment's owner secret and so the operator's by definition: it is what a node started before any
// organization exists (and before -operator-tenant-id names one) is administered with.
func adminIdentityIsTheOperators(identity adminIdentity) bool {
	switch strings.TrimSpace(identity.AuthMethod) {
	case adminLabBypassAuthMethod, "legacy_admin_token":
		return true
	}
	if operatorTenantlessMode.Load() {
		return true
	}
	operator := operatorTenantConfigured()
	return operator != "" && strings.TrimSpace(identity.TenantID) == operator
}

// writeNodeHealth writes a /healthz answer: the same status code for everybody, and the body's fields beyond
// "status" only for the operator.
func writeNodeHealth(w http.ResponseWriter, code int, body map[string]any, detailed bool) {
	if detailed {
		writeJSON(w, code, body)
		return
	}
	writeJSON(w, code, map[string]any{"status": body["status"]})
}

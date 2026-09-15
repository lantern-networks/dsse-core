package main

import (
	"flag"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_break_glass_token.go — the shared -admin-token, and the arming it never had.
//
// ★ IT WAS NOT A BREAK-GLASS, IT WAS THE ORDINARY CREDENTIAL (the machine-credential separation). Its own comment called it "a Phase 1
// break-glass path when the durable Admin Auth Store is unavailable", and in practice it was accepted on every
// request, authorised as OWNER of the node's organization, and attributed every act to a synthetic principal
// named admin_legacy_token. A full day of PKI work on the reference lab — revoking an interception authority,
// withdrawing a device CA, acknowledging a fleet-wide anchor — is recorded with no human in it.
//
// Nothing about that was a decision anybody made. It was the path of least resistance, kept open because the
// alternatives did not work (the Edge had no durable auth store, a token an operator minted for a customer
// could not authenticate, and every either-of route refused API tokens outright — all three now fixed).
//
// So: the secret still exists, and using it is now a decision. Off unless armed, every act it performs is
// recorded AS break-glass rather than as an ordinary config change, and the armed state is visible instead of
// being something you discover by reading a process log.
type adminBreakGlassFlags struct {
	armed *bool
}

func registerAdminBreakGlassFlags() adminBreakGlassFlags {
	return adminBreakGlassFlags{
		// ★ DEFAULT FALSE, AND THAT IS THE WHOLE CHANGE. A deployment that passes -admin-token and nothing else
		// finds the token inert after an upgrade — which is the point, and why the node says so loudly at boot
		// rather than answering 401 to somebody who has no idea why. It is not a startup failure: refusing to
		// start would turn a credential change into an outage, and this repository has already learned that a
		// diagnostic which crash-loops a running deployment is worse than the defect it reports.
		armed: flag.Bool("admin-token-break-glass-armed", false,
			"accept -admin-token as an owner-level break-glass credential. OFF by default: it authorises as "+
				"owner of this node's organization and attributes every act to a synthetic principal, so it is "+
				"for the case where the admin auth store is genuinely unreachable, not for ordinary use. Named "+
				"principals and API tokens are the ordinary path. Every act performed with it is audited as "+
				"break-glass and the armed state is reported by GET /admin/break-glass-token"),
	}
}

// adminBreakGlassState is what the node knows about the shared token right now.
type adminBreakGlassState struct {
	// Configured is true when a secret was supplied at all.
	Configured bool
	// Armed is true when it will actually be accepted.
	Armed bool
	// uses counts accepted authentications since boot, so "is anybody still using this" has an answer that is
	// not "read the logs".
	uses atomic.Int64
	// lastUsed is the RFC3339 time of the most recent acceptance, empty if never.
	lastUsed atomic.Value
}

var adminBreakGlass = &adminBreakGlassState{}

// configureAdminBreakGlass records the boot-time decision and says it out loud.
//
// Said at boot rather than only on use, because the dangerous state is the one nobody is looking at: a token
// armed on a node somebody set up two years ago is exactly what an audit finds and an operator does not.
func configureAdminBreakGlass(token string, armed bool, hasOtherWayIn bool) {
	adminBreakGlass.Configured = strings.TrimSpace(token) != ""
	adminBreakGlass.Armed = adminBreakGlass.Configured && armed
	switch {
	case adminBreakGlass.Armed:
		log.Printf("admin_auth ★ BREAK-GLASS TOKEN IS ARMED — -admin-token is accepted as OWNER of this node's " +
			"organization and every act performed with it is attributed to a synthetic principal, not a person. " +
			"Ordinary administration should use a named principal or API token; disarm this with " +
			"-admin-token-break-glass-armed=false once it does.")
	case adminBreakGlass.Configured && !hasOtherWayIn:
		// The one combination that can leave a node with no way in at all. Loud, and still not fatal: the
		// operator has host access by definition, and a refusal to start would make an upgrade an outage.
		log.Printf("admin_auth ★ WARNING: -admin-token is set but NOT armed, and this node has no durable admin " +
			"auth store, so nothing else can authenticate here either. Admin requests will be refused until you " +
			"either arm the break-glass (-admin-token-break-glass-armed) or configure -admin-auth-store.")
	case adminBreakGlass.Configured:
		log.Printf("admin_auth break-glass token configured and NOT armed — it is inert. Named principals and " +
			"API tokens authenticate normally; arm it with -admin-token-break-glass-armed only when the admin " +
			"auth store is unreachable.")
	}
}

// adminBreakGlassAccepted records one acceptance.
func adminBreakGlassAccepted(now time.Time) {
	adminBreakGlass.uses.Add(1)
	adminBreakGlass.lastUsed.Store(now.UTC().Format(time.RFC3339))
}

// adminBreakGlassReport is the answer GET /admin/break-glass-token gives.
func adminBreakGlassReport() map[string]any {
	lastUsed, _ := adminBreakGlass.lastUsed.Load().(string)
	report := map[string]any{
		"schema_version":  "admin_break_glass_token.v1",
		"configured":      adminBreakGlass.Configured,
		"armed":           adminBreakGlass.Armed,
		"uses_since_boot": adminBreakGlass.uses.Load(),
		"last_used_at":    lastUsed,
	}
	switch {
	case adminBreakGlass.Armed:
		report["note"] = "Armed. It authorises as owner of this node's organization and its acts are attributed " +
			"to a synthetic principal rather than a person — so an act performed with it cannot answer 'who'. " +
			"Disarm it once named credentials are in place."
	case adminBreakGlass.Configured:
		report["note"] = "Configured and inert. Named principals and API tokens are the way in."
	default:
		report["note"] = "No break-glass token is configured on this node."
	}
	return report
}

// adminBreakGlassUseAuditLog records one act performed with the shared token.
//
// A distinct action rather than a field on the ordinary config-change row, because the question it answers is
// a different question. "What changed" is answered by the config-change trail; this answers "was anybody
// holding the master key today", and burying that in a field makes it something you find only if you already
// suspected it.
func adminBreakGlassUseAuditLog(identity adminIdentity, method, path string, evaluator decision.Evaluator,
	tenantID, sourceIP, userAgent string) model.AuditLog {
	path, _ = accessGrantAuditPath(path)
	action := "admin_break_glass"
	result := "success"
	reason := "shared break-glass token accepted"
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = evaluator.PolicyBundle.TenantID
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_admin_break_glass_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   stringPtr(identity.PrincipalID),
		EventType:     "admin_break_glass_used",
		TargetType:    stringPtr("admin_route"),
		TargetID:      stringPtr(method + " " + path),
		Action:        &action,
		Result:        &result,
		Reason:        &reason,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"auth_method": identity.AuthMethod,
			"user_agent":  userAgent,
			"note": "Performed with the shared break-glass token. It authorises as owner and names no person, " +
				"so this record cannot answer who did it — only that somebody holding the token did.",
		},
	}
}

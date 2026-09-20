package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// The Console's side of the enrolment authority: an admin issues a token for a machine they are approving, hands
// it to whoever is doing the kitting, and can kill it if the config file goes astray before it is used.
//
// The secret is returned by exactly ONE response — the issuance — and is not recoverable afterwards, because the
// Edge keeps only its hash. A lost token is re-issued, not looked up. That is deliberate: a list endpoint that
// could hand back working credentials would make a Console session, or a state backup, as good as the tokens
// themselves.
// maxEnrolmentTokenBatch bounds one request. Generous enough for a real kitting run and small enough that a
// mistyped figure cannot mint thousands of live credentials in one keystroke.
const maxEnrolmentTokenBatch = 500

// enrolsForTenant is the organization THIS node's POST /enroll was BUILT around, and it is now only a hint.
//
// ★ THE ENFORCEMENT MOVED, AND THIS COMMENT DID NOT (corrected 2026-08-21). It used to be true: the endpoint
// verified the token against this one organization and signed with the node's single device-identity CA. Since
// cross-organization enrolment landed, /enroll takes the organization from the TOKEN — tokens.Verify(token,
// "", now) — and picks that organization's authority with Issuer.SignerFor. A node that holds no authority for
// the organization a token names REFUSES rather than signing under its own, which is the whole point.
//
// What this value still does is say so at the moment a token is minted: an administrator whose organization
// this node cannot enrol for is told here, rather than discovering it when a device is turned on.
//
// ★★ WHY THE TOKEN ROUTES HAVE TO KNOW IT (2026-08-17, measured). A Northwind administrator minted an
// enrolment token through the Console — 200, a real secret, tenant_northwind on the record — and POST /enroll
// answered "invalid or missing eligibility token" for it, because the token belongs to an organization this
// node does not enrol for. A credential that cannot be used by anything, issued with no hint of it, and the
// administrator's next move is to suspect the device.
//
// Not refused: another Edge in the fleet may enrol for that organization, and this node cannot know. Said
// plainly instead, at the moment of issue and on the list, so nobody spends an afternoon on it.
func registerAdminEnrolmentTokenEndpoints(mux *http.ServeMux, tokens enrolltoken.Authority, policy enrolltoken.Policy,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, or503 func(http.ResponseWriter) bool,
	labelForPrincipal func(tenantID, principalID string) string, enrolsForTenant string,
	// The lifecycle store, so a suspended organization stops being able to approve new machines. Passed in
	// rather than reached for: this file had no reason to know about the tenant registry until suspension
	// needed to reach a second admission door.
	tenantModelStore adminTenantModelRuntimeStore,
	// Whether THIS node can issue a device certificate for that organization — the same question /enroll asks
	// before it refuses. Passed in rather than reached for, because the two node roles answer it from different
	// places: a control plane from the per-organization authority it holds, an Edge from the signers the control
	// plane installed in it. Reaching for one of them was the first fix and it was wrong on the node that serves
	// this screen (2026-08-28, measured: the warning stayed on a control plane whose /enroll works).
	nodeIssuesFor func(tenant string) bool,
	// Whether THIS node's registry copy may testify to an absence. Empty means this node is the register; a
	// config-pulling Edge holds a copy nothing distributes to, and its silence is not evidence.
	configSourceURL string,
	// The operator's OWN organization — the one that administers the others. It has no devices, so it cannot
	// approve one. Empty means no operator organization is configured and this gate is off.
	operatorTenantID string) {
	if nodeIssuesFor == nil {
		nodeIssuesFor = func(string) bool { return false }
	}

	tenantOf := adminTenantIDFromRequest
	// WHICH ADMIN authorised this machine is the whole point of the record — months later that is the question an
	// operator has when a device turns up somewhere it should not be. Refuse to issue without it rather than
	// writing an anonymous token: an unattributable approval is not an approval.
	adminOf := func(r *http.Request) string {
		if identity, ok := adminIdentityFromRequest(r); ok {
			return identity.PrincipalID
		}
		return ""
	}
	// WHO that principal is, stored with the token rather than looked up later.
	//
	// A principal id resolves to a person only while the account exists, and approvals outlive the people who
	// granted them — that is the ordinary case, not the edge case. An approval that becomes unattributable the
	// day somebody leaves answers the wrong half of the question this record exists for.
	//
	// It comes from the session the authority already validated. An enforcing Edge has no other route to it:
	// admin accounts live on the authority by design, and the front door sends the account listing there too,
	// so a lookup against this node's own store returns nothing however correct it looks. That was the first
	// implementation, and it silently recorded an empty label on a real deployment.
	adminLabelOf := func(r *http.Request) string {
		if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.PrincipalLabel) != "" {
			return strings.TrimSpace(identity.PrincipalLabel)
		}
		// Local fallback for a single-node deployment where this node IS the authority.
		if labelForPrincipal == nil {
			return ""
		}
		return labelForPrincipal(tenantOf(r), adminOf(r))
	}

	ready := func(w http.ResponseWriter) bool {
		if tokens == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("enrolment tokens are not configured on this Edge"))
			return false
		}
		if health, ok := tokens.(interface{ Health() error }); ok && health.Health() != nil {
			writeError(w, http.StatusServiceUnavailable, enrolltoken.ErrStateUnavailable)
			return false
		}
		// ★★★ AN EDGE THAT ASKS THE AUTHORITY CANNOT ANSWER FOR IT (2026-08-25, measured on the two-region lab
		// while walking the new Device configuration screen). This node holds no enrolment tokens by design —
		// it forwards the one act that matters, spending one, to the control plane. The ADMIN surface was never
		// told: List returns nil and Outstanding returns 0, and the route rendered both as an authoritative
		// HTTP 200. Forty-six approvals were outstanding on the control plane while an Edge reported "0
		// outstanding, no tokens" — the answer a deployment with none would give.
		//
		// This file already SAID it was refused ("an admin surface that returns an empty list is
		// indistinguishable from one that has none"). The sentence was written; the refusal was not. Saying
		// where to ask is the whole value: a 200 sends the operator to look for a problem that is not there.
		if _, remote := tokens.(*remoteEnrolmentTokenAuthority); remote {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"this Edge does not hold this deployment's enrolment tokens and cannot answer for them — it "+
					"forwards the one act it performs, spending a token, to the control plane. Ask the control "+
					"plane: it is what the Admin Console talks to"))
			return false
		}
		return or503 == nil || or503(w)
	}

	// Read one checked snapshot so rows and counts agree, and a storage failure
	// cannot be presented as an authoritative empty inventory.
	list := func(r *http.Request) ([]enrolltoken.Token, error) {
		if checked, ok := tokens.(interface {
			ListContext(context.Context, string) ([]enrolltoken.Token, error)
		}); ok {
			return checked.ListContext(r.Context(), tenantOf(r))
		}
		return tokens.List(tenantOf(r)), nil
	}

	mux.HandleFunc("POST /admin/enrolment-tokens", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AND A DEVICE DOES NOT BELONG TO THE OPERATOR (2026-09-04, found by reading which organization the
		// devices on a working deployment were actually in — both of them were in the operator's).
		//
		// A generated deployment makes ONE id do three jobs: -operator-tenant-id defaults to tenant_default, the
		// starting policy bundle is tenant_default, and a flow whose organization does not resolve falls back to
		// the node's tenant, which is tenant_default. So approving a device without naming a customer
		// organization quietly puts it in the operator's own, and from there everything reports success:
		//
		//	steer_mux_tenant_resolved device="…" tenant="tenant_default"
		//	signing_counts_since_start {"deployment_root_no_own_authority": 40}
		//
		// Forty certificates minted under the DEPLOYMENT's interception CA, on a deployment whose customer
		// organization had its own authority loaded and unused. Per-tenant PKI never engages, and no screen
		// says so, because nothing is broken — the device is simply in the wrong organization.
		//
		// The operator organization exists to ADMINISTER other organizations. It has no devices of its own.
		if op := strings.TrimSpace(operatorTenantID); op != "" && strings.EqualFold(op, strings.TrimSpace(tenantOf(r))) {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%q is this deployment's OPERATOR organization, which administers the others and has no devices of "+
					"its own. Approving a device for it would enrol that machine under the deployment's own "+
					"authority — its traffic would be inspected by the deployment's interception CA rather than a "+
					"customer's, and nothing downstream would report a problem. Approve the device for the "+
					"customer organization it belongs to (X-Operate-Tenant, or the Console's organization picker)",
				op))
			return
		}
		if !ready(w) {
			return
		}
		var req struct {
			Label string `json:"label"` // which machine, which batch, which site — the admin's own words
			Group string `json:"group"`
			// Count is how many machines this approval covers. Kitting is the ordinary case, not the exception:
			// an admin images fifty laptops at once, and issuing fifty tokens one dialog at a time is the kind
			// of friction that gets solved by going back to a shared secret.
			//
			// Each token is still ONE machine, once. The batch is a convenience for the person, not a weakening
			// of the credential.
			Count int `json:"count"`
			// The lifetime is the ISSUER's call, because only they know whether this installer is going to the
			// next desk or into a courier's hands. Bounded by the tenant maximum, not by a fixed default.
			ExpiresInHours int `json:"expires_in_hours"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode enrolment token request: %w", err))
			return
		}
		if req.ExpiresInHours <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("expires_in_hours is required — an enrolment token has no sensible default lifetime, see the tenant maximum"))
			return
		}
		// ★★ SUSPENSION STOPS NEW ADMISSION, AND MINTING AN APPROVAL IS ADMISSION (2026-08-19). The decision on
		// adminTenantAdministrativelySuspended is that suspension freezes the administrative plane and stops NEW
		// admission while enforcement for devices already enrolled continues. Only POST /enroll enforced it, so
		// a suspended organization could still approve machines — the credential outlives the suspension and
		// the device walks in whenever it is used.
		// ★★★ AND THE ORGANIZATION HAS TO EXIST (2026-08-19, measured live). Naming a tenant that is not in
		// the registry minted a real token: POST with X-Operate-Tenant: tenant_does_not_exist_9z answered 200
		// with a usable secret. Nothing downstream refuses it either — the token is stored against that id, so
		// the day somebody creates or recreates that id the credential is live, and a purged organization's
		// namespace can be re-armed before it is reoccupied.
		//
		// adminTenantIsGone is the right question and already exists: it answers only when the store can
		// ENUMERATE, so a narrow store keeps working rather than refusing everything it cannot see.
		if reason, gone := adminTenantIsGone(r.Context(), tenantModelStore, tenantOf(r)); gone &&
			adminTenantAbsenceIsAuthoritative(configSourceURL) {
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%s, so a device cannot be approved for it", reason))
			return
		}
		if reason, refuse := adminTenantAdministrativelySuspended(r.Context(), tenantModelStore, tenantOf(r)); refuse {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%s, so no new device can be approved for it; the devices it already has keep working",
				reason))
			return
		}
		now := time.Now().UTC()
		count := req.Count
		if count <= 0 {
			count = 1
		}
		if count > maxEnrolmentTokenBatch {
			writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d tokens can be issued at once", maxEnrolmentTokenBatch))
			return
		}
		expires := now.Add(time.Duration(req.ExpiresInHours) * time.Hour)

		// Check the whole batch fits BEFORE minting any of it. Issuing thirty of fifty and then stopping leaves
		// an operator holding a partial set they have to reconcile against a kitting list, with live credentials
		// already created — worse than a refusal that says how many would fit.
		if policy.MaxOutstanding > 0 {
			outstanding := tokens.Outstanding(tenantOf(r), now)
			if room := policy.MaxOutstanding - outstanding; count > room {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"%w: %d unused tokens are already outstanding and the limit is %d, so only %d more can be issued — revoke or let some expire first",
					enrolltoken.ErrOutstandingCap, outstanding, policy.MaxOutstanding, max(room, 0)))
				return
			}
		}

		issued := make([]map[string]any, 0, count)
		for i := 0; i < count; i++ {
			label := strings.TrimSpace(req.Label)
			if count > 1 && label != "" {
				// Numbered so the list stays readable months later. Fifty rows with the same words in them tell
				// an operator nothing about which machine is which.
				label = fmt.Sprintf("%s (%d/%d)", label, i+1, count)
			}
			tok, secret, err := tokens.Issue(policy, tenantOf(r), req.Group, label, adminOf(r), adminLabelOf(r), expires, now)
			if err != nil {
				// The batch was pre-checked, so reaching here means something else — report what was already
				// minted rather than losing it silently. Those tokens exist and the operator has to know.
				writeJSON(w, http.StatusConflict, map[string]any{
					"schema_version": "admin_enrolment_tokens.v1",
					"tokens":         issued,
					"error":          err.Error(),
					"partial":        true,
					"secret_notice":  "Issuing stopped part-way. The tokens listed here WERE created and are shown only now.",
				})
				return
			}
			issued = append(issued, map[string]any{"token": tok, "secret": secret})
		}

		body := map[string]any{
			"schema_version": "admin_enrolment_tokens.v1",
			"tokens":         issued,
			// Shown once. The Console must make that unmistakable, because there is no second chance to read it.
			"secret_notice": "This is the only time these tokens are shown. They cannot be retrieved later — re-issue if they are lost.",
		}
		if warning := enrolmentTokenTenantWarning(tenantOf(r), enrolsForTenant, adminAnsweringForTheDeployment(r),
			nodeIssuesFor(tenantOf(r))); warning != "" {
			body["warning"] = warning
		}
		// Single issuance keeps its original shape so nothing that already calls this has to change.
		if count == 1 {
			body["token"] = issued[0]["token"]
			body["secret"] = issued[0]["secret"]
		}
		writeJSON(w, http.StatusOK, body)
	}))

	mux.HandleFunc("GET /admin/enrolment-tokens", adminEndpoint("admin.enrollment.read", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		now := time.Now().UTC()
		tenant := tenantOf(r)
		snapshot, err := list(r)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, enrolltoken.ErrStateUnavailable)
			return
		}
		outstanding := 0
		expiring := []enrolltoken.Token{}
		for _, tok := range snapshot {
			if !tok.Outstanding(now) {
				continue
			}
			outstanding++
			expires, _ := time.Parse(time.RFC3339, tok.ExpiresAt)
			if expires.Before(now.Add(48 * time.Hour)) {
				expiring = append(expiring, tok)
			}
		}
		sort.SliceStable(expiring, func(i, j int) bool { return expiring[i].ExpiresAt < expiring[j].ExpiresAt })
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_enrolment_tokens.v1",
			"tokens":         snapshot,
			// A backlog of unused long-lived tokens is what a caller-chosen lifetime creates, and it is invisible
			// unless it is counted. Surface it next to the cap so an operator sees it building rather than
			// discovering it when issuance starts failing.
			// ★★ THE WARNING NAMED ANOTHER CUSTOMER TO THIS ONE (2026-08-18, walked as Northwind's own
			// administrator, who holds no cross-tenant rights). The sentence read "This node enrols devices for
			// tenant_reference_lab only" — correct, useful, and it discloses the identity of a different
			// customer of the same provider on a screen belonging to this one. In an MSSP deployment those two
			// may be competitors, and nothing in the disclosed half is actionable: what Northwind can act on is
			// "not for you, bring your own device CA", which the rest of the message already says.
			//
			// The name survives only for whoever answers for the WHOLE DEPLOYMENT — an operator standing outside
			// every tenant, who is who can move the enrolment path. An operator who has ENTERED a tenant is
			// looking at that tenant's screen and sees exactly what that tenant sees, which is the same rule
			// every other read on this surface follows. (Measured 2026-08-18: an earlier note here said the
			// operator keeps the name, full stop. That was wrong about the inside-a-tenant case and the code
			// was right.)
			"enrols_for_tenant": enrolmentTokenEnrolsForDisclosure(r, enrolsForTenant),
			"tenant_warning": enrolmentTokenTenantWarning(tenant, enrolsForTenant, adminAnsweringForTheDeployment(r),
				nodeIssuesFor(tenant)),
			"outstanding":        outstanding,
			"outstanding_cap":    policy.MaxOutstanding,
			"max_lifetime_hours": int(policy.MaxLifetime / time.Hour),
			// So a kitting run is warned before it stalls on a dead installer rather than after.
			"expiring_within_48h": expiring,
		})
	}))

	mux.HandleFunc("POST /admin/enrolment-tokens/{id}/revoke", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		id := r.PathValue("id")
		existing, err := list(r)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, enrolltoken.ErrStateUnavailable)
			return
		}
		owned := false
		for _, t := range existing {
			if t.ID == id {
				owned = true
				break
			}
		}
		if !owned {
			// Scoped to the caller's tenant: one tenant's admin must not be able to revoke — or probe for —
			// another's tokens by guessing IDs.
			writeError(w, http.StatusNotFound, fmt.Errorf("no such enrolment token"))
			return
		}
		var tok enrolltoken.Token
		var ok bool
		if checked, supports := tokens.(interface {
			RevokeForTenantContext(context.Context, string, string, string, time.Time) (enrolltoken.Token, bool, error)
		}); supports {
			tok, ok, err = checked.RevokeForTenantContext(r.Context(), tenantOf(r), id, adminOf(r), time.Now().UTC())
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, enrolltoken.ErrStateUnavailable)
				return
			}
		} else {
			tok, ok = tokens.Revoke(id, adminOf(r), time.Now().UTC())
		}
		if !ok {
			if !ready(w) {
				return
			}
			writeError(w, http.StatusConflict, fmt.Errorf("enrolment token is already revoked"))
			return
		}
		// Revoking a token that was already SPENT does nothing to the device it enrolled — that device holds a
		// certificate, and taking it away is the enrolled-inventory disable plus the admission overlay. Say so,
		// because an operator reaching for revoke after a device has enrolled is reaching for the wrong control.
		note := ""
		if tok.UsedAt != "" {
			note = "this token had already been spent by device " + tok.UsedBy +
				" — revoking it does NOT remove that device's access; disable the device in Enrolled Devices instead"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_enrolment_tokens.v1",
			"token":          tok,
			"note":           note,
		})
	}))
}

// enrolmentTokenTenantWarning says, in the administrator's terms, that a token they are holding cannot be used
// against this node. Empty when it can.
func enrolmentTokenTenantWarning(tokenTenant, enrolsForTenant string, mayNameTheOtherTenant bool,
	nodeIssuesForTokenTenant bool) string {
	tokenTenant = strings.TrimSpace(tokenTenant)
	enrolsForTenant = strings.TrimSpace(enrolsForTenant)
	if tokenTenant == "" || enrolsForTenant == "" || strings.EqualFold(tokenTenant, enrolsForTenant) {
		return ""
	}
	// ★★★ AND THE NODE'S OWN ORGANIZATION STOPPED BEING THE QUESTION ON 2026-08-21, WHILE THIS SENTENCE WENT ON
	// ASKING IT (found 2026-08-28 by walking a customer's Mac onto a two-region deployment). /enroll takes the
	// organization from the TOKEN and refuses only when this node holds no device-identity authority for it —
	// so a customer whose device certificates this deployment issues has a token that works, and was told on
	// the screen that issued it that no device could ever use it. The route the message then recommends —
	// bring your own device CA — is the one thing that would have made the warning true.
	//
	// A screen that denies what the code allows costs the same as one that promises what it does not enforce:
	// the administrator abandons the path that works. So the warning now asks what /enroll asks.
	if nodeIssuesForTokenTenant {
		return ""
	}
	if !mayNameTheOtherTenant {
		// Everything the reader can act on, and nothing about whose node this is.
		return fmt.Sprintf("This node does not enrol devices for %q. A device presenting this token here is "+
			"refused; it can only be used against an Edge that enrols for your organization.", tokenTenant)
	}
	return fmt.Sprintf("This node enrols devices for %q, not %q. A device presenting this token here is refused; "+
		"it can only be used against an Edge that enrols for your organization.", enrolsForTenant, tokenTenant)
}

// enrolmentTokenEnrolsForDisclosure withholds WHOSE node this is from anybody but the deployment's operator.
// The Console composes its own sentence from this field, so leaving it populated would put the name back on
// the customer's screen however carefully the sentence above is worded.
func enrolmentTokenEnrolsForDisclosure(r *http.Request, enrolsForTenant string) string {
	if adminAnsweringForTheDeployment(r) {
		return enrolsForTenant
	}
	if _, wholeDeployment := adminAnswerScope(r); wholeDeployment {
		return enrolsForTenant
	}
	// A caller inside their own organization: their own name is theirs to see; anybody else's is not.
	if strings.EqualFold(strings.TrimSpace(adminTenantIDFromRequest(r)), strings.TrimSpace(enrolsForTenant)) {
		return enrolsForTenant
	}
	return ""
}

// adminAnsweringForTheDeployment is adminAnswerScope's second return, named for the one question asked here.
func adminAnsweringForTheDeployment(r *http.Request) bool {
	_, wholeDeployment := adminAnswerScope(r)
	return wholeDeployment
}

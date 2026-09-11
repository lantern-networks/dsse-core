package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// The operator's access to a customer's organization, and the organization's view of it (the envelope design, 2026-08-16).
//
// Two things, deliberately separate:
//
//   - the STANDING DELEGATION — the organization has asked the operator to run it, so inside that organization
//     the operator does the ordinary work with the ordinary permissions. Set once at onboarding. Off by
//     default, and the organization can withdraw it.
//   - an ELEVATION — a time-boxed addition on top, required only for the acts named in operatorElevatedActs:
//     the irreversible ones and the ones that take effect across the whole organization at once.
//
// ★ NO REASON FIELD, AND THAT IS A DECISION RATHER THAN AN OMISSION. The industry pattern for support access
// is a customer-granted, time-boxed window, not an operator-typed justification; where a reason does exist at
// this layer it is a machine-checkable ticket reference, not free text. And free text rots — what actually
// gets typed is "support", "investigating", "asdf", and the field is still full, so the record LOOKS like
// accountability and carries nothing. This repository has paid repeatedly for records that were written and
// not enforced; a mandatory unverified field manufactures one more.
//
// What the organization is shown instead is the fact: who, when, for how long, and — through the audit trail
// the middleware already writes for every operate-within mutation — what was done. "Replaced the interception
// authority" answers "why" better than "investigating" does.
type operatorElevation struct {
	ID string `json:"id"`
	// GrantedTo is the operator principal the elevation belongs to. An elevation is not a property of the
	// organization alone: two operators must not share one window, or the record cannot say who acted.
	GrantedTo string `json:"granted_to"`
	GrantedBy string `json:"granted_by"`
	StartedAt string `json:"started_at"`
	ExpiresAt string `json:"expires_at"`
	// EndedAt is set when somebody stops it early — either side may.
	EndedAt *string `json:"ended_at,omitempty"`
	EndedBy *string `json:"ended_by,omitempty"`
	// ApprovalRequired is SNAPSHOT at grant time, not read live. If the organization changes its mind about
	// requiring approval, an elevation already granted must not silently change meaning underneath the people
	// relying on it — in either direction.
	ApprovalRequired bool    `json:"approval_required"`
	ApprovedAt       *string `json:"approved_at,omitempty"`
	ApprovedBy       *string `json:"approved_by,omitempty"`
}

// finished reports whether this elevation is over — ended by hand, or lapsed by the clock.
//
// ★★ A TERMINAL STATE IS FINAL, AND WAS NOT (2026-08-16, found by calling both routes on a finished record).
// Approving and ending guarded only on EndedAt, so an elevation that had LAPSED — EndedAt nil, ApprovedAt nil —
// was still writable. Measured on the lab as a customer administrator: an elevation that expired at 12:22 took
// an approval stamped 13:55 and an end stamped 13:55, and its state flipped from "expired" to "ended". Both
// calls returned 200 saying approved:true / ended:true.
//
// The elevation record is the evidence of what an operator was allowed to do and for how long. If it can be
// restated afterwards, it is not evidence.
func (e operatorElevation) finished(now time.Time) bool {
	if e.EndedAt != nil {
		return true
	}
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(e.ExpiresAt))
	if err != nil {
		// An unparseable end is not an open-ended one, here for the same reason as in active().
		return true
	}
	return !now.Before(expires)
}

// operatorElevationHistoryLimit caps how many elevations one organization's row carries. The history is for
// the customer to read, so it is kept rather than pruned to nothing — but the row travels in the config
// bundle to every Edge, and an unbounded list would grow the thing every node pulls.
const operatorElevationHistoryLimit = 50

// active reports whether this elevation authorises an elevated act right now.
//
// Decided against the clock at the moment of the check. An elevation whose end is only DISPLAYED is the
// defect family this repository knows best: the answer says the window closed and the permission is still
// there.
func (e operatorElevation) active(now time.Time) bool {
	if e.EndedAt != nil {
		return false
	}
	if e.ApprovalRequired && e.ApprovedAt == nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339, strings.TrimSpace(e.ExpiresAt))
	if err != nil {
		// An unparseable end is not an open-ended one. A corrupt timestamp must fail closed, or the worst
		// record in the store becomes the most powerful.
		return false
	}
	return now.Before(expires)
}

func (e operatorElevation) state(now time.Time) string {
	switch {
	case e.EndedAt != nil:
		return "ended"
	case e.ApprovalRequired && e.ApprovedAt == nil:
		return "pending_approval"
	case e.active(now):
		return "active"
	default:
		return "expired"
	}
}

// operatorHasActiveElevation answers the middleware's question: may this operator perform an elevated act on
// this organization right now.
func operatorHasActiveElevation(tenant adminTenantModel, principalID string, now time.Time) bool {
	principalID = strings.TrimSpace(principalID)
	for _, elevation := range tenant.OperatorElevations {
		if !strings.EqualFold(strings.TrimSpace(elevation.GrantedTo), principalID) {
			continue
		}
		if elevation.active(now) {
			return true
		}
	}
	return false
}

// registerOperatorAccessRoutes wires the delegation, the elevations, and the organization's view of both.
// labelForPrincipal resolves an administrator id to the name a person recognises. It is deliberately NOT
// scoped to the reading organization: the principal who last moved a delegation is often the OPERATOR, in
// another organization entirely, and that is precisely who the customer needs named. An id they cannot
// resolve tells them nothing — see the delegation footnote.
func registerOperatorAccessRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	tenantModelStore adminTenantModelRuntimeStore, configSourceURL string, evaluator decision.Evaluator,
	writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, operatorTenantID string,
	labelForPrincipal func(principalID string) string) {

	// resolveTarget answers WHICH organization this request is about, and whether the caller may act on it.
	// An operator names it with X-Operate-Tenant; anybody else gets their own and only their own.
	resolveTarget := func(r *http.Request) (string, bool) {
		identity, ok := adminIdentityFromRequest(r)
		if !ok {
			return "", false
		}
		tenantID, _ := adminOperateTenant(r, identity)
		return strings.TrimSpace(tenantID), true
	}
	// load reports "found" as its own answer rather than folding it into the error: an organization that does
	// not exist and a store that could not be read lead to different responses, and a caller that cannot tell
	// them apart reports the wrong one.
	load := func(ctx context.Context, tenantID string) (adminTenantModel, bool, error) {
		tenant, err := tenantModelStore.Get(ctx, tenantID)
		if err != nil {
			return adminTenantModel{}, false, err
		}
		return tenant, strings.TrimSpace(tenant.TenantID) != "", nil
	}
	save := func(ctx context.Context, tenant adminTenantModel) error {
		store, ok := tenantModelStore.(adminTenantModelAdminStore)
		if !ok {
			return fmt.Errorf("this node cannot author organization records")
		}
		_, err := store.Put(ctx, tenant, time.Now())
		return err
	}
	audit := func(r *http.Request, tenant adminTenantModel, action string) {
		now := time.Now()
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox,
			adminTenantModelLifecycleAuditLogFor(r, tenant, action, evaluator, now), now)
	}

	// The delegation itself. Either side may write it: the operator sets it at onboarding, and the
	// organization can withdraw it — a delegation only the holder can end is not a delegation.
	mux.HandleFunc("PUT /admin/operator-delegation", adminEndpoint("admin.tenant.admin|admin.config.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "operator delegation") {
			return
		}
		target, ok := resolveTarget(r)
		if !ok || target == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "changing the operator delegation of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		var body struct {
			Managed                  *bool `json:"managed"`
			ElevationNeedsApproval   *bool `json:"elevation_requires_approval"`
			DeprecatedRequireApprove *bool `json:"require_approval"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode delegation: %w", err))
			return
		}
		// ★★ A WITHDRAWAL THAT DOES NOTHING MUST NOT ANSWER 200 (2026-08-22). Every field here is a pointer so
		// that "not mentioned" and "set to false" stay different — which is right, and it made a body naming
		// NONE of them a silent success: 200, and the delegation unchanged.
		//
		// The trap is one field name apart. The tenant record calls this operator_managed, and GET
		// /admin/tenants prints it that way, so a caller reading the record and writing back the name it saw
		// sends operator_managed and is told it worked. For this particular control that is the worst possible
		// outcome: a customer who believes they revoked their provider's standing access, and did not.
		if body.Managed == nil && body.ElevationNeedsApproval == nil && body.DeprecatedRequireApprove == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"this request changes nothing: send \"managed\" (true grants the standing delegation, false "+
					"withdraws it) and/or \"elevation_requires_approval\". Note the name — the record calls the "+
					"same thing operator_managed, and that spelling is not read here"))
			return
		}
		tenant, found, err := load(r.Context(), target)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist", target))
			return
		}
		if tenant.IsOperator {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"the operator's own organization does not delegate to itself"))
			return
		}
		// Who is writing this: the organization itself, or an operator reaching in from outside it. The rest of
		// this handler turns on that difference, and it is the same question adminTenantPKITargetAllowed asks.
		identity, _ := adminIdentityFromRequest(r)
		callerIsOperator := !strings.EqualFold(strings.TrimSpace(identity.TenantID), strings.TrimSpace(target))
		if body.Managed != nil {
			if err := delegationReopenRefusal(tenant, callerIsOperator, *body.Managed); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			applyDelegationChangeBy(&tenant, *body.Managed, strings.TrimSpace(identity.PrincipalID),
				time.Now().UTC().Format(time.RFC3339), !callerIsOperator)
		}
		wantApproval := body.ElevationNeedsApproval
		if wantApproval == nil {
			wantApproval = body.DeprecatedRequireApprove
		}
		if wantApproval != nil {
			// ★ AND THE OPERATOR MAY NOT LOWER THE BAR THE CUSTOMER SET. Clearing this flag is the same act as
			// reopening the delegation, one field over: the organization said "an elevation over me needs my
			// administrator's approval", and the party the approval protects it from must not be able to switch
			// it off. Raising it is allowed from either side — nobody needs protecting from more approval.
			if callerIsOperator && tenant.OperatorElevationRequiresApproval && !*wantApproval {
				writeError(w, http.StatusForbidden, fmt.Errorf(
					"%q requires its own administrator to approve an elevation, and an operator cannot remove "+
						"that requirement — it exists to be applied to you. %q can remove it", target, target))
				return
			}
			tenant.OperatorElevationRequiresApproval = *wantApproval
		}
		if err := save(r.Context(), tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		audit(r, tenant, "operator_delegation_changed")
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_operator_delegation.v1",
			"tenant_id":      tenant.TenantID,
			"managed":        tenant.OperatorManaged,
			// ★★ THE SCREEN PROMISED SOMETHING THIS CODE DOES NOT KEEP (2026-08-18). With the delegation off, the
			// tenant's own Operator access page said "Nobody outside your tenant can change your settings." The
			// comment on the PUT twelve lines up says the opposite and means it: either side may write this, and
			// the operator sets it at onboarding. So a tenant that withdraws the delegation is told it is closed,
			// and the provider can reopen it.
			//
			// The answer to that is not a softer sentence maintained by hand next to a guard that can change
			// under it — that is how the Console came to count a key this endpoint never returned. It is to ASK
			// THE GUARD. If somebody later restricts the grant to the tenant, this field flips on its own and
			// the sentence follows.
			"operator_may_enable":         operatorMayEnableDelegation(tenant),
			"elevation_requires_approval": tenant.OperatorElevationRequiresApproval,
			"note": "Delegation covers this organization's ordinary work. Irreversible or organization-wide " +
				"acts need a time-boxed elevation on top of it.",
		})
	}))

	// Granting an elevation is an operator act. A customer cannot grant one to itself — it has no need of one,
	// since its own administrators are not operating under a delegation in the first place.
	mux.HandleFunc("POST /admin/operator-elevations", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "operator elevations") {
			return
		}
		identity, _ := adminIdentityFromRequest(r)
		target, ok := resolveTarget(r)
		if !ok || target == "" || strings.EqualFold(target, strings.TrimSpace(identity.TenantID)) {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"name the organization to be elevated over with X-Operate-Tenant; an elevation over your own "+
					"organization is not a thing that exists"))
			return
		}
		var body struct {
			Minutes int `json:"minutes"`
		}
		if err := decodeLimitedJSONBody(w, r, &body, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode elevation: %w", err))
			return
		}
		if body.Minutes <= 0 || body.Minutes > operatorElevationMaxMinutes {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"minutes must be between 1 and %d — an elevation without a short end is the standing permission "+
					"this design exists to avoid", operatorElevationMaxMinutes))
			return
		}
		tenant, found, err := load(r.Context(), target)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist", target))
			return
		}
		if !tenant.OperatorManaged {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%q has not delegated its management to the operator, so there is nothing to elevate above. "+
					"Elevation adds to a delegation; it does not replace one", target))
			return
		}
		now := time.Now().UTC()
		elevation := operatorElevation{
			ID:               "elev_" + operatorElevationID(),
			GrantedTo:        strings.TrimSpace(identity.PrincipalID),
			GrantedBy:        adminActorLabel(identity),
			StartedAt:        now.Format(time.RFC3339),
			ExpiresAt:        now.Add(time.Duration(body.Minutes) * time.Minute).Format(time.RFC3339),
			ApprovalRequired: tenant.OperatorElevationRequiresApproval,
		}
		tenant.OperatorElevations = appendOperatorElevation(tenant.OperatorElevations, elevation)
		if err := save(r.Context(), tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		audit(r, tenant, "operator_elevation_granted")
		writeJSON(w, http.StatusCreated, map[string]any{
			"schema_version": "admin_operator_elevation.v1",
			"tenant_id":      tenant.TenantID,
			"elevation":      elevation,
			"state":          elevation.state(now),
			"note": "Ends by the clock. Nothing has to be done to close it, and nothing renews it silently — " +
				"a new elevation is a new record the organization can see.",
		})
	}))

	// Ending one early. Either side: the operator when the work is finished, the organization at any time.
	mux.HandleFunc("DELETE /admin/operator-elevations/{id}", adminEndpoint("admin.tenant.admin|admin.config.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "operator elevations") {
			return
		}
		target, ok := resolveTarget(r)
		if !ok || target == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "ending an operator elevation over"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		identity, _ := adminIdentityFromRequest(r)
		tenant, found, err := load(r.Context(), target)
		if err != nil || !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist", target))
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		now := time.Now().UTC()
		changed, known := false, false
		for i, elevation := range tenant.OperatorElevations {
			if !strings.EqualFold(elevation.ID, id) {
				continue
			}
			known = true
			if elevation.finished(now) {
				continue
			}
			ended, by := now.Format(time.RFC3339), adminActorLabel(identity)
			tenant.OperatorElevations[i].EndedAt = &ended
			tenant.OperatorElevations[i].EndedBy = &by
			changed = true
		}
		if !changed {
			if known {
				// It exists and is over. Saying so is different from saying it is not there, and stops a caller
				// concluding the id was wrong.
				writeError(w, http.StatusConflict, fmt.Errorf(
					"elevation %q over %q is already over — an elevation that has ended or lapsed cannot be ended again", id, target))
				return
			}
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%q is not an open elevation over %q", id, target))
			return
		}
		if err := save(r.Context(), tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		audit(r, tenant, "operator_elevation_ended")
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_operator_elevation_ended.v1",
			"tenant_id":      tenant.TenantID, "elevation_id": id, "ended": true,
		})
	}))

	// Approving one, for the organizations that asked to be asked. A tenant act by construction: the operator
	// approving its own elevation would make the setting decorative.
	mux.HandleFunc("POST /admin/operator-elevations/{id}/approve", adminEndpoint("admin.config.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "operator elevations") {
			return
		}
		identity, ok := adminIdentityFromRequest(r)
		if !ok {
			writeError(w, http.StatusForbidden, fmt.Errorf("admin authentication is required"))
			return
		}
		// Deliberately the identity's OWN tenant, not the operate-within target: this is the organization
		// speaking for itself, and reading the header here would let an operator approve on its behalf.
		target := strings.TrimSpace(identity.TenantID)
		tenant, found, err := load(r.Context(), target)
		if err != nil || !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist", target))
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		now := time.Now().UTC()
		approved, knownElevation := false, false
		for i, elevation := range tenant.OperatorElevations {
			if !strings.EqualFold(elevation.ID, id) {
				continue
			}
			knownElevation = true
			// Approval is only meaningful while the window is still open: an approval stamped after the
			// elevation lapsed says somebody allowed access that had already gone away.
			if elevation.finished(now) || elevation.ApprovedAt != nil {
				continue
			}
			at, by := now.Format(time.RFC3339), adminActorLabel(identity)
			tenant.OperatorElevations[i].ApprovedAt = &at
			tenant.OperatorElevations[i].ApprovedBy = &by
			approved = true
		}
		if !approved {
			if knownElevation {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"elevation %q is not waiting for approval — it has already been approved, ended, or lapsed", id))
				return
			}
			writeError(w, http.StatusNotFound, fmt.Errorf(
				"%q is not an elevation over your organization that is waiting for approval", id))
			return
		}
		if err := save(r.Context(), tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		audit(r, tenant, "operator_elevation_approved")
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_operator_elevation_approved.v1",
			"tenant_id":      tenant.TenantID, "elevation_id": id, "approved": true,
		})
	}))

	// What the organization sees. Its own delegation and every elevation over it — which is the answer to
	// "has the operator been in here", asked without having to ask the operator.
	mux.HandleFunc("GET /admin/operator-access", adminEndpoint("admin.config.read|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		target, ok := resolveTarget(r)
		if !ok || target == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "reading the operator access record of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		tenant, found, err := load(r.Context(), target)
		if err != nil || !found {
			writeError(w, http.StatusNotFound, fmt.Errorf("organization %q does not exist", target))
			return
		}
		now := time.Now().UTC()
		records := []map[string]any{}
		for i := len(tenant.OperatorElevations) - 1; i >= 0; i-- {
			elevation := tenant.OperatorElevations[i]
			records = append(records, map[string]any{
				"id": elevation.ID, "granted_by": elevation.GrantedBy,
				"started_at": elevation.StartedAt, "expires_at": elevation.ExpiresAt,
				"ended_at": elevation.EndedAt, "ended_by": elevation.EndedBy,
				"approval_required": elevation.ApprovalRequired,
				"approved_at":       elevation.ApprovedAt, "approved_by": elevation.ApprovedBy,
				"state": elevation.state(now),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_operator_access.v1",
			"tenant_id":      tenant.TenantID,
			"managed":        tenant.OperatorManaged,
			// When the standing delegation last moved, and who moved it. Either side may write it, so the
			// organization has to be able to see a re-grant it did not make — see the model field for the
			// measurement that found this missing.
			"managed_changed_at":          stringOrEmpty(tenant.OperatorDelegationChangedAt),
			"managed_changed_by":          stringOrEmpty(tenant.OperatorDelegationChangedBy),
			"managed_changed_by_label":    principalLabelOr(labelForPrincipal, stringOrEmpty(tenant.OperatorDelegationChangedBy)),
			"elevation_requires_approval": tenant.OperatorElevationRequiresApproval,
			// ★★★ THE SCREEN'S SENTENCE IS SWITCHED BY THIS KEY, AND THIS READ NEVER RETURNED IT (2026-08-20,
			// measured on the running lab the moment the withdrawal rule went in). console/operatoraccess.js
			// branches on `data.operator_may_enable === false` to decide between "Nobody outside your tenant can
			// change your settings" and "…the company that runs this service can switch this back on". The key
			// existed only on the PUT response, so the strict comparison was never true and the customer was
			// always shown the WEAKER sentence — including now, when the strong one is the true one.
			//
			// The whole design of that field was that the screen asks the guard instead of maintaining a
			// sentence by hand. It was asking a guard that only answered when the customer wrote something.
			"operator_may_enable": operatorMayEnableDelegation(tenant),
			"elevations":          records,
			"note": "Ordinary changes made under the delegation appear in this organization's audit trail as " +
				"operate-within entries; this list is the elevations, which are the acts that could not be " +
				"undone or reached the whole organization at once.",
		})
	}))
}

// operatorMayEnableDelegation asks the real guard whether a cross-tenant operator could turn this tenant's
// standing delegation back on, rather than asserting an answer beside it.
//
// It builds the request such a caller would make — an operator identity in another tenant, naming this one —
// and runs the same adminTenantPKITargetAllowed the PUT handler runs. The point is that this cannot drift: the
// only way to make it return false is to make the write actually refuse.
func operatorMayEnableDelegation(tenant adminTenantModel) bool {
	if delegationReopenRefusal(tenant, true, true) != nil {
		return false
	}
	probe, err := http.NewRequest(http.MethodPut, "/admin/operator-delegation", nil)
	if err != nil {
		// Cannot happen for a constant method and path; if it ever does, say the safer thing rather than
		// promising the tenant a closed door on the strength of a failed probe.
		return true
	}
	// ★ THE PROBE MUST STAND WHERE A REAL OPERATOR STANDS (2026-08-21). It used to invent an organization —
	// "tenant_operator_probe" — and hold super_admin, which was enough back when the role alone decided
	// cross-organization reach. Now that the answer is "do you BELONG to the operator organization", an
	// invented one is refused, and the screen would have told every customer the operator can do nothing.
	// A screen whose probe cannot be the thing it asks about reports on itself, not on the system.
	probe = probe.WithContext(context.WithValue(probe.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "probe", TenantID: operatorTenantConfigured(),
		Roles: []string{"super_admin"}, AuthMethod: "admin_session",
	}))
	return adminTenantPKITargetAllowed(probe, strings.TrimSpace(tenant.TenantID), "enabling the delegation of") == nil
}

// registerAdminBreakGlassRoute reports whether the shared token is armed here, and whether anybody has used it.
//
// ★ THE ARMED STATE HAS TO BE ASKABLE. Before this it was discoverable only by reading a process log line
// printed at boot on a node somebody set up months ago — which is to say, not discoverable. An operator
// auditing a fleet needs one question they can ask every node.
//
// Deliberately readable by the ordinary platform-read permission rather than being buried behind the
// operator's own: a customer cannot see it (it is a property of the deployment, not of their organization),
// and anybody who can already read this deployment's posture should not have to guess at this part of it.
func registerAdminBreakGlassRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /admin/break-glass-token", adminEndpoint("admin.platform.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, adminBreakGlassReport())
	}))
}

// operatorElevationMaxMinutes bounds a single window. Long enough for real work, short enough that forgetting
// to end one is not the same as never having had a bound.
const operatorElevationMaxMinutes = 8 * 60

// appendOperatorElevation keeps the newest entries and drops the oldest beyond the cap.
func appendOperatorElevation(existing []operatorElevation, elevation operatorElevation) []operatorElevation {
	out := append(existing, elevation)
	if len(out) > operatorElevationHistoryLimit {
		out = out[len(out)-operatorElevationHistoryLimit:]
	}
	return out
}

// adminActorLabel names the human, falling back to the principal id rather than to an empty string — a record
// whose actor is "" is the one this whole design exists to stop producing.
func adminActorLabel(identity adminIdentity) string {
	if label := strings.TrimSpace(identity.PrincipalLabel); label != "" {
		return label
	}
	if id := strings.TrimSpace(identity.PrincipalID); id != "" {
		return id
	}
	return strings.TrimSpace(identity.AuthMethod)
}

// operatorElevationID mints an identifier for one elevation. Random rather than sequential because the id
// appears in the record the customer reads, and a counter would tell every organization how many elevations
// every other organization has had.
func operatorElevationID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Never silently produce a colliding constant: a duplicate id would let one elevation's end close
		// another's window, or fail to.
		return "t" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

// stringOrEmpty renders an optional string field for a JSON response: absent reads as "", never as null, so a
// caller that formats it does not print the word null on a screen.
func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

// applyDelegationChange sets the standing delegation and, when the value actually MOVES, records when and by
// whom. Returns whether it moved.
//
// Stamping only on a real change is the point: re-saving the same value would otherwise rewrite the record and
// make an untouched delegation look freshly re-granted — the same defect pointing the other way. See the model
// fields for the measurement this exists for.
func applyDelegationChange(tenant *adminTenantModel, next bool, by, at string) bool {
	return applyDelegationChangeBy(tenant, next, by, at, false)
}

// applyDelegationChangeBy is applyDelegationChange with the one fact the reopen rule needs: whether the party
// writing it is the ORGANIZATION or the operator. See OperatorDelegationWithdrawnByCustomer.
func applyDelegationChangeBy(tenant *adminTenantModel, next bool, by, at string, byCustomer bool) bool {
	if tenant == nil || tenant.OperatorManaged == next {
		return false
	}
	switch {
	case next:
		// Granted again — by whoever. The organization is back to the ordinary shape and nothing accumulates.
		tenant.OperatorDelegationWithdrawnByCustomer = false
	case byCustomer:
		tenant.OperatorDelegationWithdrawnByCustomer = true
	default:
		// The operator ended their own engagement. They may pick it up again; the customer closed nothing.
		tenant.OperatorDelegationWithdrawnByCustomer = false
	}
	stamp := at
	tenant.OperatorDelegationChangedAt = &stamp
	if strings.TrimSpace(by) != "" {
		actor := strings.TrimSpace(by)
		tenant.OperatorDelegationChangedBy = &actor
	} else {
		tenant.OperatorDelegationChangedBy = nil
	}
	tenant.OperatorManaged = next
	return true
}

// delegationReopenRefusal is the rule the operator decided on 2026-08-20: an operator may not turn a
// delegation back on that the ORGANIZATION withdrew.
//
// ★ WHY IT IS NOT SIMPLY "THE OPERATOR MAY NOT WRITE THIS". The operator has to be able to set the delegation
// at onboarding: a brand-new organization has no administrator to grant anything, and the customers this
// product is sold to are precisely the ones who will not do it themselves. So the asymmetry is between the two
// DIRECTIONS, not between the two parties — which is what makes it a delegation rather than a permission the
// holder can re-grant to itself.
//
// One function, called by the write and by the field the customer's screen reads, so the sentence on the
// screen cannot drift from the guard. Maintaining that sentence by hand is how this Console came to count a
// key the endpoint never returned.
func delegationReopenRefusal(tenant adminTenantModel, callerIsOperator, want bool) error {
	if !callerIsOperator || !want || tenant.OperatorManaged || !tenant.OperatorDelegationWithdrawnByCustomer {
		return nil
	}
	return fmt.Errorf("%q withdrew this delegation itself, so only %q can grant it again. An operator sets the "+
		"delegation at onboarding and may end their own engagement, but a delegation the holder can re-grant to "+
		"itself is not a delegation", tenant.TenantID, tenant.TenantID)
}

// principalLabelOr is the person's name when it can be resolved, and the id when it cannot — never empty, so
// a screen always has something true to print.
func principalLabelOr(resolve func(string) string, principalID string) string {
	id := strings.TrimSpace(principalID)
	if id == "" || resolve == nil {
		return id
	}
	if label := strings.TrimSpace(resolve(id)); label != "" {
		return label
	}
	return id
}

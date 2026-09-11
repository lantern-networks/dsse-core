package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/vlan"
)

// Tenant model admin routes (own-tenant read/write + the operator multi-tenant CRUD).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
// adminTenantRefuseResidency answers whether this write is trying to set data_residency, which enforces
// nothing.
//
// ★★ A FIELD WHOSE NAME IS A COMPLIANCE PROMISE AND WHOSE VALUE DECIDES NOTHING (2026-08-19, decided after
// measuring). data_residency is accepted, normalised, persisted in its own Postgres column and counted in the
// deletion footprint, and no code consults it. What actually places an organization is home_region /
// allowed_regions, which the region-endpoint route and the application router read.
//
// The same treatment POST /admin/admins/invite gives tenant_id: sending it is an ERROR, because a field that
// changes nothing is worse than a field that does not exist — and worse still here, since a reader who sees
// "data_residency: jp" concludes something is being enforced.
//
// Refused at the ROUTE, not in normalisation: every stored path goes through normalisation, including the
// config-bundle apply that upserts whatever the control plane already holds. Refusing there would make an
// existing value break distribution. Refusing here stops the value being SET while leaving one that exists
// readable — and the setup screen says it enforces nothing.
func adminTenantRefuseResidency(w http.ResponseWriter, raw []byte) bool {
	var probe struct {
		DataResidency *string `json:"data_residency"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false // a body that does not parse is refused by the caller's own decode, with its own message
	}
	if probe.DataResidency == nil || strings.TrimSpace(*probe.DataResidency) == "" {
		return false
	}
	writeError(w, http.StatusBadRequest, fmt.Errorf(
		"data_residency is recorded and enforces nothing, so setting it would promise something this product "+
			"does not do; where an organization is served is decided by home_region and allowed_regions, which "+
			"are on this same record"))
	return true
}

func registerTenantAdminRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, tenantModelStore adminTenantModelRuntimeStore, operatorTenantID string, adminAuditOutbox adminAuditOutboxDeadReader, adminAuth adminAuthRuntimeStore, ruleStore *policyrule.Store, namedNetworks *vlan.Store, extraStores adminTenantExtraStores, configSourceURL string) {
	mux.HandleFunc("GET /admin/tenant", adminEndpoint("admin.tenant.read", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ AN ORGANIZATION NAMED BY A HEADER MUST EXIST BEFORE IT IS DESCRIBED (2026-09-05, seen on the
		// Console of a freshly built deployment). The store answers a Get for an unknown organization by
		// synthesising one — display name equal to the id, status "active" — which is right for the caller's
		// OWN organization on a deployment where no row has been written yet, and wrong for any other.
		//
		// A browser tab that had entered an organization on a PREVIOUS deployment still had the id in session
		// storage. It sent it as X-Operate-Tenant to a deployment that had never heard of it, this route
		// answered 200 with an "active" organization, and the Console operated inside it: the header carried
		// the raw id as its name, every screen was empty, and a banner explained the emptiness as a delegation
		// that had not been granted. The deployment's own Tenants page said "No tenants yet."
		//
		// So an id that came from the header is checked against the registry. The caller's own organization is
		// untouched — that is the case the synthesis exists for.
		tenantID := adminTenantIDFromRequest(r)
		if identity, ok := adminIdentityFromRequest(r); ok {
			if named, fromHeader := adminOperateTenant(r, identity); fromHeader && strings.TrimSpace(named) != "" &&
				!strings.EqualFold(strings.TrimSpace(named), strings.TrimSpace(identity.TenantID)) {
				if known, err := adminTenantExists(r.Context(), tenantModelStore, named); err == nil && !known {
					writeError(w, http.StatusNotFound, fmt.Errorf(
						"this deployment has no organization %q. It may belong to another deployment, or have "+
							"been removed; nothing here is scoped to it", named))
					return
				}
			}
		}
		tenant, err := tenantModelStore.Get(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, tenant)
	}))
	mux.HandleFunc("POST /admin/tenant", adminEndpoint("admin.tenant.write", func(w http.ResponseWriter, r *http.Request) {
		// An Edge that PULLS its config is not the tenant authority, and accepting a write here would store a
		// value the next bundle overwrites — the failure that cost a timezone nobody could set and a tenant with
		// three names. Refuse, and say where the write belongs.
		//
		// The check is the same one every other config route uses, so "this node takes config from a control
		// plane" has one meaning across the product rather than one per store.
		if configWriteRejectedWhenSourced(w, configSourceURL, "tenant settings") {
			return
		}
		// Read the body ONCE and interpret it twice: as the model, and as a map of which keys were actually
		// sent. The struct decode cannot tell an absent operator_managed from a present false, and that
		// difference is what stops an unrelated edit from revoking a delegation.
		raw, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEdgeRuntimeJSONBodyBytes))
		if rerr != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read tenant model: %w", rerr))
			return
		}
		var tenant adminTenantModel
		if err := json.Unmarshal(raw, &tenant); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode tenant model: %w", err))
			return
		}
		if adminTenantRefuseResidency(w, raw) {
			return
		}
		now := time.Now()
		// ★ THE SAME PRESERVATION ON THE ORGANIZATION'S OWN UPDATE. A customer editing its display name must
		// not be able to drop its own delegation record by omission either — and it cannot SET the envelope
		// here, so omission is the only way it could ever change.
		if adminStore, ok := tenantModelStore.(adminTenantModelAdminStore); ok {
			tenant = preserveOperatorEnvelopeOnUpsert(r.Context(), adminStore, tenant, bodyNamesOperatorEnvelope(raw))
		}
		updated, err := tenantModelStore.Update(r.Context(), tenant, adminTenantIDFromRequest(r), now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminTenantModelAuditLog(updated, evaluator, now), now)
		writeJSON(w, http.StatusOK, updated)
	}))
	// Cross-tenant (super-admin) tenant administration: list every tenant, create/upsert an arbitrary tenant,
	// and delete one. Gated on admin.tenant.admin (a strict super-admin permission distinct from the self-scoped
	// admin.tenant.read/write above). The store must support the cross-tenant surface; a narrow stub yields 501.
	mux.HandleFunc("GET /admin/tenants", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		adminStore, ok := tenantModelStore.(adminTenantModelAdminStore)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("cross-tenant tenant administration is not available"))
			return
		}
		tenants, err := adminStore.List(r.Context())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// ★★★ THIS ROUTE HANDED A CUSTOMER THE CUSTOMER LIST (2026-08-21, measured live). The permission it
		// asks for — admin.tenant.admin — is granted by super_admin and owner, which a CUSTOMER organization
		// grants inside itself. So an administrator of tenant_reference_lab read every organization on the
		// deployment: their ids, their display names, their plans and their status. Names of other customers
		// are the one thing a multi-tenant deployment must never hand out by accident.
		//
		// Filtered rather than refused: an organization asking about ITSELF is an ordinary read, and the
		// Console's own organization card makes it. What changes is that the answer stops containing anybody
		// else. See operator_is_an_organization_not_a_role.go for why the role was never the right question.
		if !adminCallerIsOperator(r) {
			caller := strings.TrimSpace(adminTenantIDFromRequest(r))
			own := make([]adminTenantModel, 0, 1)
			for _, tenant := range tenants {
				if caller != "" && strings.EqualFold(strings.TrimSpace(tenant.TenantID), caller) {
					own = append(own, tenant)
				}
			}
			tenants = own
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
	}))
	mux.HandleFunc("POST /admin/tenants", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ See an_organizations_life_is_not_a_customers_to_end.go. A customer's super_admin holds
		// admin.tenant.admin, so the permission alone let one create organizations in this deployment.
		if !adminOperatorOnlyOrganizationAct(w, r, "creating an organization") {
			return
		}
		if configWriteRejectedWhenSourced(w, configSourceURL, "tenant registry") {
			return
		}
		adminStore, ok := tenantModelStore.(adminTenantModelAdminStore)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("cross-tenant tenant administration is not available"))
			return
		}
		// Read once, interpret twice — see the note on the self-scoped update above.
		raw, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEdgeRuntimeJSONBodyBytes))
		if rerr != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read tenant model: %w", rerr))
			return
		}
		var tenant adminTenantModel
		if err := json.Unmarshal(raw, &tenant); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode tenant model: %w", err))
			return
		}
		if adminTenantRefuseResidency(w, raw) {
			return
		}
		now := time.Now()
		// Is this an organization that already exists, or a new one? The answer decides whether the id is the
		// caller's to name at all — see organization_id_is_not_a_name.go.
		action := "create"
		if strings.TrimSpace(tenant.TenantID) != "" {
			if existing, lerr := adminStore.List(r.Context()); lerr == nil {
				action = "create"
				for _, candidate := range existing {
					if candidate.TenantID == strings.TrimSpace(tenant.TenantID) {
						action = "update"
						break
					}
				}
			}
		}
		if action == "create" {
			// ★★★ THE ID IS MINTED, NOT CHOSEN (2026-08-21). A caller-supplied id on creation is refused: the
			// Console used to fill it in as slug(display_name), so "Northwind Traders" became tenant_northwind
			// and its transport name became northwind.dsse.invalid — a name an unauthenticated SNI probe on
			// the transport port confirms or denies. A dictionary of company names then enumerates the
			// customer list. Refused rather than quietly overridden, so nobody builds on an id they chose and
			// finds later that it is not the one in force.
			if given := strings.TrimSpace(tenant.TenantID); given != "" {
				writeError(w, http.StatusBadRequest, fmt.Errorf(
					"an organization's id is issued here, not chosen: %q was not created. The id is offered on "+
						"the transport port by name, so a guessable one lets a stranger enumerate the "+
						"organizations on this deployment. Send display_name and the rest; the id comes back "+
						"in the answer. (Updating an organization that already exists still names it.)", given))
				return
			}
			minted, merr := newOrganizationID()
			if merr != nil {
				writeError(w, http.StatusInternalServerError, merr)
				return
			}
			tenant.TenantID = minted
		}
		// ★★ THE OPERATOR ENVELOPE IS NOT THIS FORM'S TO REWRITE (2026-08-18, done by accident and measured).
		// This is a whole-record upsert, so a body that omits a field ERASES it. Sending
		// {tenant_id, display_name, status} to flip an organization back to active wiped its timezone, plan,
		// home region and allowed regions — and, far worse, its operator_managed flag and all sixteen of its
		// recorded elevations. That is the standing delegation and the customer's own record of when the
		// operator used it (the envelope design), silently revoked as collateral damage of an unrelated edit.
		//
		// Those fields have their OWN routes (PUT /admin/operator-delegation, the elevation routes) and are
		// carried here only so a read/modify/write round-trip does not lose them. So they are preserved unless
		// the body actually carries them — the same treatment CreatedAt already gets, and for the same reason.
		tenant = preserveOperatorEnvelopeOnUpsert(r.Context(), adminStore, tenant, bodyNamesOperatorEnvelope(raw))
		saved, err := adminStore.Put(r.Context(), tenant, now)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminTenantModelLifecycleAuditLogFor(r, saved, action, evaluator, now), now)
		answer := adminTenantCreateAnswer{adminTenantModel: saved}
		// ★★★ THE ONE MOMENT GIVING AN ORGANIZATION ITS OWN DOOR NAME COSTS NOTHING (2026-08-28).
		//
		// The Edge picks an organization's transport certificate by SNI, and a device that sends no name is
		// served the deployment's shared one. Doing that later is a movement: the name has to be announced,
		// every device has to adopt it, and the fleet holds both until they have. At CREATION there are no
		// devices, so the whole of that is empty — and it is the only time that is true.
		//
		// ★ ASKED, NOT ASSUMED, AND NOT DONE BY DEFAULT FOR AN API CALLER. Creating an authority makes every
		// Edge in the fleet fetch material for a new organization, so it is a fleet-wide act and it says so on
		// the screen that offers it. An existing caller that sends nothing gets exactly what it got before.
		//
		// ★ NO ELEVATION HERE, AND THAT IS NOT AN EXCEPTION. The elevated act protects an EXISTING customer's
		// PKI from an operator acting without a time-boxed grant. This is the operator creating the
		// organization — already an operator-only act, already audited as one — over an organization that has
		// no customer, no administrator and no device yet.
		if action == "create" && adminTenantBodyAsksForTransportAuthority(raw) {
			if config.TenantTransportAuthority == nil {
				answer.TransportAuthorityNote = "this control plane holds no transport authorities, so this " +
					"organization is served the deployment's shared certificate"
			} else {
				name := organizationTransportServerName(saved.TenantID, deploymentNameSuffix())
				row, aerr := config.TenantTransportAuthority.EnsureCA(saved.TenantID, name)
				switch {
				case aerr != nil:
					// The organization EXISTS — refusing the whole creation over this would leave an operator
					// with neither. Named rather than swallowed, and the Certificates screen still offers it.
					answer.TransportAuthorityNote = "this organization was created and has no door name of its " +
						"own: " + aerr.Error()
					logWarnf("tenant_created_without_transport_authority tenant=%q: %v", saved.TenantID, aerr)
				default:
					answer.TransportServerName = row.ServerName
					logInfof("tenant_created_with_transport_authority tenant=%q server_name=%q — its devices "+
						"verify this deployment on nothing but their own organization's anchor",
						saved.TenantID, row.ServerName)
				}
			}
		}
		// ★★★ AND THE POSTURE ITS OWN SCREEN DESCRIBES (2026-08-28, measured by creating one and running a flow
		// as one of its devices).
		//
		// An organization created before this had NO policy at all. Its Internet Access screen said, in these
		// words, "Everything your people reach on the internet is allowed and inspected" — and the deployment
		// answered every one of its flows with
		//
		//	steer_mux_denied … decision=deny reason="No active policy matched the request."
		//
		// so a customer handed a freshly created organization got a fleet that carries nothing, from a screen
		// promising the opposite. The deployment's own organization has had this posture since installation;
		// only the ones created afterwards went without.
		//
		// ★ IT IS AN ORDINARY RULE, in the customer's own rule list, at the top of the screen that describes
		// it — visible, editable and deletable, exactly as if they had authored it. A starting posture written
		// anywhere the Console cannot edit would be configuration nobody can narrow, which is the shape this
		// deployment has paid for before.
		//
		// ★ AND NOT OPTIONAL. Whether an organization has its own door name is a choice; whether it can carry
		// traffic at all is what creating one MEANS. A flag here would only be a way to create an organization
		// that does not work.
		if action == "create" && ruleStore != nil {
			if _, rerr := ruleStore.Upsert(startingPostureRule(saved.TenantID)); rerr != nil {
				answer.StartingPostureNote = "this organization was created and carries no traffic yet: " + rerr.Error()
				logWarnf("tenant_created_without_starting_posture tenant=%q: %v", saved.TenantID, rerr)
			} else {
				answer.StartingPosture = "everything allowed and inspected"
				logInfof("tenant_created_with_starting_posture tenant=%q — everything allowed and inspected, "+
					"which is what its Internet Access screen says and what it can now narrow", saved.TenantID)
			}
		}
		writeJSON(w, http.StatusOK, answer)
	}))
	mux.HandleFunc("DELETE /admin/tenants/{tenant_id}", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ MEASURED: a customer administrator deleted an unrelated organization here, and the tombstone
		// this writes is honoured by the whole fleet. See an_organizations_life_is_not_a_customers_to_end.go.
		if !adminOperatorOnlyOrganizationAct(w, r, "deleting an organization") {
			return
		}
		if configWriteRejectedWhenSourced(w, configSourceURL, "tenant registry") {
			return
		}
		adminStore, ok := tenantModelStore.(adminTenantModelAdminStore)
		if !ok {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("cross-tenant tenant administration is not available"))
			return
		}
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required"))
			return
		}
		// Lockout protection (multi-tenant Admin Console Q5): the operator's own tenant backs cross-tenant
		// administration; deleting it would strand the operator. Refuse with 409 Conflict.
		if operatorTenantID != "" && tenantID == operatorTenantID {
			writeError(w, http.StatusConflict, fmt.Errorf("tenant %q is the operator tenant and cannot be deleted", tenantID))
			return
		}
		// ★ AND THE SAME HOLD APPLIES HERE, one step earlier. Deletion is the precondition for erasure and it
		// removes the row that says whose data this is; a preservation order that permits that is not a
		// preservation order. Refusing is the fail-safe direction — a hold that is genuinely finished is lifted
		// deliberately, and that lifting is itself on the record.
		if config.LegalHold != nil && config.LegalHold.IsHeld(tenantID) {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"organization %q is under a legal hold, so it cannot be deleted; lift the hold first "+
					"(DELETE /admin/legal-hold)", tenantID))
			return
		}
		now := time.Now()
		if err := adminStore.Delete(r.Context(), tenantID); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenantID}, "delete", evaluator, now), now)
		cascade := cascadeTenantDeletion(r.Context(), config.LocalCredentials, adminAuth, config.EnrolledLedger, tenantID, now)

		// ★★★ RECORDS MAY WAIT FOR THE PURGE; A LIVE CERTIFICATE AUTHORITY MAY NOT (2026-08-21, measured).
		// Deletion deliberately leaves what the organization PRODUCED for the purge to erase — its audit
		// partition, its outbox rows. Its PKI was in that same bucket, and PKI is not a record: measured on
		// the lab, an organization deleted at 05:2x still had a transport CA at 05:44 that had just minted a
		// FRESH twelve-hour certificate, and every Edge in the fleet was still presenting its name on the
		// transport port. So an SNI probe for a customer that no longer exists still answered "yes, here".
		//
		// A retained log is evidence. An authority that goes on signing is a credential, and a deleted
		// organization must not have one. The rows the purge counts are untouched; what stops is the signing.
		authoritiesWithdrawn := map[string]int{}
		if n := config.TenantTransportAuthority.RemoveTenant(tenantID); n > 0 {
			authoritiesWithdrawn["transport"] = n
		}
		if n := config.TenantInterceptionAuthority.RemoveTenant(tenantID); n > 0 {
			authoritiesWithdrawn["interception"] = n
		}
		if n := config.TenantDeviceAuthority.RemoveTenant(tenantID); n > 0 {
			authoritiesWithdrawn["device_identity"] = n
		}
		if len(authoritiesWithdrawn) > 0 {
			cascade["certificate_authorities_withdrawn"] = authoritiesWithdrawn
			logInfof("tenant_deleted_authorities_withdrawn tenant=%q %v — a deleted organization must not go on "+
				"signing, and its name must stop being served", tenantID, authoritiesWithdrawn)
		}
		// ★ AND WHAT DID NOT GO (2026-08-17). Deleting an organization removes it from the registry and takes
		// its accounts, tokens and sessions with it. It does NOT erase what the organization produced — its
		// audit log partition and its rows in the durable outbox stay on every node that held them. The
		// response listed only what it removed, so "deleted: true" read as "gone", and five probe organizations
		// deleted earlier that night were still on disk with their audit partitions and 38 outbox rows hours
		// later. Nothing was wrong with the delete; the answer was just half of what happened.
		//
		// The same count the purge uses, from the same code, so before and after are comparable.
		var db *sql.DB
		if pg, ok := adminAuth.(postgresAdminAuthStore); ok {
			db = pg.DB
		}
		remaining := countAdminTenantFootprint(r.Context(), adminFootprintNodeName(configSourceURL), tenantID,
			db, writer, config.LocalCredentials, config.EnrolledLedger, ruleStore, config.TenantCARegistry, namedNetworks, tenantExtraStoresFor(extraStores, config.EnrolledLedger, tenantID), now)
		body := map[string]any{
			"tenant_id": tenantID,
			"deleted":   true,
			// What went WITH the organization. An operator deleting a customer has to be able to see that the
			// accounts went too — the previous silence is how orphaned administrators went unnoticed.
			"removed":   cascade,
			"remaining": remaining,
		}
		if !remaining.Clean() {
			body["note"] = "the organization is deleted, but what it produced is still on this node — " +
				"POST /admin/tenants/" + tenantID + "/purge erases it and answers with the count that proves it"
		}
		writeJSON(w, http.StatusOK, body)
	}))
	// What is still HERE for a tenant, per store, on this node. An operator runs it before an erasure to see
	// what there is, and after one to see that there is nothing — the same count from the same code, which is
	// the only before/after worth having. It is a read, and it is deliberately available for a tenant that has
	// already been deleted: that is precisely when the question matters.
	mux.HandleFunc("GET /admin/tenants/{tenant_id}/data-footprint", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required"))
			return
		}
		// ★★★ MEASURED: this answered a customer administrator with 669 records counted, per store, for
		// another organization. Counting your OWN data is the point of the route and stays open.
		if !adminTenantPathReadAllowed(w, r, tenantID, "counting the data of") {
			return
		}
		var db *sql.DB
		if pg, ok := adminAuth.(postgresAdminAuthStore); ok {
			db = pg.DB
		}
		footprint := countAdminTenantFootprint(r.Context(), adminFootprintNodeName(configSourceURL), tenantID,
			db, writer, config.LocalCredentials, config.EnrolledLedger, ruleStore, config.TenantCARegistry, namedNetworks, tenantExtraStoresFor(extraStores, config.EnrolledLedger, tenantID), time.Now())
		writeJSON(w, http.StatusOK, footprint)
	}))
	// Erase everything this node holds for a tenant whose contract has ended. Irreversible, and gated so that
	// it cannot happen by accident or as a side effect of anything else:
	//
	//   - the organization must ALREADY be deleted. Purging is what follows a termination, not a way to do one,
	//     and requiring the delete first means a live customer cannot be erased by a mistyped id;
	//   - the operator tenant is refused outright;
	//   - the caller must retype the tenant id in the body. A path parameter alone is one autocomplete away
	//     from erasing the wrong customer, and there is no undo behind this.
	//
	// The response carries the post-erasure footprint. That count IS the evidence; "purged: true" on its own
	// is the kind of claim this product has learned not to trust.
	mux.HandleFunc("POST /admin/tenants/{tenant_id}/purge", adminEndpoint("admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ MEASURED: a customer administrator ran this against another organization and got
		// {"complete":true,"remaining":{"total":0}}. There is no undo behind this route.
		if !adminOperatorOnlyOrganizationAct(w, r, "erasing an organization's data") {
			return
		}
		tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required"))
			return
		}
		var req struct {
			ConfirmTenantID string `json:"confirm_tenant_id"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body"))
			return
		}
		if !strings.EqualFold(strings.TrimSpace(req.ConfirmTenantID), tenantID) {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"to erase organization %q, send confirm_tenant_id with that exact id — this cannot be undone", tenantID))
			return
		}
		if operatorTenantID != "" && tenantID == operatorTenantID {
			writeError(w, http.StatusConflict, fmt.Errorf("tenant %q is the operator tenant and cannot be erased", tenantID))
			return
		}
		if adminTenantStillExists(r.Context(), tenantModelStore, tenantID) {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"organization %q still exists — delete it first. Erasure is what follows a termination, not a way to perform one", tenantID))
			return
		}
		// ★★★ A LEGAL HOLD IS A PROMISE TO KEEP DATA, AND ERASURE WALKED THROUGH IT (2026-08-19). The hold
		// store existed and exactly ONE thing read it: the retention pruner, which preserves a held tenant's
		// logs instead of ageing them out. The most complete deletion the product offers — the one that erases
		// every store and tells the fleet to do the same — never asked.
		//
		// So a hold survived the automatic deletion and not the deliberate one, which is the opposite of what
		// a hold is for. Nothing about an operator being authorised to erase makes the hold irrelevant: the
		// hold is what says this particular organization must not be erased YET, and it is released by lifting
		// it, deliberately and on the record.
		if config.LegalHold != nil && config.LegalHold.IsHeld(tenantID) {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"organization %q is under a legal hold, so its data must be preserved and cannot be erased; "+
					"lift the hold first (DELETE /admin/legal-hold) — that is a decision with its own record", tenantID))
			return
		}
		var db *sql.DB
		if pg, ok := adminAuth.(postgresAdminAuthStore); ok {
			db = pg.DB
		}
		now := time.Now()
		// Record the ORDER before acting on it. Every node that ever served this tenant holds its own copy of
		// that tenant's logs, and only that node can erase them — so the order has to be something the fleet can
		// be told, repeatedly, for as long as it takes. Recorded first so that a failure here leaves an order
		// standing rather than a partial erasure nobody is going to finish.
		//
		// ★ AND IT IS NOW A REFUSAL WHEN THE ORDER CANNOT BE RECORDED (2026-08-18). This was an anonymous type
		// assertion whose `ok` was never used, and the Postgres tenant-model backend satisfied it never: on a
		// Postgres control plane the order was recorded nowhere, this node erased its own copy, and the operator
		// got a result back. Every other node that ever served the tenant kept the customer's data, and nothing
		// said so. Erasing locally while the fleet is never told is worse than refusing, because only one of the
		// two leaves the operator knowing where they stand.
		orderer, ok := tenantModelFleetCarrier(tenantModelStore)
		if !ok {
			writeError(w, http.StatusInternalServerError, fmt.Errorf(
				"this node cannot record an erasure order, so erasing %q here would leave every other node holding "+
					"its data with nothing to tell them — refusing rather than erasing part of it", tenantID))
			return
		}
		orderer.OrderPurge(tenantID, now)
		// Read the order back. OrderPurge cannot return an error (the file store's signature has none, and the
		// two backends must be interchangeable), so the only way to know the order was actually recorded — a
		// failed INSERT, a table that migration 041 never created — is to look for it.
		if !tenantPurgeOrderStands(orderer, tenantID) {
			writeError(w, http.StatusInternalServerError, fmt.Errorf(
				"the erasure order for %q was not recorded, so no other node would ever be told to erase it — "+
					"refusing rather than erasing this node's copy alone", tenantID))
			return
		}
		result := purgeAdminTenantData(r.Context(), adminFootprintNodeName(configSourceURL), tenantID,
			db, writer, config.LocalCredentials, config.EnrolledLedger, ruleStore,
			config.TenantCARegistry, strings.TrimSpace(config.TenantCARegistryPath),
			trustAnchorStoreOrNil(deviceClientCAs), namedNetworks, tenantExtraStoresFor(extraStores, config.EnrolledLedger, tenantID), now)
		// Recorded in the OPERATOR's audit, not the customer's.
		//
		// ★ AND THAT DISTINCTION IS LOAD-BEARING, WHICH THIS CODE LEARNED THE HARD WAY (2026-08-15). The audit
		// writer partitions records by their tenant_id, so a purge record carrying the PURGED tenant's id was
		// written into that tenant's own log partition — the erasure recreated the very directory it had just
		// removed, and the node reported clean while a fresh file sat on its disk seconds later. Reproduced on
		// the lab: purge answered complete=true, and the fleet view showed remaining=1 on the next pass.
		//
		// The record belongs to the operator who performed the erasure: their tenant on the record, the erased
		// customer as the TARGET. That is also the right shape on its own terms — the evidence that an erasure
		// was authorised and carried out must not live inside the thing that was erased.
		auditRecord := adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenantID}, "purge", evaluator, now)
		auditRecord.TenantID = adminTenantIDFromRequest(r)
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, auditRecord, now)
		writeJSON(w, http.StatusOK, result)
	}))
	// connectorTunnelStatus derives whether a connector currently holds a live tunnel session. Presence in
	// the tunnel manager == connected (registered on connect, unregistered on disconnect). Returns nil when
	// no tunnel manager is wired, which surfaces as "unknown" rather than a false "disconnected".
}

// cascadeTenantDeletion takes a tenant's ACCOUNTS with it: the local administrator credentials, and every live
// session and API token those accounts hold.
//
// ★ WHY (2026-08-15). Deleting an organization used to remove a registry row and nothing else, which left two
// problems behind. Its administrators kept authenticating — measured on the lab, seconds after the tenant was
// gone from both planes. And they could not be cleaned up afterwards: "cannot delete the last administrator
// able to manage admins in this tenant" is an invariant that OUTLIVED the tenant, so deleting the organization
// locked its last account in place permanently, reachable by neither delete nor suspend.
//
// Logs, audit records and exported objects are NOT removed here, and their absence from this function is a
// decision rather than an omission. A customer whose contract has ended will ask for its data to be erased,
// and that has to be possible — but as its own named act (the tenant PURGE), for two reasons. Erasing the
// evidence must not be a side effect of pressing delete on a customer; and erasure spans stores this function
// cannot reach transactionally (the log store, object storage, both planes' durable state), so a purge has to
// report what it erased and what it could not, or "completely deleted" is a claim nobody can check.
//
// Failures are reported in the result rather than failing the request: the tenant is already gone by the time
// this runs, and answering 500 would tell the operator the deletion did not happen when it did.
func cascadeTenantDeletion(ctx context.Context, credentials *localAdminCredentialStore, adminAuth adminAuthRuntimeStore, ledger *enrolledinventory.Ledger, tenantID string, now time.Time) map[string]any {
	result := map[string]any{}
	if credentials != nil {
		if removed := credentials.DeleteAllForTenant(tenantID); len(removed) > 0 {
			result["administrators"] = removed
			log.Printf("tenant %q deleted: removed %d administrator account(s): %s", tenantID, len(removed), strings.Join(removed, ", "))
		}
	}
	if ledger != nil {
		if removed := ledger.RemoveTenant(tenantID); len(removed) > 0 {
			result["enrolled_identities"] = len(removed)
			log.Printf("tenant %q deleted: removed %d enrolled identity/identities from the ledger", tenantID, len(removed))
		}
	}
	revoker, ok := adminAuth.(interface {
		RevokeAllForTenant(context.Context, string, time.Time) (int, int, error)
	})
	if !ok || revoker == nil {
		// Say so rather than reporting a clean deletion: a store that cannot revoke leaves live sessions behind.
		result["sessions_revoked"] = "unsupported by this admin auth store — check for live sessions by hand"
		return result
	}
	sessions, tokens, err := revoker.RevokeAllForTenant(ctx, tenantID, now)
	if err != nil {
		log.Printf("tenant %q deleted, but revoking its sessions/tokens FAILED: %v", tenantID, err)
		result["sessions_revoked"] = fmt.Sprintf("failed: %v", err)
		return result
	}
	result["sessions_revoked"] = sessions
	result["api_tokens_revoked"] = tokens
	if sessions > 0 || tokens > 0 {
		log.Printf("tenant %q deleted: revoked %d session(s) and %d API token(s)", tenantID, sessions, tokens)
	}
	return result
}

// bodyNamesOperatorEnvelope reports which envelope fields the request body actually CARRIED. The struct decode
// cannot answer this — an absent operator_managed and a present false are the same bool — so the raw body is
// read a second time as a map. Cheap, and the alternative (pointer fields on the model) would put "was it
// sent?" into every other place the model is used.
func bodyNamesOperatorEnvelope(raw []byte) map[string]bool {
	named := map[string]bool{}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return named
	}
	for _, key := range []string{"operator_managed", "operator_elevations", "operator_elevation_requires_approval",
		"operator_delegation_changed_at", "operator_delegation_changed_by"} {
		if _, present := probe[key]; present {
			named[key] = true
		}
	}
	return named
}

// preserveOperatorEnvelopeOnUpsert copies the stored envelope back onto an incoming record for every envelope
// field the body did not name. A body that DOES name one is honoured — an operator restoring a full record
// from a backup must be able to, and the whole point is that omission stops meaning erasure.
func preserveOperatorEnvelopeOnUpsert(ctx context.Context, store adminTenantModelAdminStore, incoming adminTenantModel, named map[string]bool) adminTenantModel {
	if store == nil {
		return incoming
	}
	if len(named) == 5 {
		return incoming // the body carried the whole envelope
	}
	existing, err := store.Get(ctx, strings.TrimSpace(incoming.TenantID))
	if err != nil {
		// Unreadable registry: do not invent an envelope, and do not erase one either — the incoming record is
		// what the caller asked for, and a failure here must not be the thing that revokes a delegation.
		return incoming
	}
	if !named["operator_managed"] {
		incoming.OperatorManaged = existing.OperatorManaged
	}
	if !named["operator_elevations"] {
		incoming.OperatorElevations = existing.OperatorElevations
	}
	if !named["operator_elevation_requires_approval"] {
		incoming.OperatorElevationRequiresApproval = existing.OperatorElevationRequiresApproval
	}
	if !named["operator_delegation_changed_at"] {
		incoming.OperatorDelegationChangedAt = existing.OperatorDelegationChangedAt
	}
	if !named["operator_delegation_changed_by"] {
		incoming.OperatorDelegationChangedBy = existing.OperatorDelegationChangedBy
	}
	return incoming
}

// adminTenantCreateAnswer is the created organization plus what else the creation did. Embedded so every field
// an existing caller already reads is exactly where it was.
type adminTenantCreateAnswer struct {
	adminTenantModel
	// TransportServerName is the name this organization's devices will be told to send, when one was created
	// with it. Empty means it is served the deployment's shared certificate.
	TransportServerName string `json:"transport_server_name,omitempty"`
	// TransportAuthorityNote says why there is none, when one was asked for and could not be made. The
	// organization still exists — refusing the creation over this would leave the operator with neither.
	TransportAuthorityNote string `json:"transport_authority_note,omitempty"`
	// StartingPosture is what this organization carries from the moment it exists.
	StartingPosture string `json:"starting_posture,omitempty"`
	// StartingPostureNote says why it has none. An organization without one carries nothing at all, so this
	// is the field that says "created, and it does not work yet".
	StartingPostureNote string `json:"starting_posture_note,omitempty"`
}

// startingPostureRule is what a new organization carries from the moment it exists: everything allowed and
// inspected — the sentence its own Internet Access screen opens with, and the posture the deployment's own
// organization has had since it was installed.
//
// ★ ONE RULE, AT THE PRIORITY THE RULE EDITOR OFFERS BY DEFAULT, so anything the customer adds to narrow it
// sits naturally above or below and the screen reads the way it reads for every other rule.
func startingPostureRule(tenantID string) policyrule.Rule {
	return policyrule.Rule{
		TenantID:    tenantID,
		Plane:       policyrule.PlaneEgress,
		Priority:    100,
		Name:        "Everything, allowed and inspected — the rule to narrow first",
		Source:      []string{"*"},
		Destination: []string{"*"},
		Action:      policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect},
		Status:      policyrule.StatusActive,
	}
}

// adminTenantBodyAsksForTransportAuthority reads the one optional field, from the RAW body rather than from a
// decoded struct: adminTenantModel is a whole-record upsert and adding a field to it would make every
// read/modify/write round-trip carry an instruction.
func adminTenantBodyAsksForTransportAuthority(raw []byte) bool {
	var body struct {
		TransportAuthority *bool `json:"transport_authority"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.TransportAuthority == nil {
		return false
	}
	return *body.TransportAuthority
}

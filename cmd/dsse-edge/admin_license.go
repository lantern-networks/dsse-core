package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/seatallocation"
	"github.com/lantern-networks/dsse-core/vendorlicense"
)

// The MSSP's side of licensing: apply what the vendor sent, and divide it among the tenants being operated.
//
// Built around what actually generates work for an operator rather than around the data model. Three things do:
// a licence arrives and has to go in; a customer needs seats; and somebody rings up because a device will not
// enrol. The third is the one a status dashboard never answers, so it is answered here — the per-tenant view
// carries the SAME refusal the enrolment path would produce, from the same function, because a reason
// re-derived in a browser is a reason that will eventually disagree with the one the device was given.
type adminLicenseDeps struct {
	licence     *licenseStore
	allocations *seatallocation.Store
	licensing   *enrolmentLicensing
	ledger      interface {
		CountAdmitted(string) int
		CountUntenanted() int
		Tenants() []string
	}
	// displayName resolves a tenant's human name. Optional: with no tenant model available the rows fall back to
	// the identifier, which is worse to read but never wrong.
	displayName     func(tenantID string) string
	acceptedKeys    []*ecdsa.PublicKey
	recipientKey    *ecdh.PrivateKey
	msspID          string
	oversubscribe   bool
	now             func() time.Time
	auditAllocation func(*http.Request, string, string, string, *int)
}

// tenantSeatView is one row of the thing an operator actually reads.
type tenantSeatView struct {
	TenantID string `json:"tenant_id"`
	// DisplayName is what a person calls this tenant. A console that shows a raw identifier makes an operator
	// translate ids in their head, and this page is read while somebody is on the phone — the id belongs
	// underneath the name, not instead of it.
	DisplayName string `json:"display_name,omitempty"`
	Allocated   int    `json:"allocated"`
	Used        int    `json:"used"`
	// Blocked is true when this tenant cannot enrol another device right now, and Reason says why in the
	// operator's terms. This is the answer to the support call, precomputed.
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
}

func (d adminLicenseDeps) tenantViews() []tenantSeatView {
	seen := map[string]bool{}
	var ids []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			return
		}
		seen[strings.ToLower(t)] = true
		ids = append(ids, t)
	}
	for _, a := range d.allocations.List() {
		add(a.TenantID)
	}
	// Tenants with devices but NO allocation are included on purpose: that combination is exactly what an
	// operator gets called about, and a view built only from the allocation table would not show it.
	if d.ledger != nil {
		for _, t := range d.ledger.Tenants() {
			add(t)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return strings.ToLower(ids[i]) < strings.ToLower(ids[j]) })

	out := make([]tenantSeatView, 0, len(ids))
	for _, id := range ids {
		v := tenantSeatView{TenantID: id, Allocated: d.allocations.SeatsFor(id)}
		if d.displayName != nil {
			if name := strings.TrimSpace(d.displayName(id)); name != "" && !strings.EqualFold(name, id) {
				v.DisplayName = name
			}
		}
		if d.ledger != nil {
			v.Used = d.ledger.CountAdmitted(id)
		}
		if d.licensing != nil {
			if reason, blocked := d.licensing.RefuseEnrolment(id); blocked {
				v.Blocked, v.Reason = true, reason
			} else if note := d.licensing.QuotaNote(id, v.Used); note != "" {
				// ★ NOT BLOCKED IS NOT THE SAME AS NOTHING TO SAY (2026-08-14). Quotas stopped refusing that day,
				// so a tenant past its number — and a tenant nobody has given a number to — both answer "can
				// enrol", and the row would go quiet about the two conditions an operator most wants to see. The
				// row still carries the sentence; what changed is that it no longer claims the tenant is stuck.
				v.Reason = note
			}
		}
		out = append(out, v)
	}
	return out
}

// nextPoolChange finds when the seat pool next changes size, and to what.
//
// A seat block lapsing shrinks the pool on a date nobody is watching, and the first symptom is an enrolment
// failing. Surfacing the date turns that into something an operator can plan around.
func nextPoolChange(p vendorlicense.Payload, from time.Time) (when string, seats int, found bool) {
	current := p.SeatsAt(from)
	var candidates []time.Time
	for _, g := range p.Grants {
		for _, s := range []string{g.StartsAt, g.EndsAt} {
			if strings.TrimSpace(s) == "" {
				continue
			}
			if t, err := time.Parse(time.RFC3339, s); err == nil && t.After(from) {
				candidates = append(candidates, t)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
	for _, t := range candidates {
		if n := p.SeatsAt(t); n != current {
			return t.UTC().Format(time.RFC3339), n, true
		}
	}
	return "", 0, false
}

func registerAdminLicenseEndpoints(mux *http.ServeMux, d adminLicenseDeps,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc) {

	if d.now == nil {
		d.now = time.Now
	}
	adminOf := func(r *http.Request) string {
		if identity, ok := adminIdentityFromRequest(r); ok {
			return identity.PrincipalID
		}
		return ""
	}
	ready := func(w http.ResponseWriter) bool {
		if d.licence == nil || d.allocations == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("licensing is not configured on this Edge"))
			return false
		}
		return true
	}

	mux.HandleFunc("GET /admin/license", adminEndpoint("admin.state.read", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		now := d.now().UTC()
		// ★ EVERY ORGANIZATION'S DEVICE COUNT WAS READABLE BY EVERY ORGANIZATION (2026-08-16, found by an
		// adversarial pass over the new operator screens). This route is gated on admin.state.read — a
		// permission every tenant role holds, correctly, because a customer must be able to see its own
		// allowance — and it answered with the per-tenant table for the WHOLE deployment. Measured with
		// northwind's own administrator, holding no cross-tenant permission at all: it read
		// tenant_reference_lab, allocated 0, using 3.
		//
		// Capacity ACROSS organizations is the operator's business: they sell it and they allocate it. One
		// organization's usage is not another's, and a customer being able to enumerate the others is the
		// same defect the four device-facing reads had, in the one surface nobody had looked at.
		//
		// The totals stay for everyone: a customer seeing "the pool has room" is not learning anything about
		// anybody else, and hiding it would make their own row unreadable.
		visible := d.tenantViews()
		if !adminCallerIsOperator(r) {
			caller := strings.TrimSpace(adminTenantIDFromRequest(r))
			mine := make([]tenantSeatView, 0, 1)
			for _, view := range visible {
				if strings.EqualFold(strings.TrimSpace(view.TenantID), caller) {
					mine = append(mine, view)
				}
			}
			visible = mine
		}
		body := map[string]any{
			"schema_version": "admin_license.v1",
			// Whether a licence is REQUIRED here at all. Without this a console cannot tell an unlicensed
			// deployment (nothing is gated) from a licensed one with no licence yet (everything is held), and
			// telling the first that no device can enrol is a plain falsehood.
			"enforced": d.licensing != nil && d.licensing.Enforced(),
			// ★★ AND THE THIRD STATE: A NODE THAT CANNOT TELL (2026-08-21, measured). The comment above names
			// two cases and there is a third. An Edge started without licence material has no licensing gate
			// at all, so it answered "enforced": false — the same words an unlicensed deployment uses —
			// while its neighbour in the same fleet answered true with 30 of 50 seats allocated. A gate that
			// is on or off depending on which Edge a load balancer picked is not a gate, and the screen said
			// nothing to distinguish the two. This node now says whether it is able to answer at all.
			"licence_evaluated_here":   d.licensing != nil,
			"tenants":                  visible,
			"allocated":                d.allocations.Allocated(),
			"oversubscription_allowed": d.oversubscribe,
		}
		// Enforcement that counts nothing is not enforcement, and it looks identical to an empty fleet.
		//
		// Seats are counted per tenant. An enrolled entry carrying no tenant matches no tenant and is counted
		// nowhere, so a deployment whose inventory was SEEDED rather than enrolled — every entry written before
		// tenants were tagged — reports zero seats in use while admitting devices, and a licence that says it is
		// enforced can never refuse anything. Nothing about that is visible from a seat table reading zero.
		if d.ledger != nil {
			if untenanted := d.ledger.CountUntenanted(); untenanted > 0 {
				body["untenanted_devices"] = untenanted
				if d.licensing != nil && d.licensing.Enforced() {
					body["seat_counting"] = "not_counting"
					body["seat_counting_note"] = fmt.Sprintf(
						"%d enrolled device(s) carry no tenant, so they are counted against no seat pool. Licensing reports itself enforced and the seat limit cannot bite while this is true. Devices enrolled through the Console are tagged; entries seeded directly into the inventory are not.",
						untenanted)
				}
			}
		}
		p, have, why := d.licence.CurrentWithReason(d.acceptedKeys, d.msspID)
		body["licensed"] = have
		if !have {
			// Say which of the two "no licence" situations this is. They look identical in a table and need
			// opposite responses: one is a deployment that was never licensed, the other is a file that no
			// longer verifies — a withdrawn vendor key, a corrupted store.
			if d.licence.LastAcceptedSerial() > 0 {
				body["state"] = "licence_no_longer_verifies"
				// ★ AND WHICH CHECK FAILED (2026-08-17). "No longer verifies" has three causes that need three
				// different responses — re-issue to the new holder, replace a withdrawn key, investigate a
				// rollback — and the verifier names the one that happened. Not reporting it left the Console
				// guessing, and on this deployment the guess ("usually a withdrawn vendor signing key") sent an
				// operator after the wrong thing while no device could enrol.
				if why != nil {
					body["verification_error"] = why.Error()
				}
			} else {
				body["state"] = "no_licence_installed"
			}
			writeJSON(w, http.StatusOK, body)
			return
		}
		seats := p.SeatsAt(now)
		body["state"] = p.StateAt(now).String()
		body["seats"] = seats
		body["unallocated"] = seats - d.allocations.Allocated()
		body["expires_at"] = p.ExpiresAt
		body["enrolment_stops_at"] = p.EnrolmentStopsAt
		body["features"] = p.FeaturesAt(now)
		if when, next, ok := nextPoolChange(p, now); ok {
			// The pool is about to change size. Nobody watches for this, and the first symptom is an enrolment
			// that fails for no visible reason.
			body["next_pool_change_at"] = when
			body["next_pool_seats"] = next
		}
		// ★★ THE OPERATOR'S CONTRACT IS NOT THE CUSTOMER'S BUSINESS (2026-08-17, read as the first
		// administrator of a self-run organization — a session that only became possible today). The per-tenant
		// TABLE was scoped in August after the same kind of pass, and the fields around it were not: this route
		// still handed every customer the licence's addressee (mssp_id — the operator's own tenant id), its
		// serial, whether the deployment is on an evaluation, when the operator's service contract ends, and
		// the grant schedule (how many seats they bought and until when). Measured with a principal holding no
		// cross-tenant permission at all.
		//
		// What a customer needs from this route is whether their devices can enrol and how many seats they
		// hold. The pool totals stay for everyone, as the note above decided — "the pool has room" explains a
		// refusal without naming anybody. The commercial record between the operator and their vendor is a
		// different question, and no customer asked it.
		if adminCallerIsOperator(r) {
			body["mssp_id"] = p.MSSPID
			body["serial"] = p.Serial
			body["is_evaluation"] = p.IsEvaluation
			body["service_ends_at"] = p.ServiceEndsAt
			body["grants"] = p.Grants
			// ★★ ALLOCATED IS A PLAN; ENROLLED IS THE COUNT. `unallocated` above says how much of the pool the
			// operator handed out, which is not how much is in use, and it was the only pool number this route
			// reported. The licence grants AGENTS, so the deployment states how many it has.
			//
			// ★ OPERATOR-ONLY, unlike the pool totals beside it. The pool is a capacity a customer may be told
			// about — "there is room" explains a refusal without naming anybody. A DEPLOYMENT-WIDE device count
			// is different in kind: a customer holding ten devices who reads 400 has just learned that 390
			// belong to organizations they cannot see.
			enrolled := deploymentAgentsEnrolled(d.ledger)
			body["agents_enrolled"] = enrolled
			body["seats_remaining"] = seats - enrolled
			if note := licenceUsageNote(seats, enrolled); note != "" {
				body["usage_note"] = note
			}
		}
		writeJSON(w, http.StatusOK, body)
	}))

	mux.HandleFunc("POST /admin/license", adminEndpoint("admin.quota.write", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxEdgeRuntimeJSONBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read licence: %w", err))
			return
		}
		env, err := parseLicenseEnvelope(raw, d.recipientKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		now := d.now().UTC()

		// A dry run answers "what would this do" before anything changes. Applying a licence that shrinks the
		// pool below what is already allocated is legitimate and sometimes necessary, but it should never be a
		// surprise — the operator has redistribution to do, and finding out afterwards is how a customer's
		// enrolment breaks without anyone realising why.
		if strings.EqualFold(r.URL.Query().Get("dry_run"), "true") {
			p, vErr := vendorlicense.Verify(env, d.acceptedKeys, d.msspID, d.licence.LastAcceptedSerial())
			if vErr != nil {
				writeError(w, http.StatusBadRequest, vErr)
				return
			}
			current, have := d.licence.Current(d.acceptedKeys, d.msspID)
			writeJSON(w, http.StatusOK, map[string]any{
				"schema_version": "admin_license.v1",
				"dry_run":        true,
				"change":         summariseLicenceChange(current, have, p, d.allocations.Allocated(), now),
			})
			return
		}

		p, err := d.licence.Apply(env, d.acceptedKeys, d.msspID, adminOf(r), now.Format(time.RFC3339))
		if err != nil {
			if errors.Is(err, errLicensePersistence) {
				writeError(w, http.StatusServiceUnavailable, errors.New("Licence save could not be confirmed. Reload before retrying."))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		if d.licensing != nil {
			d.licensing.Apply(p)
		}
		over := 0
		if a := d.allocations.Allocated(); a > p.SeatsAt(now) {
			over = a - p.SeatsAt(now)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_license.v1",
			"seats":          p.SeatsAt(now),
			"expires_at":     p.ExpiresAt,
			"is_evaluation":  p.IsEvaluation,
			"serial":         p.Serial,
			// Reported rather than refused: shrinking the pool is a legitimate act, and the operator needs to
			// know they now have redistribution to do.
			"over_allocated": over,
		})
	}))

	mux.HandleFunc("POST /admin/seat-allocations", adminEndpoint("admin.quota.write", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		var req struct {
			TenantID string `json:"tenant_id"`
			// Seats is a POINTER so that "absent" and "zero" stay distinguishable.
			//
			// ★ MEASURED (2026-08-15). A request sent as {"max_devices": 25} — the wrong field name — answered
			// 200 and set the tenant's cap to ZERO, because the unknown field was dropped in silence and the
			// missing one defaulted. A typo became an enforcement change that blocks every enrolment for that
			// customer, reported as success. Zero is a legitimate cap, so it cannot be rejected on its value;
			// what has to be rejected is not saying.
			Seats *int   `json:"seats"`
			Note  string `json:"note"`
		}
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode allocation: %w", err))
			return
		}
		if req.Seats == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"seats is required — send seats:0 if the intent really is a cap of zero, which blocks every enrolment for this tenant"))
			return
		}
		// ★★ THE CALLER NAMES THE TENANT, BECAUSE THE CALLER IS THE OPERATOR (2026-08-14, second correction).
		//
		// The first fix bound this route's tenant to the caller's own, which stopped a per-tenant `admin` taking
		// seats from somebody else — and left the real defect in place: that `admin` could still raise ITS OWN
		// quota. The party a limit constrains was the party who wrote it, and the only thing standing in for an
		// authorisation control was the Lantern-signed pool total, which the OSS plan removes.
		//
		// The route now requires admin.quota.write, which the per-tenant `admin` does not hold and the
		// cross-tenant operator (super_admin) does. Naming another tenant is therefore no longer a privilege
		// escalation, it is the entire purpose: an MSSP operator sets each tenant's quota. Binding the tenant to
		// the caller here would now mean the operator could only ever set a quota for the operator tenant.
		callerTenant := adminTenantIDFromRequest(r)
		if callerTenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this identity has no tenant"))
			return
		}
		// Named explicitly rather than defaulted to the caller: a quota written for the wrong tenant is not
		// visible in the response, and "whichever tenant I happened to be operating as" is not a decision an
		// operator should be able to make by omission.
		if strings.TrimSpace(req.TenantID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant_id is required: an operator sets a quota FOR "+
				"a tenant, so which tenant is not something this route will assume"))
			return
		}
		req.TenantID = strings.TrimSpace(req.TenantID)

		now := d.now().UTC()
		pool := 0
		if p, have := d.licence.Current(d.acceptedKeys, d.msspID); have {
			pool = p.SeatsAt(now)
		}
		policy := seatallocation.Policy{PoolSeats: pool, AllowOversubscription: d.oversubscribe}
		a, err := d.allocations.AllocateContext(r.Context(), policy, req.TenantID, *req.Seats, adminOf(r), req.Note, now.Format(time.RFC3339))
		if d.auditAllocation != nil {
			result := "success"
			if err != nil {
				result = "error"
			}
			d.auditAllocation(r, req.TenantID, "allocate", result, req.Seats)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, seatallocation.ErrPersistence) {
				writeError(w, http.StatusServiceUnavailable, errors.New("Seat allocation save could not be confirmed. Reload before retrying."))
				return
			}
			if strings.Contains(err.Error(), "exceed the licensed pool") {
				status = http.StatusConflict
			}
			writeError(w, status, err)
			return
		}
		used := 0
		if d.ledger != nil {
			used = d.ledger.CountAdmitted(a.TenantID)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_license.v1",
			"allocation":     a,
			"used":           used,
			"unallocated":    pool - d.allocations.Allocated(),
			// An allocation below current use is allowed — an MSSP reclaiming seats is legitimate. Say so
			// plainly rather than letting it look like it failed: nothing already running is affected, and only
			// growth stops.
			"below_current_use": used > a.Seats,
		})
	}))

	mux.HandleFunc("DELETE /admin/seat-allocations/{tenant}", adminEndpoint("admin.quota.write", func(w http.ResponseWriter, r *http.Request) {
		if !ready(w) {
			return
		}
		// Like allocation, release is an operator quota operation for the explicitly named tenant.
		// The endpoint permission remains admin.quota.write; customer administrators cannot use it.
		tenant := strings.TrimSpace(r.PathValue("tenant"))
		if adminTenantIDFromRequest(r) == "" || tenant == "" {
			writeError(w, http.StatusForbidden, errors.New("an authenticated tenant and allocation target are required"))
			return
		}
		removed, err := d.allocations.RemoveConfirmedContext(r.Context(), tenant)
		if d.auditAllocation != nil {
			result := "success"
			if err != nil || !removed {
				result = "error"
			}
			d.auditAllocation(r, tenant, "remove", result, nil)
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("Seat allocation removal could not be confirmed. Reload before retrying."))
			return
		}
		if !removed {
			writeError(w, http.StatusNotFound, errors.New("no allocation for that tenant"))
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_license.v1",
			"tenant_id":      tenant,
			"removed":        true,
		})
	}))
}

package main

// Whose Named Network is it?
//
// ★★★ MEASURED, NOT REASONED (2026-08-16). Signed in to the Console as Northwind's administrator — roles
// ["admin"], no cross-tenant permission of any kind — the Networks screen listed another organization's
// network object, and DELETE on it returned 200 and removed it from the control plane. A customer deleted a
// customer's configuration.
//
// Three separate omissions, all in one small file of routes:
//
//   - the LISTS had no tenant filter at all (objects, boundary policies, and the firewall export built from
//     both). The write path had always stamped the caller's organization onto what it saved, so the data was
//     correctly attributed the whole time — nothing ever read the attribution back.
//   - DELETE resolved by id alone. An id is not a permission, and ids here are operator-chosen strings.
//   - the upsert took tenant_id FROM THE BODY when one was supplied, so a customer could file an object under
//     another organization's name as easily as read one.
//
// The rule everywhere below: an operator (admin.tenant.admin) sees and touches the whole deployment; anyone
// else sees and touches their own organization, and an object belonging to another organization is answered
// as ABSENT rather than as forbidden — "there is no such object here" is true from where they stand, and a
// 403 would confirm the id exists.

import (
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// adminVLANCallerTenant is the organization a VLAN request acts within: empty for an operator, who acts across
// the deployment.
func adminVLANCallerTenant(r *http.Request) (tenant string, wholeDeployment bool) {
	return adminAnswerScope(r)
}

func vlanObjectVisibleTo(o model.VLANObject, callerTenant string, isOperator bool) bool {
	if isOperator {
		return true
	}
	// Material with no organization on it is the deployment's own and predates per-tenant attribution. It stays
	// visible: hiding it would take a customer's own unattributed definitions away from them, which is a
	// different fault than the one being fixed. New objects are always attributed by the write path.
	owner := strings.TrimSpace(o.TenantID)
	return owner == "" || strings.EqualFold(owner, callerTenant)
}

func vlanPolicyVisibleTo(p model.VLANBoundaryPolicy, callerTenant string, isOperator bool) bool {
	if isOperator {
		return true
	}
	owner := strings.TrimSpace(p.TenantID)
	return owner == "" || strings.EqualFold(owner, callerTenant)
}

func vlanObjectsVisibleTo(all []model.VLANObject, callerTenant string, isOperator bool) []model.VLANObject {
	out := make([]model.VLANObject, 0, len(all))
	for _, o := range all {
		if vlanObjectVisibleTo(o, callerTenant, isOperator) {
			out = append(out, o)
		}
	}
	return out
}

func vlanPoliciesVisibleTo(all []model.VLANBoundaryPolicy, callerTenant string, isOperator bool) []model.VLANBoundaryPolicy {
	out := make([]model.VLANBoundaryPolicy, 0, len(all))
	for _, p := range all {
		if vlanPolicyVisibleTo(p, callerTenant, isOperator) {
			out = append(out, p)
		}
	}
	return out
}

package main

// verify_an_organization_can_have_its_own_tree.go — whether this deployment has anywhere to keep one.
//
// ★★★ THE CHECK BESIDE THIS ONE REPORTED A SHARED ROOT AS A SUCCESS (2026-08-27, caught by the operator
// asking whether an organization and its PKI had been stood up before an agent was connected).
//
//	ok  the deployment inspects under ONE authority   all 2 Edge(s) sign intercepted traffic with the same authority
//
// That check is right about what it asks — every Edge in the fleet using the same DEFAULT authority, because
// an Edge that was missed mints its own and signs under a root no device has heard of. It is the opposite of
// the question an organization cares about. Every organization has its own tree so that no single key can
// impersonate two of them, and "they are all the same one" is exactly what that must NOT mean.
//
// Nothing asked the other question. Walked on a generated deployment: the Console offered "Load this tenant's
// interception CA", the control plane answered "interception is not enabled on this node", and the Edge
// reported configured=shared, per_tenant_issuers=0 — a deployment that could never separate two customers,
// certified as ready to hand over.
//
// ★ IT DOES NOT COUNT ORGANIZATIONS. A deployment with one customer, or none yet, is not misconfigured; it
// simply has nothing to be separate from. What is asked here is whether the PLACE exists — because that is
// decided at install time, is invisible until the second customer arrives, and by then the fix is a restart
// of the authority.

import (
	"fmt"
	"net/http"
	"strings"
)

// verifyAnOrganizationCanHaveItsOwnTree asks the control plane whether it can hold an organization's own
// interception authority at all.
func verifyAnOrganizationCanHaveItsOwnTree(client *http.Client, cpAdmin, adminToken string) []verifyResult {
	const name = "an organization can have its own interception authority"
	cpAdmin = strings.TrimRight(strings.TrimSpace(cpAdmin), "/")
	if cpAdmin == "" {
		return nil
	}
	status, body, err := get(client, cpAdmin+"/admin/interception-roots", adminToken)
	if err != nil {
		return []verifyResult{{name: name, note: fmt.Sprintf("%s could not be asked: %v", cpAdmin, err)}}
	}
	switch status {
	case http.StatusConflict:
		// ★ THE RIGHT ANSWER, AND IT READS LIKE AN ERROR. "This node holds organizations' authorities but
		// serves no traffic" is a control plane declining an EDGE's question, which is precisely the shape a
		// deployment should have: authorities on the control plane, traffic on the Edges.
		return []verifyResult{{ok: true, name: name, note: fmt.Sprintf(
			"%s holds organizations' interception authorities and serves no traffic, which is the separation "+
				"this question is about — an organization's own authority has somewhere to live", cpAdmin)}}
	case http.StatusServiceUnavailable:
		return []verifyResult{{name: name, note: fmt.Sprintf(
			"%s answered %q. The control plane has no store for the interception authorities organizations "+
				"delegate to it, so EVERY organization is inspected under this deployment's one shared root "+
				"and none can be given its own. Start it with -tenant-interception-authority-store (and the "+
				"device and transport twins beside it). It is invisible until the second customer arrives, "+
				"and by then the fix is a restart of the authority",
			cpAdmin, firstLineOf(body))}}
	case http.StatusOK:
		return []verifyResult{{name: name, note: fmt.Sprintf(
			"%s answered as a node that INSPECTS. That is an Edge's answer; -control-plane should name the "+
				"control plane, whose job is to hold organizations' authorities rather than to serve their "+
				"traffic", cpAdmin)}}
	default:
		return []verifyResult{{name: name, note: fmt.Sprintf(
			"%s answered %d: %s", cpAdmin, status, firstLineOf(body))}}
	}
}

func firstLineOf(body []byte) string {
	s := strings.TrimSpace(string(body))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

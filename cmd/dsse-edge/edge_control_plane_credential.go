package main

// edge_control_plane_credential.go — what an Edge needs from its control plane, and nothing more.
//
// ★ THE CONFIG-PULL IDENTITY WAS THE SHARED OWNER SECRET (the machine-credential separation). -steer-exclusion-source-token defaults to
// -admin-token, so the credential an Edge presents to its control plane on every poll was the same
// owner-level break-glass a human uses — which means a leaked pull credential is an owner of the deployment,
// and a compromised Edge can author policy for every organization rather than read its own configuration.
//
// The machine path calls exactly three routes. Listed here, with the permission each one needs, so the token
// minted for it can be that and no more.
type edgeControlPlaneCall struct {
	Method string
	Path   string
	// Permission is the scope the route is gated on.
	Permission string
	// Why records what stops working without it, because a scope list with no reasons is one nobody can
	// safely shorten and everybody widens.
	Why string
}

var edgeControlPlaneCalls = []edgeControlPlaneCall{
	{
		Method: "GET", Path: "/admin/config-bundle", Permission: "admin.policy.read",
		Why: "the versioned configuration this Edge enforces — policies, the tenant registry, tombstones, " +
			"purge orders and the operator delegations. Without it the Edge keeps serving whatever it last " +
			"applied and stops learning about changes",
	},
	{
		Method: "GET", Path: "/admin/steer-exclusions", Permission: "admin.steering.read",
		Why: "the admin-managed steering exclusions this Edge's devices are told about",
	},
	{
		Method: "POST", Path: "/admin/enrolled-devices", Permission: "admin.enrollment.write",
		Why: "reporting an enrolment completed HERE to the control plane. Without it the next config bundle " +
			"rebuilds the ledger from the CP's copy and the device the Edge just enrolled is dropped",
	},
}

// edgeControlPlaneScopes is the scope set a machine credential for this path should carry.
//
// It is a WRITE-narrow set on purpose: one write, to report an enrolment, and two reads. A token holding this
// cannot author policy, cannot touch PKI, cannot see another organization's devices and cannot mint another
// token — which is the difference between a leaked pull credential and a leaked deployment.
func edgeControlPlaneScopes() []string {
	seen := map[string]bool{}
	scopes := []string{}
	for _, call := range edgeControlPlaneCalls {
		if seen[call.Permission] {
			continue
		}
		seen[call.Permission] = true
		scopes = append(scopes, call.Permission)
	}
	return scopes
}

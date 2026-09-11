package main

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// a_profile_missing_the_organizations_authorities.go — a profile that cannot carry an organization's own
// authorities must not be issued.
//
// ★★★ MEASURED ON A LIVE DEPLOYMENT, 2026-08-31. Three organizations were created while the control plane in
// the founding region held leadership, and each was minted its own device-identity CA, transport authority
// and interception root. Leadership later moved to the other region. From that moment every profile issued —
// 200, correctly signed, indistinguishable from a good one — came out like this:
//
//	deployment:   agent_policy_signing_public_key, anchor_pem, steer_exclusions, update_*
//	organization: tenant_id
//
// against this, issued an hour earlier for the same organization:
//
//	deployment:   … device_ca_pin_sha256, interception_root_pem, transport_anchors_pem …
//	organization: tenant_id, transport_server_name, enrolment_server_name
//
// A device installed from the second one enrols at its organization's own door, pins the organization's
// device CA, and trusts the root its traffic will be signed under. A device installed from the first has none
// of that: it dials the deployment-wide name, pins nothing, and refuses every page once its Edge starts
// inspecting — and every screen involved says the profile was issued.
//
// The underlying split (an organization's authorities are known to the node that minted them) is a separate
// and larger piece of work. This is the part that must not wait for it: an answer that omits what a device
// cannot work without is not a degraded answer, it is a wrong one, and it is worse than an error because it
// installs.
//
// ★ IT DOES NOT INVENT A RULE ABOUT WHICH ORGANIZATIONS HAVE AUTHORITIES. An organization that has not been
// given its own is a real and supported state — the deployment's own authorities cover it, and the profile
// says so by carrying none. What this refuses is the case where the organization HAS them and this node
// cannot see them, which is why it is asked as a question about this node rather than about the profile.

// organizationAuthoritiesUnavailable reports what this node cannot see for an organization that has it. The
// returned string is empty when there is nothing to refuse.
func organizationAuthoritiesUnavailable(config serverConfig, tenant string, spec installprofile.DeploymentSpec) string {
	missing := []string{}
	if config.TenantTransportAuthority != nil {
		if _, err := config.TenantTransportAuthority.materialSnapshot(); err != nil {
			return "a current shared transport authority snapshot (read failed)"
		}
	}
	if config.TenantDeviceAuthority != nil {
		snapshot, err := config.TenantDeviceAuthority.materialSnapshot()
		if err != nil {
			return "a current shared device-identity authority snapshot (read failed)"
		}
		if _, known := snapshot.cas[strings.ToLower(strings.TrimSpace(tenant))]; known && spec.DeviceCAPinSHA256 == "" {
			missing = append(missing, "the device-identity CA this organization pins")
		}
	}
	if config.TenantInterceptionAuthority != nil {
		snapshot, err := config.TenantInterceptionAuthority.materialSnapshot()
		if err != nil {
			return "a current shared interception authority snapshot (read failed)"
		}
		if _, known := snapshot.issuers[strings.ToLower(strings.TrimSpace(tenant))]; known && strings.TrimSpace(spec.InterceptionRootPEM) == "" {
			missing = append(missing, "the interception root its traffic is signed under")
		}
	}
	// ★★★ AND A NODE THAT HOLDS NONE OF THEM CANNOT ANSWER AT ALL (2026-09-06, measured on a three-region
	// deployment while walking the Console's own Device configuration screen). Everything above asks "does
	// this node hold the organization's authority, and is it missing from the profile?" — so on a node that
	// holds NO per-organization authorities the question is never asked, and the checks that follow quietly
	// fill the field with the DEPLOYMENT's interception root. The same request, for the same organization,
	// with the same credential, on the two planes of one deployment:
	//
	//	edge          200  interception_root_is_own=false  → Kusunoki Networks Interception CA
	//	control plane 200  interception_root_is_own=true   → Hiiragi Foods Interception Root
	//
	// Both signed, both installable, and the Console asked the Edge. A device built from the first is steered,
	// has its traffic re-signed under its organization's root, and has never been told that root exists —
	// which is the exact failure the top of this file describes, arriving through the one door the check
	// leaves open.
	//
	// ★ ASKED AS A QUESTION ABOUT THIS NODE, like the rest of the file. A deployment where nobody uses
	// per-organization PKI has these stores nil on every node and must keep working; what is refused is a node
	// that PULLS ITS CONFIG from an authority — it has one, upstream, and that authority is the only place
	// that knows whether this organization brought a PKI of its own.
	if len(missing) == 0 && strings.TrimSpace(config.ConfigSourceURL) != "" &&
		config.TenantInterceptionAuthority == nil && config.TenantDeviceAuthority == nil {
		return "any of this organization's own authorities"
	}
	if len(missing) == 0 {
		return ""
	}
	return strings.Join(missing, ", ")
}

// refuseTheProfileThisNodeCannotComplete turns the omission into a message an operator can act on: which node
// to ask, and why the one they asked could not answer.
func refuseTheProfileThisNodeCannotComplete(tenant, missing string) error {
	// ★ "this node", not "this control plane": the refusal is now also given by an Edge, and a node that calls
	// itself the authority while refusing to act as one is the sentence an operator cannot act on.
	return fmt.Errorf("this node cannot complete a profile for %q: it does not hold %s. "+
		"A profile issued without them installs and then fails on the device — it enrols at the "+
		"deployment-wide name, pins nothing, and refuses every page once its Edge inspects — so it is not "+
		"issued. An organization's authorities are held by the control plane that minted them; issue this "+
		"profile from that node, or give this one the organization's authorities first", tenant, missing)
}

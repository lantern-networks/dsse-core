package main

import (
	"flag"
	"net"
	"net/url"
	"strings"

	"github.com/lantern-networks/dsse-core/installprofile"
	"github.com/lantern-networks/dsse-core/steerexclusion"
)

// a_profile_is_the_whole_configuration.go — what a device must be TOLD, gathered from the deployment it is
// joining.
//
// ★★★ THE CUSTOMER GETS A PACKAGE, A PROFILE AND A ONE-TIME TOKEN, AND THAT HAS TO BE ALL OF IT (2026-08-29,
// the operator's call, made while watching a real Mac fail to start).
//
// Until now it was not all of it. The device also needed an agent_config.json holding the deployment's anchor,
// the organization's device-CA pin, its interception root, the update pins and a steering-rules file — and
// NOTHING IN THE PRODUCT PRODUCED THAT FILE. The lab had a script that wrote it by hand, which is a script no
// customer ever receives, and the product's own answer was "MDM drops it", which quietly makes MDM a
// requirement rather than a convenience. The gap was invisible because every walk of this lane had used the
// lab's script — the same shape as a check that measures the wrong thing: everything passed, and what passed
// was not the thing being claimed.
//
// So the profile carries them. None of them is a secret: an anchor, two fingerprints, a public root, two
// public keys and a list of application identifiers. The one thing that stays out is the one-time token, which
// is the only part that says THIS DEVICE — and that is why it is still handed over separately.
func deploymentFactsFor(config serverConfig, tenant string) installprofile.DeploymentSpec {
	spec := installprofile.DeploymentSpec{
		// The anchor every Edge is verified against. -connector-enrollment-edge-ca is the deployment anchor on
		// a deployment this product's installer generated; a device and a connector pin the same root.
		AnchorPEM:             strings.TrimSpace(config.ConnectorEnrollmentEdgeCAPEM),
		UpdateSigningKeys:     config.AgentUpdatePins,
		UpdatePublisherTeamID: strings.TrimSpace(config.AgentUpdatePublisher),
	}
	if config.AgentPolicySigner != nil {
		spec.AgentPolicySigningPublicKey = config.AgentPolicySigner.PublicKeyHex()
	}
	// ★ THE ORGANIZATION'S OWN AUTHORITIES, NOT THE DEPLOYMENT'S. A device pinned to the deployment's device CA
	// while its organization has one of its own refuses the certificate it is handed, at enrolment, on the
	// device, where the reason is not visible from here.
	if config.TenantDeviceAuthority != nil {
		if row, known := config.TenantDeviceAuthority.Row(tenant); known {
			if summary, ok := summarizeCertificatePEM(row.CACertPEM); ok {
				spec.DeviceCAPinSHA256 = summary.SHA256
			}
		}
	}
	// ★★★ THE AUTHORITY THAT SIGNS THE NAME THIS PROFILE TELLS THE DEVICE TO PRESENT. Without it the device
	// dials the organization's own address and cannot verify what it is served — see AnchorsFor.
	if config.TenantTransportAuthority != nil {
		spec.TransportAnchorsPEM = config.TenantTransportAuthority.AnchorsFor(tenant)
	}
	// ★★★ AND IF THE ORGANIZATION HAS NO AUTHORITY OF ITS OWN, THE DEPLOYMENT'S — BECAUSE SOMETHING IS
	// INSPECTING EITHER WAY (2026-09-04, measured by walking a Mac onto a deployment built from the published
	// tree). This filled the field only for an organization that had brought its own root, and left it EMPTY
	// otherwise. Empty is not "nothing is inspected": a deployment inspects under its own root until an
	// organization brings one, which is the state every deployment is in on the day it is handed over.
	//
	// What the empty field cost, on the wire: the Mac was steered, its traffic WAS re-signed — google.com
	// arrived issued by "yuki Interception CA" — and the device had never been told that root existed. The
	// profile is the first link of a chain: profile → agent_config.trusted_ca_bundle → the PEM bundle the
	// package points SSL_CERT_FILE at. With the first link empty every link after it is empty too, so every
	// command-line tool on the device failed to verify anything, with nothing anywhere able to say why. curl
	// returned 000 against a deployment that was working perfectly.
	//
	// ★ WHICH root it is matters, so the field is not the only thing that changes: InterceptionRootIsOwn says
	// whether this is the organization's or the deployment's, and a reader that installs a shared root should
	// know it installed a shared one.
	if config.TenantInterceptionAuthority != nil {
		if row, known := config.TenantInterceptionAuthority.Row(tenant); known {
			spec.InterceptionRootPEM = strings.TrimSpace(row.RootPEM)
			spec.InterceptionRootIsOwn = spec.InterceptionRootPEM != ""
		}
	}
	if spec.InterceptionRootPEM == "" && config.NetworkExtensionLabTLS != nil {
		spec.InterceptionRootPEM = strings.TrimSpace(string(config.NetworkExtensionLabTLS.RootCertificatePEM()))
		spec.InterceptionRootIsOwn = false
	}
	// ★ AND ON A NODE THAT NAMES THE ROOT WITHOUT SIGNING WITH IT — a control plane, which is the node the
	// Console asks. See -deployment-interception-root-cert.
	if spec.InterceptionRootPEM == "" {
		spec.InterceptionRootPEM = strings.TrimSpace(config.DeploymentInterceptionRootPEM)
		spec.InterceptionRootIsOwn = false
	}
	// ★ AND WHETHER THE STEP-UP PORTAL IS ON A CERTIFICATE THE WORLD TRUSTS. See the field's own note: this
	// is what lets a device add nothing to its trust store in production and still walk the ceremony in a lab.
	spec.StepUpPortalCertificateIsOperators = config.StepUpPortalCertificateIsOperators
	if !config.StepUpPortalCertificateIsOperators {
		// The portal is on this deployment's own certificate, so the profile says which authority that is —
		// once, here, rather than in each platform's client. See the field's note.
		spec.StepUpPortalAnchorPEM = strings.TrimSpace(config.ConnectorEnrollmentEdgeCAPEM)
	}
	spec.SteerExclusions = authoredSteerExclusions(config.SteerExclusions, tenant)
	spec.PassthroughDomains = thisDeploymentsOwnAdminNames(config)
	return spec
}

// thisDeploymentsOwnAdminNames is the deployment's own Console, named in the profile so a steered device can
// still reach it.
//
// ★★★ WHY (2026-08-30, the operator's point, and they were right). On a fleet running this product every
// corporate device is steered — that is the product. A steered device sends its traffic to an Edge, the Edge
// dials the destination, and the SWG egress guard refuses internal addresses: it is a forward proxy to the
// public internet, and internal destinations are reached as applications published through a connector. All
// correct. But on a sovereign deployment — this product's own shape — the Console lives on the customer's
// network, so the moment steering comes up on an ADMINISTRATOR's machine, they lose the Console. The remedy
// (publish it through a connector, or bypass it) is authored in the Console. The only screens that can fix it
// are behind the thing that is broken.
//
// So the deployment states its own address. This is NOT the invisible built-in list this product refuses to
// have (defaultTransparentPassthroughDomains is empty on purpose, and stays empty): it is one more fact about
// THIS deployment, in the signed profile the customer can read, beside the anchor and the interception root,
// per-deployment and visible on the screen that issues it. An operator who publishes the Console through a
// connector instead can drop it there.
//
// It is a passthrough, not a decrypt-bypass, and the difference is the whole point: the device must not send
// this flow to the Edge at all, because the Edge is exactly what cannot reach the address.
// ★★★ AND EVERY REGION'S, BECAUSE FAILOVER IS WHEN THIS MATTERS (2026-08-30, the operator's second point).
// A deployment that fails over answers its Console somewhere else afterwards. A device told only about the
// region that just died loses the Console at the moment an administrator needs it — which is the whole reason
// the destination is named. -admin-console-origins states them; nothing is derived from the region catalogue,
// because a name inferred from a convention works until the first deployment that does not follow it.
func thisDeploymentsOwnAdminNames(config serverConfig) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(origin string) {
		host := hostOfAdminOrigin(origin)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	// The single origin first: it is the one the Console redirects to, so it leads the list an operator reads.
	add(config.AdminConsoleOrigin)
	for _, origin := range strings.FieldsFunc(config.AdminConsoleOrigins, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		add(origin)
	}
	if len(out) == 0 {
		// Nothing is guessed. A deployment that never told an Edge where its Console is gets no entry, and an
		// empty list keeps meaning "the deployment authored nothing".
		return nil
	}
	return out
}

// hostOfAdminOrigin takes the host out of whatever shape an origin was written in — with a scheme, with a
// port, or bare.
func hostOfAdminOrigin(origin string) string {
	host := strings.TrimSpace(origin)
	if host == "" {
		return ""
	}
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		host = u.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// authoredSteerExclusions is the list this deployment has AUTHORED as never-steered, for this organization.
//
// ★ THIS PRODUCT SHIPS ZERO BUILT-IN EXCLUSIONS ON PURPOSE — an invisible application id compiled into a
// binary is not an authored, revocable policy — so whatever is here is the whole list, and an empty one is a
// meaningful answer rather than a missing one. It is also the list that decides whether the session doing the
// installing survives arming the agent, which is why it is stated in the profile rather than discovered.
func authoredSteerExclusions(store *steerexclusion.Store, tenant string) []string {
	if store == nil {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, policy := range store.List(tenant) {
		// Only what is in force. A withdrawn exclusion that still reached devices would be a policy an
		// operator believes they removed.
		if strings.TrimSpace(policy.Status) != "" && !strings.EqualFold(strings.TrimSpace(policy.Status), "active") {
			continue
		}
		for _, id := range policy.ExcludedAppSigningIDs {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// registerDeploymentInterceptionRootFlag defines this surface's flag HERE rather than in main.go — the same
// rule the connector-program surface follows, and the one the decomposition ratchet enforces.
// ★★★ THE ROOT A NODE NAMES BUT DOES NOT SIGN WITH (2026-09-04, found by walking a Mac onto a deployment
// built from the published tree). A control plane holds no interception key — signing stays with the
// Edges — but it is the node the Console asks for a device's configuration, and until now a profile it
// issued could not say what its devices would be inspected under. The device was then steered, its traffic
// WAS re-signed, and nothing on it had ever been told that authority existed: every command-line tool
// failed to verify anything, and no message anywhere named the cause.
//
// This carries the certificate and nothing else. It grants no ability to sign and is not part of the
// offline-intermediate triple in main.go.
func registerDeploymentInterceptionRootFlag() *string {
	return flag.String("deployment-interception-root-cert", "",
		"PEM path of THIS DEPLOYMENT's interception root, for a node that must NAME it in the device profiles "+
			"it issues without signing anything with it — a control plane. The Edges that actually inspect get "+
			"the root through the interception flags in main.go")
}

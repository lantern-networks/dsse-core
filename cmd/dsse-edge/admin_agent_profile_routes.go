package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/installprofile"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_agent_profile_routes.go — the deployment issues the one file every endpoint needs.
//
// ★★★ THERE WAS NO WAY TO PRODUCE IT WITHOUT THE REPOSITORY AND THE PRIVATE KEY (2026-08-25, reported from a
// real endpoint and from the operator). Making a profile meant: ssh to the machine holding the source, find
// cmd/dsse-genprofile, hand it the deployment's raw Ed25519 signing seed as a file path, and copy the JSON
// back. That is the ONLY configuration object every device requires, and an operator is not assumed to have a
// checkout, a Go toolchain, or shell access to the control plane.
//
// ★ AND THE KEY SHOULD NEVER BE IN A PERSON'S HANDS. The control plane already holds it and already signs
// agent policy with it; a profile is the same signature over a different document. Issued here, the private
// half never leaves the deployment — which the old procedure could not say.
//
// ★★ WHAT AN OPERATOR DECIDES IS SMALL, AND NOTHING HERE IS TYPED. The organization is the caller's. The
// addresses are the deployment's own regions. The bypass entries come from the catalogue this deployment
// already publishes. What is left is which group, what happens when an Edge cannot be reached, and which of
// the known bypasses apply.

// registerAgentProfileRoutes wires the two routes the screen needs: what the choices ARE, and issuing one.
func registerAgentProfileRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	config serverConfig, evaluator decision.Evaluator, writer *logs.Writer,
	adminAuditOutbox adminAuditOutboxDeadReader, agentPlaneURL string, regions func(tenantID string) []regionEndpoint) {

	// GET: everything the screen offers, so it can be built without the operator typing any of it.
	mux.HandleFunc("GET /admin/agent-profile/options", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		tenant := profileTenantForRequest(r, evaluator)
		endpoints := agentProfileEndpoints(agentPlaneURL, tenant, regions)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": tenant,
			// ★★ EVERYTHING THE SCREEN OFFERS COMES FROM HERE, in one read, because the alternative is a screen
			// that asks an operator to TYPE a group name and a bypass pattern. Both are matched by string on the
			// device: a typo produces a profile that is accepted, signed, installed, and silently wrong.
			"device_groups":  agentProfileGroups(config, tenant),
			"bypass_catalog": agentProfileBypassCatalog(config),
			// The addresses a device may start from, in the deployment's own words. The screen shows them
			// checked, in order, and lets that order be changed — it is the order a device tries.
			"transport_endpoints": endpoints,
			// ★ SAID SO THE SCREEN NEED NOT GUESS. A deployment that publishes only one region has nothing to
			// fail over to at first contact, and an operator should see that rather than infer it from a list
			// of length one.
			"transport_endpoints_note": agentProfileEndpointNote(endpoints),
			// ★ NAMED ON THE SCREEN, NOT DISCOVERED AT THE DEVICE. An address that resolves to the machine
			// itself is the one mistake this screen can make that takes a laptop off the network entirely.
			"transport_endpoints_unreachable": agentProfileUnreachable(endpoints),
			"postures": []map[string]any{
				{"value": installprofile.PostureFailClosed, "default": true},
				{"value": installprofile.PostureFailOpen, "needs_acknowledgement": true},
			},
			// ★ THE SCREEN HAS TO BE ABLE TO OFFER THIS, or the only way an organization that runs virtual
			// machines can keep them working is to stop steering altogether. See installprofile.VMEgressBlocked
			// for what was measured: a WSL2 distro on a steered Windows box egressing to the public internet
			// with no administrator anywhere in the story.
			"virtual_machine_egress": []map[string]any{
				{"value": installprofile.VMEgressBlocked, "default": true},
				{"value": installprofile.VMEgressAllowed, "needs_acknowledgement": true},
			},
		})
	}))

	// POST: issue one. The body carries only what an operator chose.
	//
	// node-local: this stores no configuration. Every value in the answer is read from what the control plane
	// already made authoritative here — the region catalogue, the group registry, the deployment's signing key —
	// and the only durable effect is the audit record, which travels to the authority like every other. Two
	// Edges asked on the same day therefore issue the same profile, and nothing here can diverge from the fleet
	// because nothing here is kept.
	mux.HandleFunc("POST /admin/agent-profile", adminEndpoint("admin.steering.write", func(w http.ResponseWriter, r *http.Request) {
		if config.AgentPolicySigner == nil {
			// ★ SAID PLAINLY. An unsigned profile is one every endpoint refuses, so answering with one would
			// hand an operator a file that cannot work and no reason why.
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf(
				"this deployment has no agent-policy signing key, so it cannot issue a profile a device would "+
					"accept — set -agent-policy-signing-key"))
			return
		}
		var req struct {
			Group              string   `json:"group,omitempty"`
			TransportEndpoints []string `json:"transport_endpoints,omitempty"`
			Posture            string   `json:"posture,omitempty"`
			AckFailOpen        bool     `json:"ack_fail_open,omitempty"`
			VMEgress           string   `json:"virtual_machine_egress,omitempty"`
			AckVMEgress        bool     `json:"ack_virtual_machine_egress,omitempty"`
			BypassApps         []string `json:"bypass_apps,omitempty"`
			BypassDests        []string `json:"bypass_dests,omitempty"`
			// Chosen from the catalogue this deployment publishes. The patterns are expanded HERE so the
			// screen never handles matching syntax — see agentProfileBypassPatterns.
			BypassCatalogIDs []string `json:"bypass_catalog_ids,omitempty"`
		}
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("decode agent profile request: %w", err))
				return
			}
		}

		// ★★ THE ORGANIZATION IS THE CALLER'S, NEVER A FIELD IN THE BODY. A profile names the organization its
		// devices enrol into; reading that from the request would let one customer's administrator mint
		// configuration that enrols devices into another's.
		tenant := profileTenantForRequest(r, evaluator)
		if tenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request carries no organization, so the "+
				"profile would name none and the devices taking it would enrol into nothing"))
			return
		}

		endpoints := req.TransportEndpoints
		if len(endpoints) == 0 {
			endpoints = agentProfileEndpoints(agentPlaneURL, tenant, regions)
		}
		if len(endpoints) == 0 {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf(
				"this deployment was not told the address its agents reach it on, so a profile issued here "+
					"would point devices at nothing — set -connector-enrollment-edge-url, or choose addresses"))
			return
		}
		// ★★★ AND AN ADDRESS NO DEVICE CAN REACH IS THE SAME CASE (reported from real hardware, 2026-08-26).
		// A deployment brought up on localhost generates "agents.localhost", which on a laptop is 127.0.0.1;
		// with the default posture — fail-closed, which is right — a device applying that profile dials
		// ITSELF, reaches no Edge, and stops carrying traffic. The whole machine loses the network. The lab
		// address is not the defect; offering it as a DEFAULT is, because an operator has no reason to doubt
		// an address the deployment produced.
		reachable, loopback := endpointsADeviceCanReach(endpoints)
		if len(reachable) == 0 {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf(
				"every address this deployment offers is one a device cannot reach (%s): on an endpoint those "+
					"resolve to the machine itself, so a device taking this profile would dial itself, reach no "+
					"Edge, and — being fail-closed — stop carrying traffic altogether. Give this deployment an "+
					"address its devices can reach (-connector-enrollment-edge-url / the region map), or choose "+
					"addresses here", strings.Join(loopback, ", ")))
			return
		}
		if len(loopback) > 0 {
			// Some are usable, so the profile is issued — with the unusable ones LEFT OUT rather than carried
			// as places a device will try and fail.
			endpoints = reachable
			logWarnf("agent_profile_issued dropping %d address(es) no device can reach: %s",
				len(loopback), strings.Join(loopback, ", "))
		}

		posture := strings.TrimSpace(req.Posture)
		if posture == "" {
			posture = installprofile.PostureFailClosed
		}
		// ★★★ FAIL-OPEN NEEDS THE ACKNOWLEDGEMENT, AND THE SERVER IS WHERE THAT IS ENFORCED. A screen can
		// present a checkbox; only this can make it mean something. A fleet running unmediated whenever it
		// cannot reach an Edge is a decision somebody has to make on purpose — the flag that carries it says
		// STABILIZATION ONLY — and it was measured on a real endpoint releasing a BLOCKED device to the open
		// internet.
		if posture == installprofile.PostureFailOpen && !req.AckFailOpen {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"a profile that lets devices carry traffic while no Edge can be reached has to be chosen "+
					"deliberately: those devices are neither recorded nor filtered for as long as it lasts. "+
					"Send ack_fail_open to confirm"))
			return
		}

		vmEgress := strings.TrimSpace(req.VMEgress)
		if vmEgress == "" {
			vmEgress = installprofile.VMEgressBlocked
		}
		// ★★★ AND LETTING VIRTUAL MACHINES OUT NEEDS THE SAME TWO KEYS, FOR A SHARPER REASON. Fail-open is a
		// state a fleet falls into when a deployment is unreachable; this one is permanent, and it needs no
		// administrator on the device to use. A WSL2 distro on a steered Windows box was measured egressing
		// straight to the internet with a public CA chain and the site's own address, while the agent went on
		// reporting that it was steering: nothing on that box says the traffic left unseen. Turning that on
		// deliberately is a decision an organization can make; arriving at it by leaving a field blank is not.
		if vmEgress == installprofile.VMEgressAllowed && !req.AckVMEgress {
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"a profile that lets virtual machines on the device reach the internet has to be chosen "+
					"deliberately: their traffic is not steered, not inspected and not recorded, and no "+
					"administrator on the device is needed to use one. Send ack_virtual_machine_egress to confirm"))
			return
		}

		dests, unknown := agentProfileBypassPatterns(config, req.BypassCatalogIDs, req.BypassDests)
		if len(unknown) > 0 {
			// ★ NAMED, NOT DROPPED. Silently ignoring an id the operator selected issues a profile that
			// inspects what they asked to leave alone, and nothing anywhere says so.
			writeError(w, http.StatusBadRequest, fmt.Errorf(
				"this deployment's catalogue has no entry called %s, so a profile issued now would inspect it "+
					"rather than leave it alone", strings.Join(unknown, ", ")))
			return
		}

		// ★★★ THE ORGANIZATION'S OWN DOOR NAME, WHICH NO PROFILE HAS EVER CARRIED (2026-08-28, found by walking
		// this lane onto a Mac). The Edge picks an organization's transport certificate by SNI — it has to, the
		// client certificate arrives after the server's — this control plane issues a per-organization name for
		// exactly that purpose, and the agents on both platforms read the block below. Nothing filled it, so
		// every device of every organization dialled the shared name and was served the deployment's own
		// certificate. The per-organization transport identity existed at all three layers and was joined at
		// none.
		//
		// ★★ ONLY WHEN THE CERTIFICATE ACTUALLY CARRIES IT. This name is used BEFORE the first trust bundle, so
		// it is not proved on the wire the way an announced name is — a name nothing serves turns every dial
		// into a verification failure, which this deployment has already paid for twice. So it is emitted only
		// for an organization whose transport authority is IN FORCE here; an organization without one is served
		// the deployment's shared certificate, which is what absent means and what it has always meant.
		organization := installprofile.OrganizationSpec{TenantID: tenant}
		if config.TenantTransportAuthority != nil {
			if serverName, inForceSince, _, _, known := config.TenantTransportAuthority.StateFor(tenant); known &&
				strings.TrimSpace(serverName) != "" && strings.TrimSpace(inForceSince) != "" {
				organization.TransportServerName = strings.TrimSpace(serverName)
				// ★★★ AND THE NAME THAT SELECTS THE ENROLMENT ROUTE (2026-08-29). On a folded transport port
				// the enrolment path is chosen BY the name in the ClientHello — organizationEnrolmentName,
				// "enrol." in front of the organization's own — and the profile stated the transport name and
				// not this one. A device with nothing yet therefore dialled the transport listener for its
				// first request, which is not the listener that issues identities.
				//
				// Derived from the same server name the certificate carries, by the same function the Edge
				// selects with, so the two cannot drift into a name that is offered and not served.
				organization.EnrolmentServerName = organizationEnrolmentName(organization.TransportServerName)
				// The CP owns the certificate names but does not run the Edge's recovery
				// listener. Its signed profile must use the same name as the CA's
				// leaf template, without consulting process-local Edge readiness.
				organization.RenewalRecoveryServerName = organizationRecoveryName(organization.TransportServerName)
			}
		}
		issued := time.Now().UTC().Truncate(time.Second)
		// ★★★ AND IT IS REFUSED IF THIS NODE CANNOT COMPLETE IT (2026-08-31, measured after leadership moved
		// between regions). See a_profile_missing_the_organizations_authorities.go: a profile that omits the
		// organization's own authorities is signed, valid, and installs a device that cannot work.
		facts := deploymentFactsFor(config, tenant)
		if missing := organizationAuthoritiesUnavailable(config, tenant, facts); missing != "" {
			writeError(w, http.StatusConflict, refuseTheProfileThisNodeCannotComplete(tenant, missing))
			return
		}

		profile := installprofile.Build(installprofile.Options{
			Organization: organization,
			Tenant:       tenant,
			Group:        strings.TrimSpace(req.Group),
			// ★★ THE PLAIN URL, NOT THE "region=URL" FORM (measured 2026-08-25, the first profile this route
			// ever issued). transport_url is the single address every agent built before this change dials;
			// handing it "region-a=https://…" makes it dial a string that is not a URL, and the device fails
			// to reach a deployment that is answering. The region-tagged list is transport_endpoints, which is
			// the field that was ADDED to carry it.
			TransportURL:       agentProfilePrimaryURL(endpoints),
			TransportEndpoints: endpoints,
			// The same list, as the rank the agents read. See agentProfileRegionPriority.
			RegionPriority: agentProfileRegionPriority(endpoints),
			EnrollMode:     "token",
			Posture:        posture,
			AckFailOpen:    req.AckFailOpen,
			VMEgress:       vmEgress,
			AckVMEgress:    req.AckVMEgress,
			Backend:        installprofile.BackendWFP,
			BypassApps:     strings.Join(req.BypassApps, ","),
			BypassDests:    strings.Join(dests, ","),
			DNSListen:      "127.0.0.1:53",
			BlockQUIC:      true,
			CaptiveTimeout: 180,
			// ★★★ AND EVERYTHING ELSE THE DEVICE MUST BE TOLD, so that this file and a one-time token are the
			// whole of what a customer receives — see deploymentFactsFor.
			Deployment: facts,
		}, issued)

		env, err := config.AgentPolicySigner.Sign(profile, issued)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("sign the profile: %w", err))
			return
		}

		// The identity may be absent on a machine credential; the record then says so rather than pretending.
		identity, _ := adminIdentityFromRequest(r)
		if err := appendAdminAudit(r.Context(), writer, adminAuditOutbox,
			agentProfileIssuedAuditLog(identity, tenant, profile,
				config.AgentPolicySigner.KeyID(), evaluator, sourceIPFromRequest(r)), time.Now()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Content-Disposition so a browser SAVES it rather than rendering it: what an operator needs is the
		// file, on the machine they will install from.
		//
		// ★★★ AND UNDER THE NAME THE INSTALLER LOOKS FOR (2026-08-30). This said dsse-agent-profile.json; the
		// package takes the device's configuration from the folder it was opened from and looks there for
		// install_profile.json. So the documented lane — download the three things, put them beside the
		// installer, open it — did not work, and the installer's refusal named a file this deployment had
		// never produced. The bytes were always right; the label on them was the whole failure.
		w.Header().Set("Content-Disposition", `attachment; filename="install_profile.json"`)
		writeJSON(w, http.StatusOK, env)
	}))
}

// profileTenantForRequest resolves the organization a profile is issued for: the caller's, always.
func profileTenantForRequest(r *http.Request, evaluator decision.Evaluator) string {
	if t := strings.TrimSpace(adminTenantIDFromRequest(r)); t != "" {
		return t
	}
	return strings.TrimSpace(evaluator.PolicyBundle.TenantID)
}

// agentProfileEndpoints is the deployment's own starting addresses, as "region=URL".
//
// ★ THE DEPLOYMENT'S REGION LIST IS THE SOURCE, and the agent-plane address is the fallback when there is no
// list — which is the single-region case, where one address is the whole truth.
// ★★★ THE ORGANIZATION IS NAMED, AND UNTIL 2026-08-29 IT WAS NOT (found by issuing a profile for an
// organization whose home region is tokyo and reading it: transport_url pointed at osaka).
//
// regionEndpointCatalog.allowedRegionEndpoints already does the right thing — it emits ONLY the regions an
// organization may occupy and puts its home region first — and this route called it with (nil, ""). Two
// consequences, and the second is the serious one:
//
//   - every device's FIRST contact went to whichever region sorted first, which is the one moment the home
//     region is the only thing there is to go on: no Edge has answered yet, so no signed region list governs.
//   - an organization pinned to ONE region was offered the other. Residency is declared on the tenant row,
//     shown on the screen, and the artefact its devices actually take ignored it.
func agentProfileEndpoints(agentPlaneURL, tenantID string, regions func(tenantID string) []regionEndpoint) []string {
	out := []string{}
	if regions != nil {
		for _, e := range regions(tenantID) {
			region, endpoint := strings.TrimSpace(e.Region), strings.TrimSpace(e.Endpoint)
			if region == "" || endpoint == "" {
				continue
			}
			// "region=URL" is the shape the agent's bootstrap seed already takes, so the profile carries it
			// unchanged and nothing has to re-derive it on the device.
			out = append(out, region+"="+endpoint)
		}
	}
	if len(out) == 0 {
		if u := strings.TrimSpace(agentPlaneURL); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// agentProfileRegionPriority turns the ORDER of the offered regions into the rank the agents actually read.
//
// ★★★ THE PREFERENCE WAS EXPRESSED AS AN ORDER AND READ AS A FIELD, AND THE FIELD WAS NEVER FILLED
// (2026-08-30, the operator asked whether region priority is verified to work — it was not, and could not be).
// allowedRegionEndpoints already puts an organization's home region first, so the operator's preference is in
// transport_endpoints as an ordering. Both agents discard that order: they rank by RegionPriority, where 0
// means UNSPECIFIED and sorts LAST, so an empty map ties every region and nearest-RTT decides everything. The
// profile type can carry the rank, both agents honour it, regionfailover applies it — and the one route that
// issues profiles never set it. Nothing in the product could: no field in the request, no control on any
// screen. The only writer in this repository is a Windows packaging tool no customer runs.
//
// Measured on the lab the same day: an organization whose home is fukuoka had its device steering through
// nagoya, and an organization whose home is nagoya had its Mac on fukuoka. Residency was still enforced —
// that comes from the ALLOWED list, which this cannot add to — but the operator's stated preference did
// nothing at all.
//
// ★ DERIVED, NOT ASKED FOR, the same call this deployment already makes for region failover and the Console
// origins: the operator declares the order once, where they declare the regions. A second place to say the
// same thing is how the two come to disagree.
//
// Ranks start at 1 because 0 is the wire's "unspecified" and would sanitize back to the silence being fixed.
func agentProfileRegionPriority(endpoints []string) map[string]int {
	out := map[string]int{}
	for _, e := range endpoints {
		region, _, ok := strings.Cut(strings.TrimSpace(e), "=")
		region = strings.TrimSpace(region)
		// An entry with no region tag is the single-region fallback address, which expresses no preference.
		if !ok || region == "" {
			continue
		}
		if _, already := out[region]; already {
			continue
		}
		out[region] = len(out) + 1
	}
	// One region is not a preference, and saying it is would put a rank on the wire that can never reorder
	// anything — a value an operator would later have to reason about for no reason.
	if len(out) < 2 {
		return nil
	}
	return out
}

// agentProfilePrimaryURL is the first address with its region tag removed: what an agent that knows nothing
// about regions dials.
func agentProfilePrimaryURL(endpoints []string) string {
	if len(endpoints) == 0 {
		return ""
	}
	first := strings.TrimSpace(endpoints[0])
	if i := strings.Index(first, "="); i > 0 {
		return strings.TrimSpace(first[i+1:])
	}
	return first
}

func agentProfileEndpointNote(endpoints []string) string {
	switch len(endpoints) {
	case 0:
		return "this deployment has not been told the address its agents reach it on"
	case 1:
		return "this deployment publishes one region, so a device that cannot reach it has nowhere else to " +
			"start — it keeps whatever it last applied and cannot enrol for the first time"
	default:
		return "a device tries these in order until one answers; once an Edge does, its signed region list governs"
	}
}

// agentProfileIssuedAuditLog records that somebody issued configuration for a fleet.
//
// ★ IT IS A CONFIGURATION CHANGE, not a download. It decides what every device taking it steers and whether it
// carries traffic with no Edge at all, so it is recorded the way a rule change is.
//
// ★★ AND IT NAMES WHO. This deployment has repeatedly found records that describe an act and name nobody, which
// answer the only question anybody asks of them with a blank. The acting administrator and where they acted
// from are the record — which is why this emitter sits in the DEFERRED list of the non-secret invariant rather
// than being redacted into uselessness, alongside break-glass use and admin downloads.
func agentProfileIssuedAuditLog(identity adminIdentity, tenantID string, profile installprofile.InstallProfile,
	keyID string, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "agent_profile_issued"
	result := "success"
	reason := "An install profile was issued for this organization."
	targetType := "device_group"
	target := strings.TrimSpace(profile.GroupID)
	if target == "" {
		target = "(every group)"
	}
	return model.AuditLog{
		ID:             randomEdgeID("audit_", time.Now().UTC()),
		TenantID:       tenantID,
		ActorUserID:    stringPtr(identity.PrincipalID),
		EventType:      "agent_profile_issued",
		TargetType:     &targetType,
		TargetID:       &target,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		SourceIP:       &sourceIP,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"posture":                profile.Posture,
			"virtual_machine_egress": profile.VMEgress,
			"fail_open":              profile.FailOpenEnabled(),
			"transport_endpoints":    profile.TransportEndpoints,
			"signing_key_id":         keyID,
			"issued_at":              profile.IssuedAt,
		},
	}
}

// agentProfileGroups is the device groups a profile may be issued for, in the caller's organization only.
func agentProfileGroups(config serverConfig, tenant string) []map[string]any {
	out := []map[string]any{}
	if config.EnrolledLedger == nil {
		return out
	}
	for _, g := range config.EnrolledLedger.ListGroups() {
		if !deviceGroupVisibleToTenant(g.TenantID, tenant) {
			continue
		}
		out = append(out, map[string]any{"name": g.Name, "description": g.Description})
	}
	return out
}

// agentProfileBypassCatalog is what this deployment already knows not to inspect, offered by name.
func agentProfileBypassCatalog(config serverConfig) []map[string]any {
	cat := knownbypass.Catalog()
	if config.CatalogFeed != nil {
		cat = config.CatalogFeed.EffectiveCatalog()
	}
	out := make([]map[string]any, 0, len(cat.Entries))
	for _, e := range cat.Entries {
		out = append(out, map[string]any{
			"id": e.ID, "name": e.Name, "vendor": e.Vendor, "category": e.Category,
			// ★ THE RISK OF NOT LOOKING IS THE DECISION BEING MADE HERE, so it travels with the choice
			// rather than being something an operator has to go and look up.
			"risk": e.Risk, "description": e.Description,
		})
	}
	return out
}

// agentProfileBypassPatterns turns catalogue choices into the destinations a device matches on, and returns
// the ids this deployment does not know — never silently dropping one.
func agentProfileBypassPatterns(config serverConfig, ids, extra []string) (dests []string, unknown []string) {
	cat := knownbypass.Catalog()
	if config.CatalogFeed != nil {
		cat = config.CatalogFeed.EffectiveCatalog()
	}
	byID := map[string]knownbypass.Group{}
	for _, e := range cat.Entries {
		byID[strings.TrimSpace(e.ID)] = e
	}
	seen := map[string]bool{}
	add := func(p string) {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			dests = append(dests, p)
		}
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		e, ok := byID[id]
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		for _, p := range e.Patterns {
			add(p)
		}
	}
	for _, p := range extra {
		add(p)
	}
	return dests, unknown
}

// agentProfileUnreachable is the offered addresses no device could dial, for the screen to mark.
func agentProfileUnreachable(endpoints []string) []string {
	_, loopback := endpointsADeviceCanReach(endpoints)
	if loopback == nil {
		return []string{}
	}
	return loopback
}

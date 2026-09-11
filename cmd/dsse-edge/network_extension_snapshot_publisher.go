package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/steering"

	"github.com/lantern-networks/dsse-core/durablefile"
)

const (
	networkExtensionSnapshotAgentConfigRef             = "agent_config.json"
	networkExtensionSnapshotRulesRef                   = "network_extension_steering_rules.json"
	networkExtensionSnapshotRuntimeEvidenceRef         = "network_extension_runtime_evidence.json"
	networkExtensionSnapshotRuntimeCopyEvidenceRef     = "network_extension_runtime_copy_evidence.json"
	networkExtensionSnapshotRuntimeDiagnosticRef       = "network_extension_runtime_diagnostic.json"
	networkExtensionSnapshotLabRawAuthorityRef         = "network_extension_lab_raw_authority_diagnostic.json"
	networkExtensionSnapshotDefaultEndpointPath        = "/network-extension/runtime-copy/round-trip"
	networkExtensionSnapshotDefaultSessionEndpointPath = "/network-extension/runtime-copy/session"
	networkExtensionSnapshotDefaultDNSOverTunnelPath   = "/steer/dns-query"
	networkExtensionSnapshotDefaultTransportScope      = "real_edge"
	networkExtensionSnapshotDefaultConnectorRealness   = "over_the_wire_local"
	networkExtensionSnapshotSourceProtectedAppMap      = "admin_console_policy_snapshot"
	networkExtensionSnapshotPolicyListLimit            = 10000
	networkExtensionSnapshotRuntimeEvidenceSchema      = "network_extension_runtime_evidence.v1"
	networkExtensionSnapshotRuntimeCopyEvidenceSchema  = "network_extension_runtime_copy_evidence.v1"
	networkExtensionSnapshotRuntimeDiagnosticSchema    = "phase2_provider_runtime_diagnostic.v1"
	networkExtensionSnapshotRawAuthoritySchema         = "phase2_lab_raw_authority_diagnostic.v1"
)

type networkExtensionSnapshotPublisher interface {
	PublishAdminPolicySnapshot(context.Context, string, policy.RuntimeStore, model.PolicyBundle, time.Time) error
}

type localNetworkExtensionSnapshotPublisherConfig struct {
	OutputDir                                                   string
	EdgeURL                                                     string
	RuntimeCopyEndpointPath                                     string
	RuntimeCopySessionEndpointPath                              string
	RuntimeCopyTransportScope                                   string
	EdgeConnectorRealness                                       string
	PassthroughResolvedIPs                                      []string
	RuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers []string
	RuntimeCopyDownstreamPassthroughDefaultTunnelEnabled        bool
	PassthroughDomains                                          []string
	DefaultPassthroughDomainsEnabled                            *bool
	SelfExclusionSourceAppSigningIdentifiers                    []string
	InterceptOnlyDomains                                        []string
	// W4 (T) transport contract for the NE: how to dial the Edge over the encrypted tunnel.
	TransportTLSURL            string // e.g. https://203.0.113.10:18543 (empty = transport block omitted)
	TransportPinnedCARef       string // ref/filename of the pinned (T) transport CA PEM the NE pins
	RenewalRecoveryEndpoint    string // host:port of the renewal RECOVERY listener, for devices whose cert expired while off
	TransportMTLSRequired      bool   // NE must present a device client cert (mTLS)
	TransportDNSOverTunnelPath string // path for DNS-over-tunnel (default /steer/dns-query)
}

type localNetworkExtensionSnapshotPublisher struct {
	outputDir                                                   string
	edgeURL                                                     string
	runtimeCopyEndpointPath                                     string
	runtimeCopySessionEndpointPath                              string
	runtimeCopyTransportScope                                   string
	edgeConnectorRealness                                       string
	passthroughResolvedIPs                                      []string
	runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers []string
	runtimeCopyDownstreamPassthroughDefaultTunnelEnabled        bool
	passthroughDomains                                          []string
	defaultPassthroughDomainsEnabled                            bool
	selfExclusionSourceAppSigningIdentifiers                    []string
	interceptOnlyDomains                                        []string
	transportTLSURL                                             string
	transportPinnedCARef                                        string
	// Published so a device learns where to renew when its certificate has ALREADY expired. Fleet-wide, not
	// per-device, which is exactly what this snapshot can carry.
	renewalRecoveryEndpoint    string
	transportMTLSRequired      bool
	transportDNSOverTunnelPath string
	// trustedCABundle answers, for one organization, the certificate authorities its agents must trust — the
	// interception root chief among them. It is a FUNCTION rather than a value because this publisher is
	// constructed before the interception engine exists, and a value captured at that moment would be the
	// empty string forever.
	//
	// ★ THE AGENT'S TRUSTED AUTHORITIES BELONG IN THE CONFIGURATION IT IS INSTALLED WITH (2026-08-16). Until
	// now the config named where to send traffic and which transport CA to pin, and said nothing about the
	// interception root — so that root reached a machine through a separate manual step, and drifted from what
	// the Edge actually signs under. Carrying it here makes an agent's trust a property of the artifact it was
	// installed from, and makes the two impossible to distribute out of step, because they are one file.
	trustedCABundle func(tenantID string) map[string]any
	// updateSigningKeys are the public keys a device accepts on an update manifest.
	//
	// ★ THE PUBLISHED CONFIGURATION WAS ONE THE INSTALLER REFUSES (2026-08-16). The macOS preinstall requires
	// update_signing_keys — without them a Mac installs a security agent it can never patch, and the check
	// exists because the fleet was carrying exactly that. This publisher never emitted the field, so the
	// artifact the product publishes could not be used for an install at all: every attempt would stop at that
	// refusal, and the reason would look like a broken installer rather than a configuration missing one key.
	updateSigningKeys []string
	// updatePublisher is the signing identity a device requires of any package it installs — an Apple Team ID
	// on macOS, its counterpart on Windows.
	//
	// ★★★ AND THE FIX ABOVE HELD FOR ONE FIELD (2026-08-27). The gate that refuses a configuration without
	// update_signing_keys grew a second requirement, and nothing told this publisher, so the artifact the
	// product publishes was refused at the NEXT line instead of the first:
	//
	//	REFUSING TO INSTALL: the agent configuration names no update_publisher_team_id. Without it this Mac
	//	installs whatever a signed manifest points at, as root, without checking who built it.
	//
	// The two halves of this product are built and tested apart, and what connects them is the field list. It
	// is asserted now rather than rediscovered on a device.
	updatePublisher string
}

// SetUpdatePublisher records the signing identity a device requires of a package before installing it.
func (publisher *localNetworkExtensionSnapshotPublisher) SetUpdatePublisher(identity string) {
	if publisher == nil {
		return
	}
	publisher.updatePublisher = strings.TrimSpace(identity)
}

// SetUpdateSigningKeys records the keys a device accepts on an update manifest, so the published configuration
// is one an installer will accept rather than one it refuses at the last check.
func (publisher *localNetworkExtensionSnapshotPublisher) SetUpdateSigningKeys(keys []string) {
	if publisher == nil {
		return
	}
	publisher.updateSigningKeys = append([]string(nil), keys...)
}

// SetTrustedCABundleSource wires the per-organization authorities in after the interception engine exists.
func (publisher *localNetworkExtensionSnapshotPublisher) SetTrustedCABundleSource(source func(tenantID string) map[string]any) {
	if publisher == nil {
		return
	}
	publisher.trustedCABundle = source
}

func newLocalNetworkExtensionSnapshotPublisher(config localNetworkExtensionSnapshotPublisherConfig) (*localNetworkExtensionSnapshotPublisher, error) {
	outputDir := strings.TrimSpace(config.OutputDir)
	if outputDir == "" {
		return nil, nil
	}
	edgeURL := strings.TrimSpace(config.EdgeURL)
	if edgeURL == "" {
		return nil, fmt.Errorf("network extension snapshot publisher requires edge URL")
	}
	endpointPath := strings.TrimSpace(config.RuntimeCopyEndpointPath)
	if endpointPath == "" {
		endpointPath = networkExtensionSnapshotDefaultEndpointPath
	}
	sessionEndpointPath := strings.TrimSpace(config.RuntimeCopySessionEndpointPath)
	if sessionEndpointPath == "" {
		sessionEndpointPath = networkExtensionSnapshotDefaultSessionEndpointPath
	}
	transportScope := strings.TrimSpace(config.RuntimeCopyTransportScope)
	if transportScope == "" {
		transportScope = networkExtensionSnapshotDefaultTransportScope
	}
	edgeConnectorRealness := strings.TrimSpace(config.EdgeConnectorRealness)
	if edgeConnectorRealness == "" {
		edgeConnectorRealness = networkExtensionSnapshotDefaultConnectorRealness
	}
	defaultPassthroughDomainsEnabled := true
	if config.DefaultPassthroughDomainsEnabled != nil {
		defaultPassthroughDomainsEnabled = *config.DefaultPassthroughDomainsEnabled
	}
	publisher := &localNetworkExtensionSnapshotPublisher{
		outputDir:                      outputDir,
		edgeURL:                        edgeURL,
		runtimeCopyEndpointPath:        endpointPath,
		runtimeCopySessionEndpointPath: sessionEndpointPath,
		runtimeCopyTransportScope:      transportScope,
		edgeConnectorRealness:          edgeConnectorRealness,
		passthroughResolvedIPs:         normalizedNetworkExtensionSnapshotIPs(config.PassthroughResolvedIPs),
		runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers: normalizedNetworkExtensionSnapshotSigningIdentifiers(config.RuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers),
		selfExclusionSourceAppSigningIdentifiers:                    normalizedNetworkExtensionSnapshotSigningIdentifiers(config.SelfExclusionSourceAppSigningIdentifiers),
		interceptOnlyDomains:                                        normalizedNetworkExtensionSnapshotDomains(config.InterceptOnlyDomains),
		runtimeCopyDownstreamPassthroughDefaultTunnelEnabled:        config.RuntimeCopyDownstreamPassthroughDefaultTunnelEnabled,
		passthroughDomains:                                          normalizedNetworkExtensionSnapshotDomains(config.PassthroughDomains),
		defaultPassthroughDomainsEnabled:                            defaultPassthroughDomainsEnabled,
		transportTLSURL:                                             strings.TrimSpace(config.TransportTLSURL),
		transportPinnedCARef:                                        strings.TrimSpace(config.TransportPinnedCARef),
		renewalRecoveryEndpoint:                                     strings.TrimSpace(config.RenewalRecoveryEndpoint),
		transportMTLSRequired:                                       config.TransportMTLSRequired,
		transportDNSOverTunnelPath:                                  strings.TrimSpace(config.TransportDNSOverTunnelPath),
	}
	if err := publisher.validate(); err != nil {
		return nil, err
	}
	return publisher, nil
}

func (publisher *localNetworkExtensionSnapshotPublisher) validate() error {
	if publisher == nil {
		return nil
	}
	edgeURL, err := url.Parse(publisher.edgeURL)
	if err != nil {
		return fmt.Errorf("parse network extension edge URL: %w", err)
	}
	if edgeURL.Scheme != "http" && edgeURL.Scheme != "https" {
		return fmt.Errorf("network extension edge URL must use http or https")
	}
	if strings.TrimSpace(edgeURL.Hostname()) == "" || strings.TrimSpace(edgeURL.Port()) == "" {
		return fmt.Errorf("network extension edge URL must include host and explicit port")
	}
	if edgeURL.User != nil || edgeURL.RawQuery != "" || edgeURL.Fragment != "" {
		return fmt.Errorf("network extension edge URL must not include credentials, query, or fragment")
	}
	if edgeURL.EscapedPath() != "" && edgeURL.EscapedPath() != "/" {
		return fmt.Errorf("network extension edge URL must not include a path")
	}
	if !strings.HasPrefix(publisher.runtimeCopyEndpointPath, "/") {
		return fmt.Errorf("network extension runtime-copy endpoint path must start with slash")
	}
	if !strings.HasPrefix(publisher.runtimeCopySessionEndpointPath, "/") {
		return fmt.Errorf("network extension runtime-copy session endpoint path must start with slash")
	}
	switch publisher.runtimeCopyTransportScope {
	case "lab_endpoint", "real_edge":
	default:
		return fmt.Errorf("network extension runtime-copy transport scope must be lab_endpoint or real_edge")
	}
	switch publisher.edgeConnectorRealness {
	case "in_process_stub", "over_the_wire_local", "over_the_wire_device":
	default:
		return fmt.Errorf("network extension edge connector realness is invalid")
	}
	if publisher.runtimeCopyTransportScope == "real_edge" || strings.HasPrefix(publisher.edgeConnectorRealness, "over_the_wire") {
		if networkExtensionSnapshotHostIsLoopback(edgeURL.Hostname()) {
			return fmt.Errorf("network extension real-edge data-plane URL must be non-loopback")
		}
	}
	for _, value := range publisher.passthroughResolvedIPs {
		ip := net.ParseIP(strings.Trim(value, "[]"))
		if ip == nil {
			return fmt.Errorf("network extension passthrough resolved IP must be an IP literal")
		}
		if ip.IsLoopback() && (publisher.runtimeCopyTransportScope == "real_edge" || strings.HasPrefix(publisher.edgeConnectorRealness, "over_the_wire")) {
			return fmt.Errorf("network extension real-edge passthrough resolved IP must be non-loopback")
		}
	}
	for _, value := range publisher.runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers {
		if !networkExtensionSnapshotSigningIdentifierIsValid(value) {
			return fmt.Errorf("network extension runtime-copy downstream source app signing identifier is invalid")
		}
	}
	if publisher.runtimeCopyDownstreamPassthroughDefaultTunnelEnabled &&
		len(publisher.runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers) == 0 {
		return fmt.Errorf("network extension runtime-copy downstream default-tunnel passthrough requires source app signing identifiers")
	}
	return nil
}

func (publisher *localNetworkExtensionSnapshotPublisher) PublishAdminPolicySnapshot(ctx context.Context, tenantID string, store policy.RuntimeStore, bundle model.PolicyBundle, now time.Time) error {
	if publisher == nil {
		return nil
	}
	if store == nil {
		return fmt.Errorf("network extension snapshot publisher requires policy store")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(bundle.TenantID)
	}
	if tenantID == "" {
		return fmt.Errorf("network extension snapshot tenant_id is required")
	}
	list, err := store.List(ctx, tenantID, policy.ListOptions{
		Status: "active",
		Limit:  networkExtensionSnapshotPolicyListLimit,
	})
	if err != nil {
		return fmt.Errorf("list active policies for network extension snapshot: %w", err)
	}
	rules, err := networkExtensionRulesFromAdminPolicies(tenantID, list.Policies, bundle, now)
	if err == nil {
		err = steering.ValidateNetworkExtensionRules(rules)
	}
	if err != nil {
		// ★ THE CONFIGURATION IS NOT THE RULES, AND WAS WITHHELD WITH THEM (2026-08-16). One missing input —
		// this organization having no policy of the shape the RULES file is built from — used to abandon the
		// whole publish, including agent_config.json. That file carries where the Edge is, how the tunnel is
		// dialled, which keys may update the agent and, since today, WHICH CERTIFICATE AUTHORITIES THE DEVICE
		// TRUSTS. None of that depends on a policy existing. Measured on the reference lab the moment the
		// publisher was switched on: no eligible policies, so nothing at all was written, and a device
		// installed from that directory would have carried no trusted authorities for a reason that has
		// nothing to do with trust.
		//
		// So the configuration is published anyway and the RULES FILE IS LEFT ALONE. Not written empty: a
		// device reads that file to decide what it steers, and handing it an empty set because the rules could
		// not be built is the silent disarm this tree keeps finding. Whatever was there stays there, and the
		// error is returned so the caller still says out loud that the rules were not refreshed.
		if cerr := publisher.publishAgentConfigOnly(tenantID); cerr != nil {
			return fmt.Errorf("%w (and the agent configuration could not be written either: %v)", err, cerr)
		}
		return fmt.Errorf("%w — the agent configuration WAS published; the steering rules were left as they were", err)
	}
	agentConfig := publisher.agentConfig(tenantID)
	if err := os.MkdirAll(publisher.outputDir, 0o750); err != nil {
		return fmt.Errorf("create network extension snapshot dir: %w", err)
	}
	files := map[string]any{
		networkExtensionSnapshotAgentConfigRef:         agentConfig,
		networkExtensionSnapshotRulesRef:               rules,
		networkExtensionSnapshotRuntimeEvidenceRef:     networkExtensionRuntimeEvidencePlaceholder(now),
		networkExtensionSnapshotRuntimeCopyEvidenceRef: networkExtensionRuntimeCopyEvidencePlaceholder(now),
		networkExtensionSnapshotRuntimeDiagnosticRef:   networkExtensionRuntimeDiagnosticPlaceholder(now),
		networkExtensionSnapshotLabRawAuthorityRef:     networkExtensionRawAuthorityDiagnosticPlaceholder(now),
	}
	for name, value := range files {
		if err := writeNetworkExtensionSnapshotJSONAtomic(filepath.Join(publisher.outputDir, name), value); err != nil {
			return err
		}
	}
	return nil
}

func (publisher *localNetworkExtensionSnapshotPublisher) agentConfig(tenantID string) map[string]any {
	config := map[string]any{
		"schema_version":                                              "dsse_agent_config.v1",
		"edge_url":                                                    publisher.edgeURL,
		"network_extension_rules_ref":                                 networkExtensionSnapshotRulesRef,
		"network_extension_runtime_evidence_ref":                      networkExtensionSnapshotRuntimeEvidenceRef,
		"network_extension_runtime_copy_endpoint_path":                publisher.runtimeCopyEndpointPath,
		"network_extension_runtime_copy_session_endpoint_path":        publisher.runtimeCopySessionEndpointPath,
		"network_extension_runtime_copy_transport_scope":              publisher.runtimeCopyTransportScope,
		"network_extension_runtime_copy_edge_connector_realness":      publisher.edgeConnectorRealness,
		"network_extension_runtime_copy_evidence_ref":                 networkExtensionSnapshotRuntimeCopyEvidenceRef,
		"network_extension_runtime_diagnostic_ref":                    networkExtensionSnapshotRuntimeDiagnosticRef,
		"network_extension_lab_raw_authority_diagnostic_ref":          networkExtensionSnapshotLabRawAuthorityRef,
		"network_extension_default_passthrough_domains_enabled":       publisher.defaultPassthroughDomainsEnabled,
		"network_extension_runtime_config_publication_source":         "admin_console_policy_snapshot",
		"network_extension_runtime_config_requires_network_extension": true,
		"metadata": map[string]any{
			"source":                             "admin_console_policy_snapshot_publisher",
			"operator_config_endpoint_secret":    false,
			"captured_secret_material_committed": false,
		},
	}
	// ★★★ WHICH ORGANIZATION THIS DEVICE BELONGS TO, STATED AT INSTALL TIME (2026-08-22, the operator's call).
	//
	// A device that holds nothing cannot learn its organization from the trust bundle: the bundle arrives AFTER
	// enrolment, and enrolment is the thing that needs the name. Measured on the folded transport port — the
	// enrolment path is selected by SNI, and ONLY enrol.<organization> opens it:
	//
	//	SNI=enrol.lab.dsse.invalid        /enroll  405 (the route is there)  /bootstrap/trust-bundle  200
	//	SNI=lab.dsse.invalid              /enroll  000
	//	SNI=<the deployment's own name>   /enroll  000
	//	no SNI at all                     the SHARED certificate, and no selector — Go sends no SNI for an
	//	                                  IP literal at all (crypto/tls hostnameInSNI), which is why edge_url
	//	                                  must never be an address
	//
	// So the installer is the only thing that can know, and it now says so instead of leaving an agent to
	// infer it. That is also why the field is here rather than in the bundle: everything in the bundle is
	// downstream of the enrolment this name exists to reach.
	//
	// ★ IT IS NOT A SECRET, and nothing here authorises anything. The organization id is issued and
	// unguessable (organization_id_is_not_a_name.go); the enrolment TOKEN is what admits a device and it is
	// deliberately not in this file.
	//
	// ★ AND THE NAME IS ONLY OFFERED WHEN A CERTIFICATE CARRIES IT — the rule the enrolment fold has already paid for twice
	// (2026-08-19 for the recovery name, 2026-08-21 for the enrolment one). An agent that dials a name no
	// certificate names fails verification, and the failure looks like the Edge being down on the one path a
	// device with nothing has.
	if org := agentConfigOrganization(tenantID); len(org) > 0 {
		config["organization"] = org
	}
	// The organization's own trusted authorities, travelling in the same file as everything else the agent is
	// installed with. Omitted entirely when this deployment has nothing to say, so a config that never carried
	// the field behaves exactly as before rather than growing an empty one somebody would embed.
	if len(publisher.updateSigningKeys) > 0 {
		config["update_signing_keys"] = publisher.updateSigningKeys
	}
	if publisher.updatePublisher != "" {
		// ★ WHO BUILT IT, not only who signed the manifest. A signed manifest says a trusted party CHOSE this
		// package; this says the package itself is theirs. Without it a device installs, as root, whatever a
		// manifest points at — and the Developer ID signature those packages already carry goes unused.
		config["update_publisher_team_id"] = publisher.updatePublisher
	}
	if publisher.trustedCABundle != nil {
		if bundle := publisher.trustedCABundle(tenantID); len(bundle) > 0 {
			config["trusted_ca_bundle"] = bundle
		}
	}
	// W4 (T) transport contract: tells the NE to dial the Edge over the encrypted tunnel (TLS),
	// pin the transport CA, optionally present a device client cert (mTLS), and send DNS over the tunnel.
	// Emitted only when a transport TLS URL is configured (additive; absent = legacy plaintext dial).
	if publisher.transportTLSURL != "" {
		dnsPath := publisher.transportDNSOverTunnelPath
		if dnsPath == "" {
			dnsPath = networkExtensionSnapshotDefaultDNSOverTunnelPath
		}
		transport := map[string]any{
			"transport_tls_url":         publisher.transportTLSURL,
			"mtls_required":             publisher.transportMTLSRequired,
			"dns_over_tunnel_path":      dnsPath,
			"dns_over_tunnel_supported": true,
		}
		if publisher.transportPinnedCARef != "" {
			transport["pinned_ca_ref"] = publisher.transportPinnedCARef
		}
		// Where to renew once the certificate has expired. Without it a device switched off across its own
		// expiry cannot get back on its own — and that only becomes visible when somebody returns from leave.
		if publisher.renewalRecoveryEndpoint != "" {
			transport["renewal_recovery_endpoint"] = publisher.renewalRecoveryEndpoint
		}
		config["network_extension_transport"] = transport
	}
	if len(publisher.passthroughResolvedIPs) > 0 {
		config["network_extension_runtime_copy_passthrough_resolved_ips"] = publisher.passthroughResolvedIPs
	}
	if len(publisher.runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers) > 0 {
		config["network_extension_runtime_copy_downstream_passthrough_source_app_signing_identifiers"] = publisher.runtimeCopyDownstreamPassthroughSourceAppSigningIdentifiers
	}
	if publisher.runtimeCopyDownstreamPassthroughDefaultTunnelEnabled {
		config["network_extension_runtime_copy_downstream_passthrough_default_tunnel_enabled"] = true
	}
	if len(publisher.passthroughDomains) > 0 {
		config["network_extension_passthrough_domains"] = publisher.passthroughDomains
	}
	if len(publisher.selfExclusionSourceAppSigningIdentifiers) > 0 {
		config["network_extension_self_exclusion_source_app_signing_identifiers"] = publisher.selfExclusionSourceAppSigningIdentifiers
	}
	// The intercept allowlist (added, then removed by mistake, then restored). The network extension takes
	// over only the hosts to be intercepted and lets everything else pass straight through, without going
	// through the NE-to-Edge relay. That is what stops a SaaS sub-resource being cut off by the half-duplex
	// relay and rendering blank or broken. Development scaffolding: steering ALL traffic is for after the
	// full-duplex tunnel is working on a real device.
	if len(publisher.interceptOnlyDomains) > 0 {
		config["network_extension_intercept_only_domains"] = publisher.interceptOnlyDomains
	}
	// Enables the full-duplex runtime-copy tunnel. Without it the network extension falls back to the old
	// half-duplex session path, and real sites heavy in images or streaming break.
	config["network_extension_runtime_copy_tunnel_enabled"] = true
	return config
}

func networkExtensionRulesFromAdminPolicies(tenantID string, policies []model.Policy, bundle model.PolicyBundle, now time.Time) (steering.NetworkExtensionRules, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy.SortPolicies(policies)
	policyIDs := []string{}
	for _, policy := range policies {
		if !adminPolicyEligibleForNetworkExtensionSnapshot(policy) {
			continue
		}
		policyIDs = append(policyIDs, policy.ID)
	}
	if len(policyIDs) == 0 {
		return steering.NetworkExtensionRules{}, fmt.Errorf("network extension snapshot has no active allow/network_extension policies")
	}
	return steering.NetworkExtensionRules{
		SchemaVersion:         steering.NetworkExtensionRulesSchemaVersion,
		TenantID:              tenantID,
		Version:               "admin-console-" + strconv.FormatInt(now.UTC().UnixNano(), 10),
		SourceProtectedAppMap: networkExtensionSnapshotSourceProtectedAppMap,
		GeneratedAt:           now.UTC().Format(time.RFC3339),
		DefaultAction:         steering.NetworkExtensionActionTunnel,
		Rules:                 []steering.NetworkExtensionRule{},
		Metadata: map[string]any{
			"source":                                 "admin_console_policy_snapshot",
			"active_network_extension_policy_ids":    policyIDs,
			"default_tunnel_all_tcp":                 true,
			"steering_exception_model":               "agent_config_passthrough_and_provider_loopback_passthrough",
			"wildcard_saas_catalog_projection_state": "not_required_for_default_tunnel_snapshot",
			"header_value_material_in_snapshot":      false,
		},
	}, nil
}

func adminPolicyEligibleForNetworkExtensionSnapshot(policy model.Policy) bool {
	return strings.TrimSpace(policy.Status) == "active" &&
		strings.TrimSpace(policy.Action.Decision) == "allow" &&
		strings.TrimSpace(stringValue(policy.Conditions["steering_mode"])) == "network_extension"
}

func networkExtensionPolicyDestinationPort(policy model.Policy) (int, bool) {
	value, ok := policy.Conditions["destination_port"]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, typed > 0 && typed <= 65_535
	case int64:
		return int(typed), typed > 0 && typed <= 65_535
	case float64:
		asInt := int(typed)
		return asInt, typed == float64(asInt) && asInt > 0 && asInt <= 65_535
	case json.Number:
		asInt, err := typed.Int64()
		return int(asInt), err == nil && asInt > 0 && asInt <= 65_535
	case string:
		asInt, err := strconv.Atoi(strings.TrimSpace(typed))
		return asInt, err == nil && asInt > 0 && asInt <= 65_535
	default:
		return 0, false
	}
}

func networkExtensionPolicyServiceFamily(policy model.Policy) string {
	if policy.ServiceFamily != nil && strings.TrimSpace(*policy.ServiceFamily) != "" {
		return strings.TrimSpace(*policy.ServiceFamily)
	}
	return strings.TrimSpace(stringValue(policy.Conditions["service_family"]))
}

func networkExtensionPolicyFQDNs(policy model.Policy, bundle model.PolicyBundle) []string {
	values := []string{}
	for _, key := range []string{"fqdn", "host", "sni", "destination"} {
		values = append(values, strings.TrimSpace(stringValue(policy.Conditions[key])))
	}
	saasApplicationID := strings.TrimSpace(stringValue(policy.Conditions["saas_application_id"]))
	if saasApplicationID != "" {
		for _, entry := range bundle.SaaSCatalog {
			if strings.TrimSpace(entry.SaaSApplicationID) != saasApplicationID {
				continue
			}
			for _, pattern := range entry.DomainPatterns {
				if strings.Contains(pattern, "*") {
					continue
				}
				values = append(values, strings.TrimSpace(pattern))
			}
		}
	}
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, value := range values {
		candidate := normalizeNetworkExtensionSnapshotHost(value)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeNetworkExtensionSnapshotHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.ContainsAny(value, "*/:") || strings.Contains(value, "..") {
		return ""
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ""
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return ""
		}
	}
	return value
}

func networkExtensionSnapshotHostIsLoopback(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizedNetworkExtensionSnapshotIPs(values []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, value := range values {
		value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), "[]")
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizedNetworkExtensionSnapshotDomains(values []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		value = strings.TrimPrefix(value, "*.")
		value = strings.TrimPrefix(value, ".")
		candidate := normalizeNetworkExtensionSnapshotHost(value)
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		normalized = append(normalized, candidate)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizedNetworkExtensionSnapshotSigningIdentifiers(values []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || !networkExtensionSnapshotSigningIdentifierIsValid(value) {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func networkExtensionSnapshotSigningIdentifierIsValid(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func writeNetworkExtensionSnapshotJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode network extension snapshot %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create network extension snapshot file dir: %w", err)
	}
	// ★ ONE DURABLE WRITE (2026-08-14). Hand-staged create/write/flush/close/chmod/rename — which is exactly
	// durablefile.Write. See ops/checks/one_durable_write.sh.
	if err := durablefile.Write(path, data, 0o640); err != nil {
		return fmt.Errorf("publish network extension snapshot file %s: %w", filepath.Base(path), err)
	}
	return nil
}

func networkExtensionRuntimeEvidencePlaceholder(now time.Time) map[string]any {
	return map[string]any{
		"schema_version":              networkExtensionSnapshotRuntimeEvidenceSchema,
		"evidence_kind":               "provider_runtime_evidence",
		"provider_kind":               "transparent_proxy_provider",
		"runtime_status":              "not_observed",
		"rules_loaded":                false,
		"rule_count":                  0,
		"flow_extraction_attempted":   false,
		"flow_extraction_succeeded":   false,
		"flow_extraction_denied":      false,
		"flow_attempted":              false,
		"flow_tunneled":               false,
		"flow_denied":                 false,
		"last_error":                  "not_observed",
		"raw_logs_included":           false,
		"raw_command_output_included": false,
		"raw_ne_flow_included":        false,
		"host_user_payload_included":  false,
		"no_secret_attestation":       true,
		"created_at":                  now.UTC().Format(time.RFC3339),
	}
}

func networkExtensionRuntimeCopyEvidencePlaceholder(now time.Time) map[string]any {
	return map[string]any{
		"schema_version":                        networkExtensionSnapshotRuntimeCopyEvidenceSchema,
		"evidence_kind":                         "provider_runtime_copy_evidence",
		"status":                                "not_run",
		"runtime_copy_transport_gate":           "not_run",
		"runtime_copy_transport_implementation": "not_run_admin_console_snapshot",
		"edge_connector_realness":               "not_observed",
		"bytes_up":                              0,
		"bytes_down":                            0,
		"blocking_categories":                   []string{"not_run"},
		"raw_logs_included":                     false,
		"raw_command_output_included":           false,
		"raw_ne_flow_included":                  false,
		"host_user_payload_included":            false,
		"no_secret_attestation":                 true,
		"created_at":                            now.UTC().Format(time.RFC3339),
	}
}

func networkExtensionRuntimeDiagnosticPlaceholder(now time.Time) map[string]any {
	return map[string]any{
		"schema_version":                                networkExtensionSnapshotRuntimeDiagnosticSchema,
		"status":                                        "ok",
		"evidence_kind":                                 "phase2_provider_runtime_enum_diagnostic",
		"diagnostic_source":                             "admin_console_policy_snapshot_preload",
		"created_at":                                    now.UTC().Format(time.RFC3339),
		"handle_new_flow_observed":                      false,
		"handle_new_flow_decision_category":             "not_observed",
		"handle_new_flow_extraction_status":             "not_observed",
		"handle_new_flow_extraction_reason":             "not_observed",
		"provider_decision_action":                      "not_observed",
		"provider_decision_reason":                      "not_observed",
		"provider_rules_reload_gate":                    "not_checked",
		"provider_loaded_rules_generation_gate":         "not_observed",
		"provider_loaded_rules_generated_at":            "not_observed",
		"authority_extraction_runtime_marker":           "not_observed",
		"flow_authority_endpoint_source_gate":           "not_observed",
		"flow_authority_port_source_gate":               "not_observed",
		"allow_flow_authority_port_match":               "extraction_failed",
		"single_rule_lab_fallback_gate":                 "not_evaluated",
		"single_rule_lab_fallback_port_gate":            "not_evaluated",
		"live_copy_started":                             false,
		"live_copy_status":                              "not_observed",
		"live_copy_failure_category":                    "none",
		"edge_round_trip_completed":                     false,
		"start_proxy_running_observed":                  false,
		"transparent_network_settings_applied_observed": false,
		"raw_logs_included":                             false,
		"raw_command_output_included":                   false,
		"raw_ne_flow_included":                          false,
		"host_user_payload_included":                    false,
		"destination_ip_included":                       false,
		"credentials_included":                          false,
		"packet_capture_included":                       false,
		"apple_identifier_included":                     false,
		"no_secret_attestation":                         true,
		"recommended_next_dev_action":                   "restart_network_extension_to_load_admin_console_snapshot",
		"nonsecret_notes":                               []string{"Admin Console snapshot placeholder; provider overwrites fields during runtime."},
	}
}

func networkExtensionRawAuthorityDiagnosticPlaceholder(now time.Time) map[string]any {
	return map[string]any{
		"schema_version":                     networkExtensionSnapshotRawAuthoritySchema,
		"status":                             "not_observed",
		"created_at":                         now.UTC().Format(time.RFC3339),
		"diagnostic_source":                  "admin_console_policy_snapshot_preload",
		"authority_host":                     "",
		"authority_port":                     0,
		"authority_endpoint_source_gate":     "not_observed",
		"authority_port_source_gate":         "not_observed",
		"rule_fqdn":                          "not_loaded",
		"rule_destination_port":              0,
		"rule_generated_at":                  "not_observed",
		"handle_new_flow_decision_category":  "not_observed",
		"handle_new_flow_extraction_status":  "not_observed",
		"handle_new_flow_extraction_reason":  "not_observed",
		"provider_decision_action":           "not_observed",
		"provider_decision_reason":           "not_observed",
		"single_rule_lab_fallback_gate":      "not_evaluated",
		"single_rule_lab_fallback_port_gate": "not_evaluated",
		"allow_flow_authority_port_match":    "extraction_failed",
		"raw_endpoint_values_included":       false,
		"no_secret_attestation":              true,
	}
}

// publishAgentConfigOnly writes the agent configuration and nothing else. It exists for the case where the
// steering rules cannot be built: the configuration says where the Edge is, how the tunnel is dialled, which
// keys may update the agent and which certificate authorities the device trusts, and none of that depends on
// a policy existing. The rules file is deliberately not touched — see the caller.
func (publisher *localNetworkExtensionSnapshotPublisher) publishAgentConfigOnly(tenantID string) error {
	if publisher == nil {
		return nil
	}
	if err := os.MkdirAll(publisher.outputDir, 0o750); err != nil {
		return fmt.Errorf("create network extension snapshot dir: %w", err)
	}
	return writeNetworkExtensionSnapshotJSONAtomic(
		filepath.Join(publisher.outputDir, networkExtensionSnapshotAgentConfigRef), publisher.agentConfig(tenantID))
}

// agentConfigOrganization is what an installer states about the organization a device is being enrolled into.
// Empty when this deployment cannot say — a field that is absent is honest; one that is present and wrong
// sends a device to a name nothing answers to.
func agentConfigOrganization(tenantID string) map[string]any {
	tenant := strings.ToLower(strings.TrimSpace(tenantID))
	if tenant == "" {
		return nil
	}
	out := map[string]any{"tenant_id": tenant}
	// ★ TWO SOURCES, BECAUSE THIS RUNS ON BOTH KINDS OF NODE (2026-08-22, measured — the first version asked
	// only the Edge's index and published a tenant_id with no name, because the publisher runs on the CONTROL
	// PLANE, which holds the authority and serves no organization's transport certificate itself).
	//
	// On a control plane the answer is the authority's own record; on an Edge it is the certificate index that
	// node is actually serving. Both are the same string, and asking whichever exists means the file says the
	// same thing wherever it is written.
	serverName, ok := "", false
	if agentConfigTransportAuthority != nil {
		if name, _, _, _, known := agentConfigTransportAuthority.StateFor(tenant); known {
			serverName, ok = name, true
		}
	}
	if !ok && transportTenantCertificates != nil {
		serverName, ok = transportTenantCertificates.ServerNameFor(tenant)
	}
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if !ok || serverName == "" {
		// No transport name of its own: the organization is still named, because knowing WHOSE device this is
		// matters for enrolment either way, and a missing name is not a reason to withhold the id.
		return out
	}
	out["transport_server_name"] = serverName
	// The enrolment name follows the transport name by construction — the control plane mints every
	// organization's transport certificate with enrol.<name> in its SAN, which is what makes the fold
	// reachable at all. On an Edge, offer it only if the certificate this node serves actually carries it: the
	// same index isEnrolmentName consults, so the file and the handshake cannot disagree.
	//
	// ★ the enrolment fold HAS PAID FOR THE OPPOSITE TWICE (2026-08-19 for the recovery name, 2026-08-21 for this one). A
	// device that dials a name no certificate carries fails verification, and it reads as the Edge being down
	// on the one path a device holding nothing has.
	if enrol := organizationEnrolmentName(serverName); enrol != "" {
		if transportTenantCertificates != nil {
			if _, _, carried := transportTenantCertificates.For(enrol); carried {
				out["enrolment_server_name"] = enrol
			}
		} else if agentConfigTransportAuthority != nil {
			// A control plane serves no transport certificate of its own, but it MINTS them, and every one it
			// mints carries this name.
			out["enrolment_server_name"] = enrol
		}
	}
	return out
}

// agentConfigTransportAuthority is the control plane's own record of each organization's transport name. Nil
// on an Edge, which asks its certificate index instead.
var agentConfigTransportAuthority *tenantTransportAuthority

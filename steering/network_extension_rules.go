package steering

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	NetworkExtensionRulesSchemaVersion = "network_extension_steering_rules.v1"

	NetworkExtensionActionTunnel = "tunnel"
	NetworkExtensionActionDeny   = "deny"

	NetworkExtensionDecisionReasonMatched      = "matched_network_extension_rule"
	NetworkExtensionDecisionReasonDefault      = "matched_default_network_extension_tunnel"
	NetworkExtensionDecisionReasonNoMatch      = "no_matching_network_extension_rule"
	NetworkExtensionDecisionReasonInvalidFlow  = "invalid_flow_authority"
	NetworkExtensionDecisionReasonInvalidRules = "invalid_network_extension_rules"
)

// NetworkExtensionRules is the entitlement-independent flow steering contract
// consumed by the future macOS App Proxy Provider / Packet Tunnel Provider.
type NetworkExtensionRules struct {
	SchemaVersion         string                 `json:"schema_version"`
	TenantID              string                 `json:"tenant_id"`
	Version               string                 `json:"version"`
	SourceProtectedAppMap string                 `json:"source_protected_app_map"`
	GeneratedAt           string                 `json:"generated_at"`
	DefaultAction         string                 `json:"default_action"`
	Rules                 []NetworkExtensionRule `json:"rules"`
	Metadata              map[string]any         `json:"metadata,omitempty"`
}

type NetworkExtensionRule struct {
	ApplicationID   string         `json:"application_id"`
	FQDN            string         `json:"fqdn"`
	DestinationPort int            `json:"destination_port"`
	ServiceFamily   string         `json:"service_family"`
	SteeringMode    string         `json:"steering_mode"`
	Action          string         `json:"action"`
	ConnectorGroup  *string        `json:"connector_group_id,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type NetworkExtensionDecision struct {
	Action          string `json:"action"`
	Reason          string `json:"reason"`
	ApplicationID   string `json:"application_id,omitempty"`
	FQDN            string `json:"fqdn,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	ServiceFamily   string `json:"service_family,omitempty"`
	ConnectorGroup  string `json:"connector_group_id,omitempty"`
}

func LoadNetworkExtensionRules(path string) (NetworkExtensionRules, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return NetworkExtensionRules{}, err
	}
	var rules NetworkExtensionRules
	if err := json.Unmarshal(body, &rules); err != nil {
		return NetworkExtensionRules{}, err
	}
	if err := ValidateNetworkExtensionRules(rules); err != nil {
		return NetworkExtensionRules{}, err
	}
	return rules, nil
}

func ValidateNetworkExtensionRules(rules NetworkExtensionRules) error {
	if strings.TrimSpace(rules.SchemaVersion) != NetworkExtensionRulesSchemaVersion {
		return fmt.Errorf("network extension rules schema_version must be %s", NetworkExtensionRulesSchemaVersion)
	}
	if strings.TrimSpace(rules.TenantID) == "" {
		return fmt.Errorf("network extension rules tenant_id is required")
	}
	if strings.TrimSpace(rules.Version) == "" {
		return fmt.Errorf("network extension rules version is required")
	}
	if strings.TrimSpace(rules.SourceProtectedAppMap) == "" {
		return fmt.Errorf("network extension rules source_protected_app_map is required")
	}
	if strings.TrimSpace(rules.GeneratedAt) == "" {
		return fmt.Errorf("network extension rules generated_at is required")
	}
	defaultAction := strings.TrimSpace(rules.DefaultAction)
	if defaultAction != NetworkExtensionActionDeny && defaultAction != NetworkExtensionActionTunnel {
		return fmt.Errorf("network extension rules default_action must be deny or tunnel")
	}
	if len(rules.Rules) == 0 && defaultAction != NetworkExtensionActionTunnel {
		return fmt.Errorf("network extension rules must not be empty unless default_action is tunnel")
	}

	seen := map[string]struct{}{}
	for _, rule := range rules.Rules {
		if strings.TrimSpace(rule.ApplicationID) == "" {
			return fmt.Errorf("network extension rule application_id is required")
		}
		host, ok := normalizeNetworkExtensionHost(rule.FQDN)
		if !ok {
			return fmt.Errorf("network extension rule fqdn is invalid for %s", rule.ApplicationID)
		}
		if !validNetworkExtensionPort(rule.DestinationPort) {
			return fmt.Errorf("network extension rule destination_port is invalid for %s", rule.ApplicationID)
		}
		if strings.TrimSpace(rule.ServiceFamily) == "" {
			return fmt.Errorf("network extension rule service_family is required for %s", rule.ApplicationID)
		}
		if strings.TrimSpace(rule.SteeringMode) != "network_extension" {
			return fmt.Errorf("network extension rule steering_mode must be network_extension for %s", rule.ApplicationID)
		}
		if strings.TrimSpace(rule.Action) != NetworkExtensionActionTunnel {
			return fmt.Errorf("network extension rule action must be tunnel for %s", rule.ApplicationID)
		}
		key := networkExtensionDestinationKey(host, rule.DestinationPort)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate network extension destination %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func EvaluateNetworkExtensionFlow(rules NetworkExtensionRules, host string, port int) NetworkExtensionDecision {
	if err := ValidateNetworkExtensionRules(rules); err != nil {
		return NetworkExtensionDecision{
			Action: NetworkExtensionActionDeny,
			Reason: NetworkExtensionDecisionReasonInvalidRules,
		}
	}
	if !validNetworkExtensionPort(port) {
		return NetworkExtensionDecision{
			Action: NetworkExtensionActionDeny,
			Reason: NetworkExtensionDecisionReasonInvalidFlow,
		}
	}
	// A raw IP-literal flow (client connected by IP) is a VALID flow, not an invalid one — it simply cannot
	// match any FQDN rule, so it must fall through to default_action. The old code normalized the host as an
	// FQDN and DENIED it up front when that failed, so an IP-literal egress was denied even under
	// default_action=tunnel (tunnel-all) — a compiled-in disposition instead of honoring operator config
	// (no-hardcoded-policy, review #25). Only a host that is neither a valid FQDN nor a valid IP literal is truly malformed.
	normalizedHost, isFQDN := normalizeNetworkExtensionHost(host)
	ipLiteral, isIP := normalizeNetworkExtensionIPLiteral(host)
	if !isFQDN && !isIP {
		return NetworkExtensionDecision{
			Action: NetworkExtensionActionDeny,
			Reason: NetworkExtensionDecisionReasonInvalidFlow,
		}
	}
	if !isFQDN {
		// IP-literal flow: no FQDN rule can match it, so go straight to default_action with the IP as the host.
		normalizedHost = ipLiteral
	} else {
		for _, rule := range rules.Rules {
			ruleHost, _ := normalizeNetworkExtensionHost(rule.FQDN)
			if ruleHost != normalizedHost || rule.DestinationPort != port {
				continue
			}
			decision := NetworkExtensionDecision{
				Action:          NetworkExtensionActionTunnel,
				Reason:          NetworkExtensionDecisionReasonMatched,
				ApplicationID:   strings.TrimSpace(rule.ApplicationID),
				FQDN:            ruleHost,
				DestinationPort: rule.DestinationPort,
				ServiceFamily:   strings.TrimSpace(rule.ServiceFamily),
			}
			if rule.ConnectorGroup != nil {
				decision.ConnectorGroup = strings.TrimSpace(*rule.ConnectorGroup)
			}
			return decision
		}
	}
	if strings.TrimSpace(rules.DefaultAction) == NetworkExtensionActionTunnel {
		return NetworkExtensionDecision{
			Action:          NetworkExtensionActionTunnel,
			Reason:          NetworkExtensionDecisionReasonDefault,
			ApplicationID:   "default_network_extension_tunnel",
			FQDN:            normalizedHost,
			DestinationPort: port,
			ServiceFamily:   networkExtensionDefaultServiceFamily(port),
		}
	}
	return NetworkExtensionDecision{
		Action: NetworkExtensionActionDeny,
		Reason: NetworkExtensionDecisionReasonNoMatch,
	}
}

func networkExtensionDefaultServiceFamily(port int) string {
	switch port {
	case 443:
		return "https"
	case 80:
		return "http"
	default:
		return "tcp"
	}
}

func normalizeNetworkExtensionHost(host string) (string, bool) {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	if strings.ContainsAny(host, "*/:") || strings.Contains(host, "..") {
		return "", false
	}
	if strings.ContainsFunc(host, func(r rune) bool {
		return r <= ' ' || r > '~'
	}) {
		return "", false
	}
	labels := strings.Split(host, ".")
	if networkExtensionHostIsIPv4Literal(labels) {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}
	return host, true
}

// normalizeNetworkExtensionIPLiteral reports whether host is a valid IP literal (v4 or v6) and returns its
// canonical lowercase form. Used to tell a raw-IP flow (valid, routed via default_action) apart from a
// genuinely malformed host (denied as an invalid flow).
func normalizeNetworkExtensionIPLiteral(host string) (string, bool) {
	h := strings.TrimSpace(strings.ToLower(host))
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return h, true
	}
	return "", false
}

func networkExtensionHostIsIPv4Literal(labels []string) bool {
	if len(labels) != 4 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validNetworkExtensionPort(port int) bool {
	return port > 0 && port <= 65535
}

func networkExtensionDestinationKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/policy"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// server-initiated access control admin surface: store + setters on the admin policy
// store, model->decision conversion for RuntimeEvaluator, and the admin API request handling.

var validLegacyExceptionMode = map[string]bool{"observe": true, "warn": true, "deny": true, "allow": true}

// validateLegacyException enforces the required governance fields.
func validateLegacyException(ex model.LegacyException) error {
	if strings.TrimSpace(ex.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(ex.BusinessOwner) == "" {
		return fmt.Errorf("business_owner is required (governance)")
	}
	if strings.TrimSpace(ex.ExpiresAt) == "" {
		return fmt.Errorf("expires_at is required (governance)")
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt)); err != nil {
		return fmt.Errorf("expires_at must be RFC3339: %w", err)
	}
	if m := strings.TrimSpace(ex.Mode); m != "" && !validLegacyExceptionMode[m] {
		return fmt.Errorf("invalid mode %q (want observe|warn|deny|allow)", ex.Mode)
	}
	if ex.Port < 0 || ex.Port > 65535 {
		return fmt.Errorf("port must be from 0 to 65535")
	}
	if ex.MaxSessionSeconds < 0 {
		return fmt.Errorf("max_session_seconds must not be negative")
	}
	if ex.Status != "active" && ex.Status != "disabled" {
		return fmt.Errorf("status must be active or disabled")
	}
	if ex.Status == "active" {
		return validateIncomingExportConditions(ex)
	}
	return nil
}

func validateIncomingExportConditions(ex model.LegacyException) error {
	// These are the existing TCP-family mappings of the v1 Windows consumer.
	// Its unknown-family fallback is TCP, so arbitrary family names are unsafe.
	switch strings.ToLower(strings.TrimSpace(ex.ServiceFamily)) {
	case "", "tcp", "smb", "cifs", "rdp", "winrm", "wmi", "dcom", "rpc", "ssh", "vnc", "mssql", "mysql", "postgres", "oracle", "db", "http", "https", "rmm", "management_tcp":
	default:
		return fmt.Errorf("exception %q has a service family unsupported by this export", ex.ID)
	}
	protocol := strings.ToLower(strings.TrimSpace(ex.Protocol))
	if (protocol != "" && protocol != "tcp") || ex.Port < 0 || ex.Port > 65535 || ex.ApprovalRequired || ex.MaxSessionSeconds != 0 {
		return fmt.Errorf("exception %q has conditions unsupported by this export (TCP/Any only; approval and session limits are unsupported)", ex.ID)
	}
	if protocol == "" && strings.TrimSpace(ex.ServiceFamily) == "" && ex.Port != 0 {
		return fmt.Errorf("exception %q has a port without a transport", ex.ID)
	}
	return nil
}

// Omitted fields retain the current restriction; explicit empty/zero/false values
// remain intentional changes. Null is not an explicit wildcard or activation.
func mergeLegacyException(current model.LegacyException, patch map[string]json.RawMessage, tenant string) (model.LegacyException, error) {
	raw, err := json.Marshal(current)
	if err != nil {
		return current, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return current, err
	}
	for key, value := range patch {
		if _, known := fields[key]; !known {
			return current, fmt.Errorf("unknown incoming exception field %q", key)
		}
		if strings.TrimSpace(string(value)) == "null" {
			return current, fmt.Errorf("incoming exception field %q cannot be null", key)
		}
		fields[key] = value
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		return current, err
	}
	var result model.LegacyException
	if err := json.Unmarshal(raw, &result); err != nil {
		return current, fmt.Errorf("invalid incoming exception field type")
	}
	result.TenantID = tenant
	result.Protocol = strings.ToLower(strings.TrimSpace(result.Protocol))
	result.Mode = strings.ToLower(strings.TrimSpace(result.Mode))
	result.Status = strings.ToLower(strings.TrimSpace(result.Status))
	if result.Protocol != "" && result.Protocol != "tcp" && !(result.Status == "disabled" && result.Protocol == strings.ToLower(strings.TrimSpace(current.Protocol))) {
		return current, fmt.Errorf("non-TCP incoming conditions cannot be created or activated; disable or correct an existing record")
	}
	if err := validateLegacyException(result); err != nil {
		return current, err
	}
	return result, nil
}

// Refuse the complete export instead of silently dropping a restriction while
// retaining a wider allow. Turning management off still withdraws all DSSE rules.
func incomingExportForTenant(store policy.RuntimeStore, tenant string, now time.Time) (serverInitiatedExport, error) {
	source, ok := store.(interface {
		LegacyExceptionsFor(string) []model.LegacyException
		ServerInitiatedEnabledFor(string) bool
	})
	if !ok {
		return serverInitiatedExport{}, fmt.Errorf("incoming policy storage is unavailable")
	}
	if !source.ServerInitiatedEnabledFor(tenant) {
		exp, _ := buildServerInitiatedExport(nil, now)
		exp.DefaultAction = "allow"
		return exp, nil
	}
	return buildServerInitiatedExport(source.LegacyExceptionsFor(tenant), now)
}

type adminLegacyExceptionListResponse struct {
	SchemaVersion       string                    `json:"schema_version"`
	ServerInitiatedNote string                    `json:"server_initiated_note"`
	Exceptions          []adminLegacyExceptionRow `json:"exceptions"`
	NoSecretAttestation bool                      `json:"no_secret_attestation"`
}

type adminLegacyExceptionRow struct {
	model.LegacyException
	Expired      bool `json:"expired"`
	ExpiringSoon bool `json:"expiring_soon"` // within 7 days
}

// serverInitiatedExportRule is a firewall-agnostic rule for server-initiated (server->client) control,
// exported to an existing Firewall / L3 (or Network Enforcement Connector) for agentless/VLAN endpoints
// (S2). The default posture is deny; exceptions are the explicit allow/deny rules above it.
type serverInitiatedExportRule struct {
	ExceptionID   string `json:"exception_id"`
	SourceServer  string `json:"source_server"`
	DeviceGroup   string `json:"device_group"`
	ServiceFamily string `json:"service_family"`
	Port          int    `json:"port"`
	Action        string `json:"action"` // allow | deny | log | log_alert
}

type serverInitiatedExport struct {
	SchemaVersion       string                      `json:"schema_version"`
	GeneratedAt         string                      `json:"generated_at"`
	DefaultAction       string                      `json:"default_action"` // deny (server-initiated default-deny)
	RuleCount           int                         `json:"rule_count"`
	Rules               []serverInitiatedExportRule `json:"rules"`
	NoSecretAttestation bool                        `json:"no_secret_attestation"`
}

var legacyModeToFirewallAction = map[string]string{"allow": "allow", "deny": "deny", "observe": "log", "warn": "log_alert"}

// buildServerInitiatedExport emits firewall rules for active, non-expired Legacy Exceptions (S2).
// Pure function (testable). Default action is deny (server-initiated default-deny).
func buildServerInitiatedExport(exs []model.LegacyException, now time.Time) (serverInitiatedExport, error) {
	rules := make([]serverInitiatedExportRule, 0, len(exs))
	for _, ex := range exs {
		status := strings.ToLower(strings.TrimSpace(ex.Status))
		if status == "disabled" {
			continue
		}
		if status != "active" {
			return serverInitiatedExport{}, fmt.Errorf("exception %q has an invalid status", ex.ID)
		}
		expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt))
		if err != nil {
			return serverInitiatedExport{}, fmt.Errorf("exception %q has an invalid expiry", ex.ID)
		}
		if !now.Before(expiry) {
			continue
		}
		if err := validateIncomingExportConditions(ex); err != nil {
			return serverInitiatedExport{}, err
		}
		mode := strings.ToLower(strings.TrimSpace(ex.Mode))
		if mode == "" {
			mode = "allow"
		}
		action := legacyModeToFirewallAction[mode]
		if action == "" {
			return serverInitiatedExport{}, fmt.Errorf("exception %q has an invalid mode", ex.ID)
		}
		// Existing Windows readers derive transport from ServiceFamily. A TCP
		// condition with no family must not be exported as Any (which drops Port).
		family := ex.ServiceFamily
		if strings.TrimSpace(family) == "" && strings.EqualFold(strings.TrimSpace(ex.Protocol), "tcp") {
			family = "tcp"
		}
		rules = append(rules, serverInitiatedExportRule{
			ExceptionID: ex.ID, SourceServer: ex.SourceServer, DeviceGroup: ex.DeviceGroup,
			ServiceFamily: family, Port: ex.Port, Action: action,
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ExceptionID < rules[j].ExceptionID })
	return serverInitiatedExport{
		SchemaVersion: "server_initiated_export.v1", GeneratedAt: now.UTC().Format(time.RFC3339),
		DefaultAction: "deny", RuleCount: len(rules), Rules: rules, NoSecretAttestation: true,
	}, nil
}

// buildLegacyExceptionList annotates exceptions with expiry status (renewal-decision prompt, ).
func buildLegacyExceptionList(exs []model.LegacyException, now time.Time) adminLegacyExceptionListResponse {
	rows := make([]adminLegacyExceptionRow, 0, len(exs))
	for _, ex := range exs {
		row := adminLegacyExceptionRow{LegacyException: ex}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt)); err == nil {
			row.Expired = !now.Before(t)
			row.ExpiringSoon = !row.Expired && now.Add(7*24*time.Hour).After(t)
		}
		rows = append(rows, row)
	}
	return adminLegacyExceptionListResponse{
		SchemaVersion:       "admin_legacy_exceptions.v1",
		ServerInitiatedNote: "server-initiated flows are default-deny unless matched by an active, non-expired exception",
		Exceptions:          rows, NoSecretAttestation: true,
	}
}

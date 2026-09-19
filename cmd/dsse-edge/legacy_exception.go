package main

import (
	"fmt"
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
	return nil
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
func buildServerInitiatedExport(exs []model.LegacyException, now time.Time) serverInitiatedExport {
	rules := make([]serverInitiatedExportRule, 0, len(exs))
	for _, ex := range exs {
		if !strings.EqualFold(strings.TrimSpace(ex.Status), "active") {
			continue
		}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(ex.ExpiresAt)); err == nil && !now.Before(t) {
			continue // expired
		}
		mode := strings.TrimSpace(ex.Mode)
		if mode == "" {
			mode = "allow"
		}
		action := legacyModeToFirewallAction[mode]
		if action == "" {
			action = "allow"
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
	}
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

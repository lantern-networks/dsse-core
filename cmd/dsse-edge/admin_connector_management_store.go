package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

type adminConnectorListResponse struct {
	Connectors []adminConnector `json:"connectors"`
	Count      int              `json:"count"`
}

type adminConnector struct {
	ID                       string   `json:"id"`
	TenantID                 string   `json:"tenant_id"`
	ConnectorGroupID         string   `json:"connector_group_id,omitempty"`
	Name                     string   `json:"name,omitempty"`
	EdgeRegionID             string   `json:"edge_region_id,omitempty"`
	EdgeClusterID            string   `json:"edge_cluster_id,omitempty"`
	ApplicationIDs           []string `json:"application_ids"`
	PrivateBaseURLConfigured bool     `json:"private_base_url_configured"`
	Status                   string   `json:"status,omitempty"`
	RegisteredAt             string   `json:"registered_at,omitempty"`
	LastHeartbeatAt          string   `json:"last_heartbeat_at,omitempty"`
	RuntimeSecretConfigured  bool     `json:"runtime_secret_configured"`
	RuntimeSecretRotatedAt   *string  `json:"runtime_secret_rotated_at,omitempty"`
	MetadataKeyCount         int      `json:"metadata_key_count"`
	// Additive Slice 0 detail fields (secret-safe). All omitempty / pointer so existing JSON clients are
	// unaffected and an unknown value (e.g. no tunnel manager, no reported version) is simply absent.
	TunnelConnected *bool `json:"tunnel_connected,omitempty"` // nil = unknown (no tunnel manager)
	// Online is the ANSWER, not the ingredients: whether this connector is up, decided once, here, by
	// adminConnectorOnline.
	//
	// ★★★ THE SCREEN HAD ITS OWN RULE AND IT WAS A DIFFERENT RULE (2026-09-01, seen on the Console). It read
	// tunnel_connected as a boolean, so the moment that field learned a third state — unknown, which is what a
	// node answers about a connector it does not hold, and what a CONTROL PLANE answers about every connector
	// — the screen read unknown as offline. It then showed "Healthy … 0 / 2 connectors online", with a
	// heartbeat eight seconds old beside each Offline row, while the API it had just called said online=2.
	//
	// A rule kept in two places disagrees the first time one of them learns something. So the server sends the
	// conclusion and the screen shows it.
	Online          bool                           `json:"online"`
	Version         string                         `json:"version,omitempty"`          // connector-reported runtime version
	UptimeSeconds   *int64                         `json:"uptime_seconds,omitempty"`   // connector-reported uptime
	ReachableRoutes *adminConnectorReachableRoutes `json:"reachable_routes,omitempty"` // route layer (non-secret destinations)
	// AttachedRegionID is where this connector's tunnel was last seen terminating, reported by the Edge that
	// terminated it. It differs from EdgeRegionID after a region failover, and the difference is the whole
	// point: it is the region the deployment routes flows to.
	AttachedRegionID string `json:"attached_region_id,omitempty"`
	// ★ THE FACTS, NOT THE SENTENCE. The Console says what the difference MEANS, in the reader's language;
	// composing that sentence here as well would be the same statement in two places, and the two would drift.
}

// adminConnectorReachableRoutes is the admin-safe projection of model.ConnectorReachableRoutes. Reachable
// destinations (FQDN domains, CIDRs, namespace) are the route LAYER and are not secrets — they are exposed
// directly, with counts for at-a-glance summaries. Private base URLs / runtime secrets are never included.
type adminConnectorReachableRoutes struct {
	FQDNDomains     []string `json:"fqdn_domains,omitempty"`
	FQDNDomainCount int      `json:"fqdn_domain_count"`
	CIDRs           []string `json:"cidrs,omitempty"`
	CIDRCount       int      `json:"cidr_count"`
	Namespace       string   `json:"namespace,omitempty"`
}

// connectorTunnelStatusResolver reports whether a connector currently has a live tunnel session. It returns
// nil when liveness cannot be determined (no tunnel manager wired), which surfaces as "unknown" in the UI.
type connectorTunnelStatusResolver func(connectorID string) *bool

type adminConnectorRuntimeSecretRotateResponse struct {
	Connector     adminConnector `json:"connector"`
	RuntimeSecret string         `json:"runtime_secret"`
	RotatedAt     string         `json:"rotated_at"`
}

func adminConnectorList(ctx context.Context, registry connectorRegistryStore, tenantID string, tunnelStatus connectorTunnelStatusResolver) (adminConnectorListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminConnectorListResponse{}, fmt.Errorf("tenant_id is required")
	}
	connectors, err := connectorRegistrationsForTenantWithContext(ctx, registry, tenantID)
	if err != nil {
		return adminConnectorListResponse{}, err
	}
	result := make([]adminConnector, 0, len(connectors))
	for _, conn := range connectors {
		dto := adminConnectorFromModel(conn)
		applyConnectorTunnelStatus(&dto, tunnelStatus)
		result = append(result, dto)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})
	return adminConnectorListResponse{
		Connectors: result,
		Count:      len(result),
	}, nil
}

func adminConnectorGet(ctx context.Context, registry connectorRegistryStore, tenantID, connectorID string, tunnelStatus connectorTunnelStatusResolver) (adminConnector, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorID = strings.TrimSpace(connectorID)
	if tenantID == "" {
		return adminConnector{}, false, fmt.Errorf("tenant_id is required")
	}
	if connectorID == "" {
		return adminConnector{}, false, fmt.Errorf("connector_id is required")
	}
	if strings.Contains(connectorID, "/") {
		return adminConnector{}, false, fmt.Errorf("connector_id cannot contain slash")
	}
	conn, ok, err := connectorRegistrationForTenantWithContext(ctx, registry, connectorID, tenantID)
	if err != nil || !ok {
		return adminConnector{}, ok, err
	}
	dto := adminConnectorFromModel(conn)
	applyConnectorTunnelStatus(&dto, tunnelStatus)
	return dto, true, nil
}

// applyConnectorTunnelStatus overlays the live tunnel-connection state onto a connector DTO. A nil resolver
// (or one that returns nil) leaves TunnelConnected nil = unknown, never asserting a false "disconnected".
func applyConnectorTunnelStatus(dto *adminConnector, tunnelStatus connectorTunnelStatusResolver) {
	if dto == nil {
		return
	}
	if tunnelStatus != nil {
		dto.TunnelConnected = tunnelStatus(dto.ID)
	}
	// Decided here so every reader gets the same answer — see the note on adminConnector.Online.
	dto.Online = adminConnectorOnline(*dto, time.Now().UTC())
}

func adminConnectorRotateRuntimeSecret(ctx context.Context, registry connectorRegistryStore, tenantID, connectorID string, request connectorRuntimeSecretRotateRequest, now time.Time, tunnelStatus connectorTunnelStatusResolver) (adminConnectorRuntimeSecretRotateResponse, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	connectorID = strings.TrimSpace(connectorID)
	if tenantID == "" {
		return adminConnectorRuntimeSecretRotateResponse{}, false, fmt.Errorf("tenant_id is required")
	}
	if connectorID == "" {
		return adminConnectorRuntimeSecretRotateResponse{}, false, fmt.Errorf("connector_id is required")
	}
	if strings.Contains(connectorID, "/") {
		return adminConnectorRuntimeSecretRotateResponse{}, false, fmt.Errorf("connector_id cannot contain slash")
	}
	runtimeSecret, err := connectorRuntimeSecretForRotation(request)
	if err != nil {
		return adminConnectorRuntimeSecretRotateResponse{}, false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	conn, ok, err := registry.RotateRuntimeSecretHashForTenantWithMetadata(tenantID, connectorID, connectorRuntimeSecretHash(runtimeSecret), now, "")
	if err != nil || !ok {
		return adminConnectorRuntimeSecretRotateResponse{}, ok, err
	}
	dto := adminConnectorFromModel(conn)
	applyConnectorTunnelStatus(&dto, tunnelStatus)
	return adminConnectorRuntimeSecretRotateResponse{
		Connector:     dto,
		RuntimeSecret: runtimeSecret,
		RotatedAt:     now.UTC().Format(time.RFC3339),
	}, true, nil
}

func adminConnectorFromModel(conn model.ConnectorRegistration) adminConnector {
	runtimeSecretRotatedAt := adminConnectorRuntimeSecretRotatedAt(conn.Metadata)
	applications := []string{}
	if conn.ApplicationIDs != nil {
		applications = append(applications, conn.ApplicationIDs...)
		sort.Strings(applications)
	}
	name := conn.Name
	if dn := connector.DisplayName(conn); dn != "" {
		name = dn // operator-set display name wins over the connector's self-reported name
	}
	return adminConnector{
		ID:                       conn.ID,
		TenantID:                 conn.TenantID,
		ConnectorGroupID:         conn.ConnectorGroupID,
		Name:                     name,
		EdgeRegionID:             conn.EdgeRegionID,
		AttachedRegionID:         conn.AttachedRegionID,
		EdgeClusterID:            conn.EdgeClusterID,
		ApplicationIDs:           applications,
		PrivateBaseURLConfigured: strings.TrimSpace(conn.PrivateBaseURL) != "",
		Status:                   conn.Status,
		RegisteredAt:             conn.RegisteredAt,
		LastHeartbeatAt:          conn.LastHeartbeatAt,
		RuntimeSecretConfigured:  connectorRuntimeSecretHashFromMetadata(conn.Metadata) != "",
		RuntimeSecretRotatedAt:   runtimeSecretRotatedAt,
		MetadataKeyCount:         adminConnectorMetadataKeyCount(conn.Metadata),
		Version:                  adminConnectorVersion(conn.Metadata),
		UptimeSeconds:            adminConnectorUptimeSeconds(conn.Metadata),
		ReachableRoutes:          adminConnectorReachableRoutesFromModel(conn.ReachableRoutes),
	}
}

// adminConnectorVersion reads the connector-reported runtime version from metadata (non-secret). Empty when
// the connector never reported one.
func adminConnectorVersion(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata["version"].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(raw)
}

// adminConnectorUptimeSeconds reads the connector-reported uptime from metadata. JSON decoding may surface a
// numeric metadata value as float64, so both integer and float encodings are accepted. Returns nil (unknown)
// when absent or non-positive.
func adminConnectorUptimeSeconds(metadata map[string]any) *int64 {
	if metadata == nil {
		return nil
	}
	var seconds int64
	switch v := metadata["uptime_seconds"].(type) {
	case int64:
		seconds = v
	case int:
		seconds = int64(v)
	case float64:
		seconds = int64(v)
	default:
		return nil
	}
	if seconds <= 0 {
		return nil
	}
	return &seconds
}

// adminConnectorReachableRoutesFromModel projects the route layer (FQDN domains, CIDRs, namespace) with
// counts. These destinations are not secrets; private base URLs / runtime secrets are never included here.
func adminConnectorReachableRoutesFromModel(routes model.ConnectorReachableRoutes) *adminConnectorReachableRoutes {
	fqdn := append([]string(nil), routes.FQDNDomains...)
	cidrs := append([]string(nil), routes.CIDRs...)
	namespace := strings.TrimSpace(routes.Namespace)
	if len(fqdn) == 0 && len(cidrs) == 0 && namespace == "" {
		return nil
	}
	sort.Strings(fqdn)
	sort.Strings(cidrs)
	return &adminConnectorReachableRoutes{
		FQDNDomains:     fqdn,
		FQDNDomainCount: len(fqdn),
		CIDRs:           cidrs,
		CIDRCount:       len(cidrs),
		Namespace:       namespace,
	}
}

func adminConnectorRuntimeSecretRotatedAt(metadata map[string]any) *string {
	if metadata == nil {
		return nil
	}
	raw, ok := metadata["runtime_secret_rotated_at"].(string)
	if !ok {
		return nil
	}
	rotatedAt := strings.TrimSpace(raw)
	if rotatedAt == "" {
		return nil
	}
	return &rotatedAt
}

func adminConnectorMetadataKeyCount(metadata map[string]any) int {
	if metadata == nil {
		return 0
	}
	count := 0
	for key := range metadata {
		switch key {
		case "runtime_secret_hash", "runtime_secret_rotated_at", "runtime_secret_rotated_by",
			"version", "uptime_seconds":
			// runtime-secret keys are server-managed; version/uptime_seconds are surfaced as dedicated
			// DTO fields, so neither is counted as custom metadata.
			continue
		default:
			count++
		}
	}
	return count
}

func adminConnectorManagementAuditLog(eventType string, conn adminConnector, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := strings.TrimPrefix(eventType, "admin_connector_")
	result := conn.Status
	if result == "" {
		result = "updated"
	}
	reason := "Connector management admin metadata updated."
	targetType := "admin_connector"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       conn.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &conn.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status":                            conn.Status,
			"connector_group_id_present":        conn.ConnectorGroupID != "",
			"edge_region_id_present":            conn.EdgeRegionID != "",
			"edge_cluster_id_present":           conn.EdgeClusterID != "",
			"application_count":                 len(conn.ApplicationIDs),
			"private_base_url_configured":       conn.PrivateBaseURLConfigured,
			"runtime_secret_configured":         conn.RuntimeSecretConfigured,
			"runtime_secret_rotated_at_present": conn.RuntimeSecretRotatedAt != nil && *conn.RuntimeSecretRotatedAt != "",
			"metadata_key_count":                conn.MetadataKeyCount,
			"connector_metadata_recorded_scope": "none",
			"runtime_secret_material_recorded":  false,
			"runtime_secret_hash_recorded":      false,
			"connector_runtime_secret_rotated":  eventType == "admin_connector_runtime_secret_rotated",
			"runtime_hot_reload":                false,
			"reason_codes":                      []string{"admin_connector_management_lifecycle"},
		},
	}
}

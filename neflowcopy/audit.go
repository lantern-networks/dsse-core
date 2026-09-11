package neflowcopy

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/tunnel"
)

const MetadataAuditContractVersion = "ne_flow_copy_metadata_audit.v1"

const (
	AuditEventFlowCopyStarted                    = "flow_copy_started"
	AuditEventFlowCopyByteCapExceeded            = "flow_copy_byte_cap_exceeded"
	AuditEventFlowCopyIdleTimeout                = "flow_copy_idle_timeout"
	AuditEventFlowCopyBackpressureOverflowClosed = "flow_copy_backpressure_overflow_closed"
	AuditEventFlowCopyTenantScopeMismatch        = "flow_copy_tenant_scope_mismatch"
	AuditEventFlowCopyClosed                     = "flow_copy_closed"
)

var requiredMetadataAuditEvents = []string{
	AuditEventFlowCopyStarted,
	AuditEventFlowCopyByteCapExceeded,
	AuditEventFlowCopyIdleTimeout,
	AuditEventFlowCopyBackpressureOverflowClosed,
	AuditEventFlowCopyTenantScopeMismatch,
	AuditEventFlowCopyClosed,
}

type MetadataAuditInput struct {
	EventType      string
	TenantID       string
	RequestID      string
	ApplicationID  string
	Direction      string
	CloseReason    string
	BytesUp        int64
	BytesDown      int64
	DurationMillis int64
}

type MetadataAuditEvent struct {
	SchemaVersion                    string `json:"schema_version"`
	EventType                        string `json:"event_type"`
	TenantID                         string `json:"tenant_id"`
	RequestID                        string `json:"request_id"`
	ApplicationID                    string `json:"application_id"`
	Direction                        string `json:"direction,omitempty"`
	CloseReason                      string `json:"close_reason,omitempty"`
	BytesUp                          int64  `json:"bytes_up"`
	BytesDown                        int64  `json:"bytes_down"`
	DurationMillis                   int64  `json:"duration_ms"`
	MetadataOnly                     bool   `json:"metadata_only"`
	NetworkExtensionRuntimeUsed      bool   `json:"network_extension_runtime_used"`
	NetworkExtensionFlowReadStarted  bool   `json:"network_extension_flow_read_started"`
	NetworkExtensionFlowWriteStarted bool   `json:"network_extension_flow_write_started"`
	EdgeTunnelOpenStarted            bool   `json:"edge_tunnel_open_started"`
	TCPPayloadCopyStarted            bool   `json:"tcp_payload_copy_started"`
	RawPayloadIncluded               bool   `json:"raw_payload_included"`
	RawNEFlowIncluded                bool   `json:"raw_ne_flow_included"`
	RawDestinationIPIncluded         bool   `json:"raw_destination_ip_included"`
	CredentialsIncluded              bool   `json:"credentials_included"`
	SessionIDIncluded                bool   `json:"session_id_included"`
}

func RequiredMetadataAuditEvents() []string {
	events := make([]string, len(requiredMetadataAuditEvents))
	copy(events, requiredMetadataAuditEvents)
	return events
}

func NewMetadataAuditEvent(input MetadataAuditInput) (MetadataAuditEvent, error) {
	eventType := strings.TrimSpace(input.EventType)
	if !isRequiredMetadataAuditEvent(eventType) {
		return MetadataAuditEvent{}, fmt.Errorf("metadata audit event_type %q is not allowed", input.EventType)
	}
	tenantID, err := requiredMetadataID("tenant_id", input.TenantID)
	if err != nil {
		return MetadataAuditEvent{}, err
	}
	requestID, err := requiredMetadataID("request_id", input.RequestID)
	if err != nil {
		return MetadataAuditEvent{}, err
	}
	applicationID, err := requiredMetadataID("application_id", input.ApplicationID)
	if err != nil {
		return MetadataAuditEvent{}, err
	}
	if input.BytesUp < 0 || input.BytesDown < 0 || input.DurationMillis < 0 {
		return MetadataAuditEvent{}, fmt.Errorf("metadata audit metrics cannot be negative")
	}
	return MetadataAuditEvent{
		SchemaVersion:                    MetadataAuditContractVersion,
		EventType:                        eventType,
		TenantID:                         tenantID,
		RequestID:                        requestID,
		ApplicationID:                    applicationID,
		Direction:                        strings.TrimSpace(input.Direction),
		CloseReason:                      strings.TrimSpace(input.CloseReason),
		BytesUp:                          input.BytesUp,
		BytesDown:                        input.BytesDown,
		DurationMillis:                   input.DurationMillis,
		MetadataOnly:                     true,
		NetworkExtensionRuntimeUsed:      false,
		NetworkExtensionFlowReadStarted:  false,
		NetworkExtensionFlowWriteStarted: false,
		EdgeTunnelOpenStarted:            false,
		TCPPayloadCopyStarted:            false,
		RawPayloadIncluded:               false,
		RawNEFlowIncluded:                false,
		RawDestinationIPIncluded:         false,
		CredentialsIncluded:              false,
		SessionIDIncluded:                false,
	}, nil
}

func MetadataAuditEventFromOpen(tenantID string, frame tunnel.Frame) (MetadataAuditEvent, error) {
	if frame.Type != tunnel.FrameTCPOpen {
		return MetadataAuditEvent{}, fmt.Errorf("tcp_open frame is required for flow copy started audit event")
	}
	return NewMetadataAuditEvent(MetadataAuditInput{
		EventType:     AuditEventFlowCopyStarted,
		TenantID:      tenantID,
		RequestID:     frame.RequestID,
		ApplicationID: frame.ApplicationID,
	})
}

func MetadataAuditEventFromClose(tenantID, applicationID string, frame tunnel.Frame) (MetadataAuditEvent, error) {
	if frame.Type != tunnel.FrameTCPClose {
		return MetadataAuditEvent{}, fmt.Errorf("tcp_close frame is required for flow copy close audit event")
	}
	return NewMetadataAuditEvent(MetadataAuditInput{
		EventType:      auditEventTypeForCloseReason(frame.CloseReason),
		TenantID:       tenantID,
		RequestID:      frame.RequestID,
		ApplicationID:  applicationID,
		Direction:      frame.Direction,
		CloseReason:    frame.CloseReason,
		BytesUp:        frame.BytesUp,
		BytesDown:      frame.BytesDown,
		DurationMillis: frame.DurationMillis,
	})
}

func auditEventTypeForCloseReason(reason string) string {
	switch reason {
	case tunnel.TCPCloseReasonByteCapExceeded:
		return AuditEventFlowCopyByteCapExceeded
	case tunnel.TCPCloseReasonIdleTimeoutExceeded:
		return AuditEventFlowCopyIdleTimeout
	default:
		return AuditEventFlowCopyClosed
	}
}

func isRequiredMetadataAuditEvent(eventType string) bool {
	for _, required := range requiredMetadataAuditEvents {
		if eventType == required {
			return true
		}
	}
	return false
}
